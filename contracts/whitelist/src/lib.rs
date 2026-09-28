#![no_std]
#![allow(clippy::enum_variant_names)]
//!
//! # Callora Whitelist Contract
//!
//! Admin actions that modify the whitelist (`add_address`,
//! `remove_address`, `clear_all`) are protected by a configurable
//! cool-off window (see `admin.rs`).
//!
//! ## Storage layout (v2)
//!
//! One persistent entry per address, so `is_whitelisted` is a single keyed
//! lookup (O(1)) and instance storage stays constant-size.
//!
//! - `Whitelisted(epoch, address) -> slot` (persistent): presence == whitelisted.
//! - `WhitelistSlot(epoch, slot) -> address` (persistent): dense index for
//!   paging and O(1) swap-remove.
//! - `WhitelistEpoch`, `WhitelistCount`, `WhitelistMigrated`,
//!   `WhitelistMigrationCursor` (instance): small scalars only.
//!
//! `clear_all` bumps the epoch and resets the count, invalidating every
//! entry in O(1). Stale entries expire via TTL.
//!
//! ## Ordering
//!
//! `remove_address` uses swap-remove, so order is not insertion order after
//! a removal.
//!
//! ## Legacy migration
//!
//! A legacy `Vec<Address>` under `WhitelistList` is migrated in batches with
//! `migrate_legacy`. Until it completes, reads fall back to the legacy vector
//! and mutations fail with `MigrationPending`.

mod errors;
pub use errors::WhitelistError;

pub mod admin;

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol, Vec};

/// Storage keys. New variants are only ever appended so existing on-chain
/// keys keep their encoding.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum StorageKey {
    WhitelistOwner,
    WhitelistAdmin,
    WhitelistPendingAdmin,
    /// LEGACY: instance vector. Only read/removed by migration.
    WhitelistList,
    WhitelistAdminCooldown,
    WhitelistLastCriticalAction,
    /// Instance: current epoch (u32), bumped by `clear_all`.
    WhitelistEpoch,
    /// Instance: entries in the current epoch (u32).
    WhitelistCount,
    /// Instance: true once no legacy vector remains.
    WhitelistMigrated,
    /// Instance: next legacy index to migrate (u32).
    WhitelistMigrationCursor,
    /// Persistent: (epoch, address) -> slot.
    Whitelisted(u32, Address),
    /// Persistent: (epoch, slot) -> address.
    WhitelistSlot(u32, u32),
}

const LEDGERS_PER_DAY: u32 = 17_280;

pub const INSTANCE_BUMP_THRESHOLD: u32 = LEDGERS_PER_DAY * 30;
pub const INSTANCE_BUMP_AMOUNT: u32 = LEDGERS_PER_DAY * 60;
pub const PERSISTENT_BUMP_THRESHOLD: u32 = LEDGERS_PER_DAY * 30;
pub const PERSISTENT_BUMP_AMOUNT: u32 = LEDGERS_PER_DAY * 60;

/// Maximum entries returned by `get_whitelist_page`.
pub const MAX_PAGE_SIZE: u32 = 100;
/// Maximum legacy entries migrated per `migrate_legacy` call.
pub const MAX_MIGRATION_BATCH: u32 = 100;

#[contract]
pub struct CalloraWhitelist;

#[contractimpl]
impl CalloraWhitelist {
    /// One-time setup. Fresh deployments never have a legacy vector.
    pub fn init(env: Env, admin: Address) -> Result<(), WhitelistError> {
        if env.storage().instance().has(&StorageKey::WhitelistOwner) {
            return Err(WhitelistError::AlreadyInitialized);
        }

        env.storage()
            .instance()
            .set(&StorageKey::WhitelistOwner, &admin);
        env.storage()
            .instance()
            .set(&StorageKey::WhitelistAdmin, &admin);
        env.storage()
            .instance()
            .set(&StorageKey::WhitelistMigrated, &true);

        Self::bump_instance_ttl(&env);
        Ok(())
    }

    pub fn get_admin(env: Env) -> Result<Address, WhitelistError> {
        Self::bump_instance_ttl(&env);
        env.storage()
            .instance()
            .get::<_, Address>(&StorageKey::WhitelistAdmin)
            .ok_or(WhitelistError::NotInitialized)
    }

    /// Start a two-step admin transfer (current admin only).
    pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), WhitelistError> {
        Self::require_admin(&env, &caller)?;

        let current_admin = env
            .storage()
            .instance()
            .get::<_, Address>(&StorageKey::WhitelistAdmin)
            .ok_or(WhitelistError::NotInitialized)?;

        if new_admin == current_admin {
            return Err(WhitelistError::NewAdminSameAsCurrent);
        }

        env.storage()
            .instance()
            .set(&StorageKey::WhitelistPendingAdmin, &new_admin);
        Self::bump_instance_ttl(&env);
        Ok(())
    }

    /// Accept a pending admin transfer (pending admin only).
    pub fn accept_admin(env: Env) -> Result<(), WhitelistError> {
        let new_admin: Address = env
            .storage()
            .instance()
            .get(&StorageKey::WhitelistPendingAdmin)
            .ok_or(WhitelistError::NoAdminTransferPending)?;
        new_admin.require_auth();

        env.storage()
            .instance()
            .set(&StorageKey::WhitelistAdmin, &new_admin);
        env.storage()
            .instance()
            .remove(&StorageKey::WhitelistPendingAdmin);
        Self::bump_instance_ttl(&env);
        Ok(())
    }

/// Add an address (admin only, cooldown-gated).
    pub fn add_address(env: Env, caller: Address, address: Address) -> Result<(), WhitelistError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;
        Self::require_migrated(&env)?;

        admin::guard(&env, Symbol::new(&env, "add_address"))?;

        if !Self::insert(&env, &address) {
            return Err(WhitelistError::AddressAlreadyInWhitelist);
        }

        Self::bump_instance_ttl(&env);
        Ok(())
    }

    /// Remove an address (admin only, cooldown-gated). Swap-remove.
    pub fn remove_address(
        env: Env,
        caller: Address,
        address: Address,
    ) -> Result<(), WhitelistError> {
        Self::require_admin(&env, &caller)?;
        Self::require_migrated(&env)?;

        admin::guard(&env, Symbol::new(&env, "remove_address"))?;

        if !Self::remove(&env, &address) {
            return Err(WhitelistError::AddressNotInWhitelist);
        }

        Self::bump_instance_ttl(&env);
        Ok(())
    }

    /// Remove all addresses in O(1) by bumping the epoch (admin only,
    /// cooldown-gated). Still arms the cool-off on an empty whitelist.
    pub fn clear_all(env: Env, caller: Address) -> Result<(), WhitelistError> {
        Self::require_admin(&env, &caller)?;
        Self::require_migrated(&env)?;

        admin::guard(&env, Symbol::new(&env, "clear_all"))?;

        let next = Self::epoch(&env).checked_add(1).expect("epoch overflow");
        env.storage()
            .instance()
            .set(&StorageKey::WhitelistEpoch, &next);
        env.storage()
            .instance()
            .set(&StorageKey::WhitelistCount, &0u32);

        Self::bump_instance_ttl(&env);
        Ok(())
    }

    /// O(1) membership check. While a migration is pending it also falls
    /// back to the legacy vector.
    pub fn is_whitelisted(env: Env, address: Address) -> bool {
        let key = StorageKey::Whitelisted(Self::epoch(&env), address.clone());
        if env.storage().persistent().has(&key) {
            return true;
        }
        if Self::is_migrated(&env) {
            return false;
        }
        Self::legacy_list(&env).contains(&address)
    }

    /// Whole whitelist (compatibility). O(n); prefer `get_whitelist_page`.
    pub fn get_whitelist(env: Env) -> Vec<Address> {
        Self::bump_instance_ttl(&env);
        if !Self::is_migrated(&env) {
            return Self::legacy_list(&env);
        }
        let epoch = Self::epoch(&env);
        let count = Self::count(&env);
        let mut out = Vec::new(&env);
        for slot in 0..count {
            if let Some(a) = Self::address_at(&env, epoch, slot) {
                out.push_back(a);
            }
        }
        out
    }

    /// Up to `limit` addresses from slot `start`. `limit` is clamped to
    /// `MAX_PAGE_SIZE`.
    pub fn get_whitelist_page(env: Env, start: u32, limit: u32) -> Vec<Address> {
        Self::bump_instance_ttl(&env);
        let limit = limit.min(MAX_PAGE_SIZE);

        if !Self::is_migrated(&env) {
            let legacy = Self::legacy_list(&env);
            let end = start.saturating_add(limit).min(legacy.len());
            if start >= end {
                return Vec::new(&env);
            }
            return legacy.slice(start..end);
        }

        let epoch = Self::epoch(&env);
        let end = start.saturating_add(limit).min(Self::count(&env));
        let mut out = Vec::new(&env);
        let mut slot = start;
        while slot < end {
            if let Some(a) = Self::address_at(&env, epoch, slot) {
                out.push_back(a);
            }
            slot += 1;
        }
        out
    }

    /// Number of whitelisted addresses.
    pub fn whitelist_count(env: Env) -> u32 {
        if Self::is_migrated(&env) {
            Self::count(&env)
        } else {
            Self::legacy_list(&env).len()
        }
    }

    /// Migrate up to `limit` legacy entries (clamped to
    /// 1..=MAX_MIGRATION_BATCH). Admin only. Idempotent.
    /// Returns true when migration is complete.
    pub fn migrate_legacy(env: Env, caller: Address, limit: u32) -> Result<bool, WhitelistError> {
        Self::require_admin(&env, &caller)?;

        if Self::is_migrated(&env) {
            return Ok(true);
        }

        let limit = limit.clamp(1, MAX_MIGRATION_BATCH);
        let legacy = Self::legacy_list(&env);
        let cursor: u32 = env
            .storage()
            .instance()
            .get(&StorageKey::WhitelistMigrationCursor)
            .unwrap_or(0);
        let end = cursor.saturating_add(limit).min(legacy.len());

        let mut i = cursor;
        while i < end {
            if let Some(a) = legacy.get(i) {
                Self::insert(&env, &a);
            }
            i += 1;
        }

        let done = end >= legacy.len();
        if done {
            env.storage().instance().remove(&StorageKey::WhitelistList);
            env.storage()
                .instance()
                .remove(&StorageKey::WhitelistMigrationCursor);
            env.storage()
                .instance()
                .set(&StorageKey::WhitelistMigrated, &true);
        } else {
            env.storage()
                .instance()
                .set(&StorageKey::WhitelistMigrationCursor, &end);
        }

        Self::bump_instance_ttl(&env);
        Ok(done)
    }

    pub fn is_migration_complete(env: Env) -> bool {
        Self::is_migrated(&env)
    }

pub fn get_admin_cooldown(env: Env) -> u64 {
        admin::get_cooldown(&env)
    }

    pub fn set_admin_cooldown(
        env: Env,
        caller: Address,
        seconds: u64,
    ) -> Result<(), WhitelistError> {
        Self::require_admin(&env, &caller)?;
        admin::set_cooldown(&env, seconds)?;
        Self::bump_instance_ttl(&env);
        Ok(())
    }

    pub fn admin_cooldown_remaining(env: Env) -> u64 {
        admin::remaining(&env)
    }

    pub fn is_admin_action_ready(env: Env) -> bool {
        admin::is_ready(&env)
    }

    pub fn get_last_critical_admin_action(env: Env) -> Option<admin::CriticalAdminAction> {
        admin::last_action(&env)
    }

    // ---- Private helpers ----

    fn require_admin(env: &Env, caller: &Address) -> Result<(), WhitelistError> {
        caller.require_auth();
        let admin = env
            .storage()
            .instance()
            .get::<_, Address>(&StorageKey::WhitelistAdmin)
            .ok_or(WhitelistError::NotInitialized)?;
        if caller != &admin {
            return Err(WhitelistError::Unauthorized);
        }
        Ok(())
    }

    fn require_migrated(env: &Env) -> Result<(), WhitelistError> {
        if Self::is_migrated(env) {
            Ok(())
        } else {
            Err(WhitelistError::MigrationPending)
        }
    }

    fn is_migrated(env: &Env) -> bool {
        env.storage()
            .instance()
            .get::<_, bool>(&StorageKey::WhitelistMigrated)
            .unwrap_or(false)
    }

    fn epoch(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get::<_, u32>(&StorageKey::WhitelistEpoch)
            .unwrap_or(0)
    }

    fn count(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get::<_, u32>(&StorageKey::WhitelistCount)
            .unwrap_or(0)
    }

    fn legacy_list(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get::<_, Vec<Address>>(&StorageKey::WhitelistList)
            .unwrap_or_else(|| Vec::new(env))
    }

    fn address_at(env: &Env, epoch: u32, slot: u32) -> Option<Address> {
        env.storage()
            .persistent()
            .get::<_, Address>(&StorageKey::WhitelistSlot(epoch, slot))
    }

    /// Insert in the current epoch. Returns false if already present.
    fn insert(env: &Env, address: &Address) -> bool {
        let epoch = Self::epoch(env);
        let key = StorageKey::Whitelisted(epoch, address.clone());
        if env.storage().persistent().has(&key) {
            return false;
        }

        let slot = Self::count(env);
        let slot_key = StorageKey::WhitelistSlot(epoch, slot);
        env.storage().persistent().set(&key, &slot);
        env.storage().persistent().set(&slot_key, address);
        Self::bump_persistent(env, &key);
        Self::bump_persistent(env, &slot_key);

        env.storage()
            .instance()
            .set(&StorageKey::WhitelistCount, &(slot + 1));
        true
    }

    /// Swap-remove in the current epoch. Returns false if absent.
    fn remove(env: &Env, address: &Address) -> bool {
        let epoch = Self::epoch(env);
        let key = StorageKey::Whitelisted(epoch, address.clone());
        let slot: u32 = match env.storage().persistent().get(&key) {
            Some(s) => s,
            None => return false,
        };

        let last = Self::count(env) - 1;
        if slot != last {
            let moved = Self::address_at(env, epoch, last).expect("index corrupted");
            let moved_key = StorageKey::Whitelisted(epoch, moved.clone());
            let slot_key = StorageKey::WhitelistSlot(epoch, slot);
            env.storage().persistent().set(&slot_key, &moved);
            env.storage().persistent().set(&moved_key, &slot);
            Self::bump_persistent(env, &slot_key);
            Self::bump_persistent(env, &moved_key);
        }
        env.storage()
            .persistent()
            .remove(&StorageKey::WhitelistSlot(epoch, last));
        env.storage().persistent().remove(&key);
        env.storage()
            .instance()
            .set(&StorageKey::WhitelistCount, &last);
        true
    }

    #[inline]
    fn bump_persistent(env: &Env, key: &StorageKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
    }

    #[inline]
    pub(crate) fn bump_instance_ttl(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_BUMP_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::testutils::Ledger as _;
    use soroban_sdk::Env;

    /// Deploy a fresh whitelist contract, init with `admin`, and return
    /// `(env, admin, client)`.
    fn deploy_whitelist<'a>(env: &'a Env, admin: &Address) -> CalloraWhitelistClient<'a> {
        let contract_id = env.register(CalloraWhitelist, ());
        let client = CalloraWhitelistClient::new(env, &contract_id);
        client.init(admin);
        client
    }
