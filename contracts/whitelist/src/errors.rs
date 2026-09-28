use soroban_sdk::contracterror;

/// Stable, machine-readable error codes for the Callora Whitelist contract.
///
/// The numeric discriminants in this enum are part of the contract interface and
/// must remain stable over time. Callers may branch on these `u32` codes instead
/// of parsing panic strings.
///
/// | Code | Variant                     | Meaning                                              |
/// |------|-----------------------------|------------------------------------------------------|
/// | 1    | NotInitialized              | Contract has not been initialized                    |
/// | 2    | AlreadyInitialized          | `init` was called more than once                     |
/// | 3    | Unauthorized                | Caller is not authorized for the operation           |
/// | 4    | AddressAlreadyInWhitelist   | Address is already in the whitelist                  |
/// | 5    | AddressNotInWhitelist       | Address is not in the whitelist                      |
/// | 49   | AdminCooldownActive         | Admin cool-off window is still active                |
/// | 50   | InvalidAdminCooldown        | Admin cool-off window is outside accepted bounds     |
/// | 51   | NoAdminTransferPending      | No admin transfer is pending                         |
/// | 52   | NewAdminSameAsCurrent       | Proposed admin matches the current admin             |
#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum WhitelistError {
    /// Contract has not been initialized yet (code 1).
    NotInitialized = 1,
    /// Contract has already been initialized (code 2).
    AlreadyInitialized = 2,
    /// Caller is not authorized for this operation (code 3).
    Unauthorized = 3,
    /// Address is already in the whitelist (code 4).
    /// Returned by `add_address` when the address is already present.
    AddressAlreadyInWhitelist = 4,
    /// Address is not found in the whitelist (code 5).
    /// Returned by `remove_address` when the address is absent.
    AddressNotInWhitelist = 5,

    /// A critical admin action is still inside the global cool-off window (code 49).
    AdminCooldownActive = 49,
    /// Admin cool-off window is outside the accepted bounds (code 50).
    InvalidAdminCooldown = 50,
    /// No admin transfer is pending (code 51).
    NoAdminTransferPending = 51,
    /// Proposed admin is the same as the current admin (code 52).
    NewAdminSameAsCurrent = 52,
    MigrationPending = 53,
}
