/*!

# Protected Data credential store

iOS (and macOS on Apple Silicon) offers a secure storage service called
_Protected Data_. This module provides a credential store for that service.

To use all the features of this module, your client application must be
code-signed with a provisioning profile. Since command-line tools cannot be
code-signed, there's not much point in their using this module.

There are actually two, distinct protected stores: one local to the
device, and one that is synchronized with iCloud. If you create a store with
`Store::new`, you get the default configuration in which the local store is
used, but if you create a store with `Store::new_with_configuration` and pass
the string `true` for the `cloud-sync` key, then the iCloud-synchronized
store is used instead. (Use of the cloud-synchronized store is only available
to applications that have the iCloud capability enabled in their provisioning
profile.)

For a given service/user pair, this module creates/searches for a generic
password item whose _account_ attribute holds the user and whose _service_
attribute holds the service. Because of a quirk in the protected data API,
neither the _account_ nor the _service_ may be the empty string. (Empty strings
are treated as wildcards when looking up credentials.) Since there can be only
one generic password item in the local or cloud store with a given _account_ and
_service_, the protected store does not allow ambiguity.

## Access control

Protected data items _in the local store_ can be created with varying levels of
protection. This module uses a default access policy of "accessible when device
is unlocked", but entry modifiers can be used to change this. See the docs for
[build](Store::build) for details.

## Attributes

This store exposes no attributes on credentials.

## Search

This store exposes search over both the local and cloud-synchronized stores.
You can search for credentials by service and/or user (exact match, case-sensitive).
If you specify neither a service nor a user, then the search will return all
credentials in the store (but see the next paragraph).

The OS, by design, does not expose the access policy on existing secrets in the
store. To avoid popping up authentication dialogs during a search, searches
ignore access-controlled secrets, and search results will never include them.
The only way to manage an access-controlled secret is to know its service and
user and to create an entry using them.
 */

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error;
use security_framework::item;
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password, get_generic_password,
    set_generic_password_options,
};
#[cfg(feature = "sync")]
use security_framework::passwords::{delete_generic_password_options, generic_password};

use keyring_core::{
    CredentialPersistence, Entry, Error as ErrorCode, Result,
    api::{Credential, CredentialApi, CredentialStoreApi},
    attributes::parse_attributes,
};

/// Access policies for protected data items.
///
/// These are recognized case-insensitively from their
/// camel-cased or snake-cased equivalents, as
/// well as the string "default".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AccessPolicy {
    AfterFirstUnlock,
    #[default]
    WhenUnlocked,
    RequireUserPresence,
}

impl FromStr for AccessPolicy {
    type Err = ErrorCode;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "after-first-unlock" | "afterfirstunlock" => Ok(AccessPolicy::AfterFirstUnlock),
            "when-unlocked" | "whenunlocked" | "default" => Ok(AccessPolicy::WhenUnlocked),
            "require-user-presence" | "requireuserpresence" => {
                Ok(AccessPolicy::RequireUserPresence)
            }
            _ => Err(ErrorCode::Invalid(
                "access-policy".to_string(),
                format!("unknown value: {}", s),
            )),
        }
    }
}

/// The representation of a generic Keychain credential.
///
/// The actual credentials can have lots of attributes
/// not represented here.  There's no way to use this
/// module to get at those attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cred {
    pub service: String,
    pub account: String,
    pub access_policy: AccessPolicy,
    pub cloud_synchronize: bool,
}

impl CredentialApi for Cred {
    /// See the keychain-core API docs.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
        #[cfg(feature = "sync")]
        if self.cloud_synchronize {
            options.set_access_synchronized(Some(true));
        }
        match self.access_policy {
            AccessPolicy::AfterFirstUnlock => {
                options.set_access_control(
                    SecAccessControl::create_with_protection(
                        Some(ProtectionMode::AccessibleAfterFirstUnlock),
                        Default::default(),
                    )
                    .map_err(decode_error)?,
                );
            }
            AccessPolicy::WhenUnlocked => {}
            AccessPolicy::RequireUserPresence => {
                let access_control = SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleWhenUnlocked),
                    AccessControlOptions::USER_PRESENCE.bits(),
                )
                .map_err(decode_error)?;
                options.set_access_control(access_control);
            }
        }
        set_generic_password_options(secret, options).map_err(decode_error)?;
        Ok(())
    }

    /// See the keychain-core API docs.
    fn get_secret(&self) -> Result<Vec<u8>> {
        #[cfg(feature = "sync")]
        if self.cloud_synchronize {
            let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
            options.set_access_synchronized(Some(true));
            generic_password(options).map_err(decode_error)
        } else {
            get_generic_password(&self.service, &self.account).map_err(decode_error)
        }
        #[cfg(not(feature = "sync"))]
        get_generic_password(&self.service, &self.account).map_err(decode_error)
    }

    /// See the keychain-core API docs.
    fn delete_credential(&self) -> Result<()> {
        #[cfg(feature = "sync")]
        if self.cloud_synchronize {
            let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
            options.set_access_synchronized(Some(true));
            delete_generic_password_options(options).map_err(decode_error)?;
        } else {
            delete_generic_password(&self.service, &self.account).map_err(decode_error)?;
        }
        #[cfg(not(feature = "sync"))]
        delete_generic_password(&self.service, &self.account).map_err(decode_error)?;
        Ok(())
    }

    /// See the keychain-core API docs.
    ///
    /// Since specifiers are wrappers in this store, we just check to
    /// see if the underlying item exists before returning None.
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        get_generic_password(&self.service, &self.account).map_err(decode_error)?;
        Ok(None)
    }

    /// See the keychain-core API docs.
    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.account.clone()))
    }

    /// See the keychain-core API docs.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// See the keychain-core API docs.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Cred {
    /// Create an entry representing a protected generic password.
    ///
    /// This will fail if the service or user strings are empty,
    /// because empty attribute values act as wildcards in the
    /// Keychain Services API.
    ///
    /// This will fail if the access policy is not compatible
    /// with the cloud-sync policy.
    pub fn build(
        service: &str,
        user: &str,
        access_policy: AccessPolicy,
        cloud_synchronize: bool,
    ) -> Result<Entry> {
        if service.is_empty() {
            return Err(ErrorCode::Invalid(
                "service".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        if user.is_empty() {
            return Err(ErrorCode::Invalid(
                "user".to_string(),
                "cannot be empty".to_string(),
            ));
        }
        if cloud_synchronize && access_policy == AccessPolicy::RequireUserPresence {
            return Err(ErrorCode::Invalid(
                "require-user-presence".to_string(),
                "not allowed in cloud-synchronized store".to_string(),
            ));
        }
        let cred = Self {
            service: service.to_string(),
            account: user.to_string(),
            access_policy,
            cloud_synchronize,
        };
        Ok(Entry::new_with_credential(Arc::new(cred)))
    }
}

/// The builder for iOS keychain credentials
#[derive(Debug)]
pub struct Store {
    id: String,
    cloud_synchronize: bool,
}

impl Store {
    /// Create a default store, which does *not* synchronize with the cloud.
    pub fn new() -> Result<Arc<Self>> {
        Ok(Self::new_internal(false))
    }

    /// Create a configured store.
    ///
    /// The only configuration key is `cloud-sync` (`true` or `false`).
    pub fn new_with_configuration(config: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        let config = parse_attributes(&["cloud-sync"], Some(config))?;
        let mut cloud_synchronize = false;
        if let Some(option) = config.get("cloud-sync") {
            cloud_synchronize = option.parse().map_err(|_| {
                ErrorCode::Invalid(
                    String::from("cloud-sync"),
                    String::from("must be true or false"),
                )
            })?;
        }
        if cloud_synchronize && !cfg!(feature = "sync") {
            return Err(ErrorCode::NotSupportedByStore(
                "cloud-sync config requires a build with the \"sync\" feature".to_string(),
            ));
        }
        Ok(Self::new_internal(cloud_synchronize))
    }

    fn new_internal(cloud_synchronize: bool) -> Arc<Self> {
        let now = SystemTime::now();
        let elapsed = if now.lt(&UNIX_EPOCH) {
            UNIX_EPOCH.duration_since(now).unwrap()
        } else {
            now.duration_since(UNIX_EPOCH).unwrap()
        };
        let id = format!(
            "Crate version {}, Instantiated at {}",
            env!("CARGO_PKG_VERSION"),
            elapsed.as_secs_f64()
        );
        Arc::new(Store {
            id,
            cloud_synchronize,
        })
    }
}

impl CredentialStoreApi for Store {
    /// See the keychain-core API docs.
    fn vendor(&self) -> String {
        "macOS/iOS Protected Store, https://crates.io/crates/apple-native-keyring-store".to_string()
    }

    /// See the keychain-core API docs.
    fn id(&self) -> String {
        self.id.to_string()
    }

    /// See the keychain-core API docs.
    ///
    /// The only allowed modifier is `access-policy`, which can be one of
    /// `after-first-unlock`, `when-unlocked` (the default), or
    /// `require-user-presence` (which requires a user-performed unlock action
    /// via biometrics or passcode whenever the credential is accessed).
    ///
    /// Cloud-synchronized stores do not allow a `require-user-presence` policy
    /// because the user need not be present during cloud synchronization.
    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let mods = parse_attributes(&["access-policy"], modifiers)?;
        let mut access_policy = AccessPolicy::default();
        if let Some(option) = mods.get("access-policy") {
            access_policy = option.parse()?;
        }
        Cred::build(service, user, access_policy, self.cloud_synchronize)
    }

    /// See the keychain-core API docs.
    ///
    /// The allowed search attributes are `service` and `user`, which
    /// must match a credential's values exactly (case-sensitive)
    /// for a wrapper over that credential to be returned. An empty search
    /// spec will return every credential in the store except those
    /// that require user presence.
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let spec = parse_attributes(&["service", "user", "case-sensitive"], Some(spec))?;
        let mut options = item::ItemSearchOptions::new();
        options
            .class(item::ItemClass::generic_password())
            .limit(item::Limit::All)
            .load_attributes(true);
        #[cfg(feature = "sync")]
        options.skip_authenticated_items(true);
        if let Some(service) = spec.get("service") {
            options.service(service);
        }
        if let Some(user) = spec.get("user") {
            options.account(user);
        }
        let items = match options.search().map_err(decode_error) {
            Ok(items) => items,
            Err(ErrorCode::NoEntry) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut result = Vec::new();
        for item in items {
            if let Some(map) = item.simplify_dict() {
                if let Some(service) = map.get("svce") {
                    if let Some(account) = map.get("acct") {
                        let cred = Cred {
                            service: service.to_string(),
                            account: account.to_string(),
                            access_policy: AccessPolicy::default(),
                            cloud_synchronize: self.cloud_synchronize,
                        };
                        result.push(Entry::new_with_credential(Arc::new(cred)))
                    }
                }
            }
        }
        Ok(result)
    }

    /// See the keychain-core API docs.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    //// See the keychain-core API docs.
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }

    /// See the keychain-core API docs.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Map an iOS API error to a crate error with appropriate annotation
///
/// The iOS error code values used here are from
/// [this reference](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-78/lib/SecBase.h.auto.html)
fn decode_error(err: Error) -> ErrorCode {
    match err.code() {
        -25291 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecNotAvailable
        -25292 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecReadOnly
        -25300 => ErrorCode::NoEntry,                        // errSecItemNotFound
        -34018 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecMissingEntitlement
        _ => ErrorCode::PlatformFailure(Box::new(err)),
    }
}
