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
is unlocked", but the option to use a policy of "accessible only when the user is
present" (meaning the user will have to do a biometric-based or passcode-based
authorization at the time of access) is available. If you want to create a single
entry with biometric access, use `Entry::new_with_modifiers` and supply a
`require-user-presence` modifier value of `true`. If you want this to be the
default for all the entries you create, use [Store::new_with_configuration] and
supply a `require-user-presence` configuration value of `true`.

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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error;
use security_framework::item;
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password,
    delete_generic_password_options, generic_password, get_generic_password, set_generic_password,
    set_generic_password_options,
};

use keyring_core::{
    CredentialPersistence, Entry, Error as ErrorCode, Result,
    api::{Credential, CredentialApi, CredentialStoreApi},
    attributes::parse_attributes,
};

/// The representation of a generic Keychain credential.
///
/// The actual credentials can have lots of attributes
/// not represented here.  There's no way to use this
/// module to get at those attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cred {
    pub service: String,
    pub account: String,
    pub require_user_presence: bool,
    pub cloud_synchronize: bool,
}

impl CredentialApi for Cred {
    /// See the keychain-core API docs.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        if self.require_user_presence || self.cloud_synchronize {
            let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
            if self.require_user_presence {
                let access_control = SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleWhenUnlocked),
                    AccessControlOptions::USER_PRESENCE.bits(),
                )
                .map_err(decode_error)?;
                options.set_access_control(access_control);
            }
            if self.cloud_synchronize {
                options.set_access_synchronized(Some(true));
            }
            set_generic_password_options(secret, options).map_err(decode_error)?;
        } else {
            set_generic_password(&self.service, &self.account, secret).map_err(decode_error)?;
        }
        Ok(())
    }

    /// See the keychain-core API docs.
    fn get_secret(&self) -> Result<Vec<u8>> {
        if self.cloud_synchronize {
            let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
            options.set_access_synchronized(Some(true));
            generic_password(options).map_err(decode_error)
        } else {
            get_generic_password(&self.service, &self.account).map_err(decode_error)
        }
    }

    /// See the keychain-core API docs.
    fn delete_credential(&self) -> Result<()> {
        if self.cloud_synchronize {
            let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
            options.set_access_synchronized(Some(true));
            delete_generic_password_options(options).map_err(decode_error)?;
        } else {
            delete_generic_password(&self.service, &self.account).map_err(decode_error)?;
        }
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
    pub fn build(
        service: &str,
        user: &str,
        require_user_presence: bool,
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
        if require_user_presence && cloud_synchronize {
            return Err(ErrorCode::Invalid(
                "require-user-presence".to_string(),
                "not allowed in cloud-synchronized store".to_string(),
            ));
        }
        let cred = Self {
            service: service.to_string(),
            account: user.to_string(),
            require_user_presence,
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
    require_user_presence: bool,
}

impl Store {
    /// Create a default store, which does *not* synchronize with the cloud.
    pub fn new() -> Result<Arc<Self>> {
        Ok(Self::new_internal(false, false))
    }

    /// Create a configured store.
    ///
    /// The allowed configuration keys are `cloud-sync` (`true` or `false`) and
    /// `require-user-presence` (`true` or `false`). You cannot require user presence
    /// if the store is being synchronized to the cloud. A per-entry modification
    /// of `require-user-presence` overrides the store configuration.
    pub fn new_with_configuration(config: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        let config = parse_attributes(&["cloud-sync", "require-user-presence"], config)?;
        let mut cloud_synchronize = false;
        let mut require_user_presence = false;
        if let Some(option) = config.get("cloud-sync") {
            if option != "true" && option != "false" {
                return Err(ErrorCode::Invalid(
                    String::from("cloud-sync"),
                    String::from("must be true or false"),
                ));
            }
            cloud_synchronize = option == "true"
        }
        if let Some(option) = config.get("require-user-presence") {
            if option != "true" && option != "false" {
                return Err(ErrorCode::Invalid(
                    String::from("require-user-presence"),
                    String::from("must be true or false"),
                ));
            }
            require_user_presence = option == "true"
        }
        if cloud_synchronize && require_user_presence {
            return Err(ErrorCode::Invalid(
                String::from("require-user-presence"),
                String::from("not allowed in cloud-synchronized store"),
            ));
        }
        Ok(Self::new_internal(cloud_synchronize, require_user_presence))
    }

    fn new_internal(cloud_synchronize: bool, require_user_presence: bool) -> Arc<Self> {
        let now = SystemTime::now();
        let elapsed = if now.lt(&UNIX_EPOCH) {
            UNIX_EPOCH.duration_since(now).unwrap()
        } else {
            now.duration_since(UNIX_EPOCH).unwrap()
        };
        Arc::new(Store {
            id: format!(
                "Crate version {}, Instantiated at {}",
                env!("CARGO_PKG_VERSION"),
                elapsed.as_secs_f64()
            ),
            cloud_synchronize,
            require_user_presence,
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
    /// The only allowed modifier is `require-user-presence`, which must be
    /// "true" or "false" (case-sensitive).
    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let mods = parse_attributes(
            &["require-user-presence"],
            modifiers.unwrap_or(&HashMap::new()),
        )?;
        let mut require_user_presence = self.require_user_presence;
        if let Some(option) = mods.get("require-user-presence") {
            if option != "true" && option != "false" {
                return Err(ErrorCode::Invalid(
                    String::from("require-user-presence"),
                    String::from("must be true or false"),
                ));
            }
            require_user_presence = option == "true"
        }
        Cred::build(service, user, require_user_presence, self.cloud_synchronize)
    }

    /// See the keychain-core API docs.
    ///
    /// The allowed search attributes are `service` and `user`, which
    /// must match a credential's values exactly (case-sensitive)
    /// for a wrapper over that credential to be returned. An empty search
    /// spec will return every credential in the store.
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let spec = parse_attributes(&["service", "user", "case-sensitive"], spec)?;
        let mut options = item::ItemSearchOptions::new();
        options
            .class(item::ItemClass::generic_password())
            .limit(item::Limit::All)
            .skip_authenticated_items(true)
            .load_attributes(true);
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
                            require_user_presence: false,
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
