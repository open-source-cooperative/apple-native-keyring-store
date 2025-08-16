/*!

# macOS Keychain credential store

All credentials on macOS are stored in secure stores called _keychains_. The OS
automatically creates three of them (or four if removable media is being used),
called _User_ (aka login), _Common_, _System_, and _Dynamic_.  The `keychain`
configuration key specified when instantiating a [Store] determines
which keychain that store uses for its credentials. By default,
the 'User' (aka login) keychain is used.

For a given service/user pair, this module creates/searches for a generic
credential in the store's keychain whose _account_ attribute holds the user
and whose _service_ attribute holds the service. Because generic credentials are
uniquely identified within each keychain by their _account_ and _service_
attributes, there is no chance of ambiguity.

Because of a quirk in the Mac keychain services API, neither the _account_
nor the _service_ may be the empty string.

In the _Keychain Access_ UI on Mac, credentials created by this module show up
in the _Passwords_ view (with their _where_ and _name_ fields both showing
their _service_ attribute). What the Keychain Access lists under _Note_ entries
on the Mac are also generic credentials, so this module can access existing
_notes_ created by third-party applications if you know the value of their
_account_ attribute (which is not displayed by _Keychain Access_).

## Attributes

Credentials on macOS can have a large number of _key/value_ attributes, but this
module ignores all of them. The only attribute on returned for credentials is a
read-only, synthesized attribute `keychain` that gives the name of the keychain
in which the credential is stored.

## Search

You can search the credentials in a given store (keychain) by `service`
and `user`. The search is case-sensitive, and a wrapper around each
matching credential is returned. Specifying neither `service` nor `user`
returns all wrappers around all the credentials in the store.

 */
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use security_framework::base::Error;
use security_framework::item;
use security_framework::os::macos::item::ItemSearchOptionsExt;
use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
use security_framework::os::macos::passwords::find_generic_password;

use keyring_core::{
    Entry,
    api::{Credential, CredentialApi, CredentialPersistence, CredentialStoreApi},
    attributes::parse_attributes,
    error::{Error as ErrorCode, Result},
};

/// The representation of a generic Keychain credential.
///
/// The actual credentials can have lots of attributes
/// not represented here.  There's no way to use this
/// module to get at those attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cred {
    pub domain: MacKeychainDomain,
    pub service: String,
    pub account: String,
}

impl CredentialApi for Cred {
    /// See the keychain-core API docs.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        self.get_keychain()?
            .set_generic_password(&self.service, &self.account, secret)
            .map_err(decode_error)?;
        Ok(())
    }

    /// See the keychain-core API docs.
    fn get_secret(&self) -> Result<Vec<u8>> {
        let (password_bytes, _) =
            find_generic_password(Some(&[self.get_keychain()?]), &self.service, &self.account)
                .map_err(decode_error)?;
        Ok(password_bytes.to_owned())
    }

    /// See the keychain-core API docs.
    ///
    /// A read-only attribute `keychain` is synthesized.
    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        find_generic_password(Some(&[self.get_keychain()?]), &self.service, &self.account)
            .map_err(decode_error)?;
        Ok(HashMap::from([(
            String::from("keychain"),
            self.domain.to_string(),
        )]))
    }

    /// See the keychain-core API docs.
    fn delete_credential(&self) -> Result<()> {
        let (_, item) =
            find_generic_password(Some(&[self.get_keychain()?]), &self.service, &self.account)
                .map_err(decode_error)?;
        item.delete();
        Ok(())
    }

    /// See the keychain-core API docs.
    ///
    /// Since every specifier is also a wrapper, this is just a check
    /// to see whether the underlying credential exists.
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        find_generic_password(Some(&[self.get_keychain()?]), &self.service, &self.account)
            .map_err(decode_error)?;
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
    /// Create a credential representing a Mac keychain entry.
    ///
    /// A keychain string is interpreted as the keychain to use for the entry.
    ///
    /// Creating a credential does not put anything into the keychain.
    /// The keychain entry will be created
    /// when [set_password](Cred::set_password) is
    /// called.
    ///
    /// This will fail if the service or user strings are empty,
    /// because empty attribute values act as wildcards in the
    /// Keychain Services API.
    pub fn build(keychain: MacKeychainDomain, service: &str, user: &str) -> Result<Entry> {
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
        let cred = Cred {
            domain: keychain,
            service: service.to_string(),
            account: user.to_string(),
        };
        Ok(Entry::new_with_credential(Arc::new(cred)))
    }

    fn get_keychain(&self) -> Result<SecKeychain> {
        get_keychain(&self.domain)
    }
}

/// The store for Mac keychain credentials
#[derive(Debug)]
pub struct Store {
    id: String,
    keychain: MacKeychainDomain,
}

impl Store {
    /// Create a default store, which uses the User (aka login) keychain.
    pub fn new() -> Result<Arc<Self>> {
        Ok(Self::new_internal(MacKeychainDomain::User))
    }

    /// Create a store configured to use a specific keychain.
    ///
    /// The keychain used can be overridden by a modifier on a specific entry.
    pub fn new_with_configuration(configuration: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        let config = parse_attributes(&["keychain"], configuration)?;
        let mut keychain = MacKeychainDomain::User;
        if let Some(option) = config.get("keychain") {
            keychain = option.parse()?;
        }
        Ok(Self::new_internal(keychain))
    }

    fn new_internal(keychain: MacKeychainDomain) -> Arc<Self> {
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
            keychain,
        })
    }
}

impl CredentialStoreApi for Store {
    /// See the keychain-core API docs.
    fn vendor(&self) -> String {
        "macOS Keychain Store, https://crates.io/crates/apple-native-keyring-store".to_string()
    }

    /// See the keychain-core API docs.
    fn id(&self) -> String {
        self.id.to_string()
    }

    /// See the keychain-core API docs.
    ///
    /// The only option you can specify is `keychain`, and the value
    /// must name a keychain (User, System, Common, or Dynamic)
    /// you want to use to hold the credential when it's created.
    /// The default is the User (aka login) keychain.
    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let mods = parse_attributes(&["keychain"], modifiers.unwrap_or(&HashMap::new()))?;
        let mut keychain = self.keychain.clone();
        if let Some(option) = mods.get("keychain") {
            keychain = option.parse()?;
        }
        Cred::build(keychain, service, user)
    }

    /// See the keychain-core API docs.
    ///
    /// The (optional) search spec keys allowed are `service` and `user`. They
    /// are matched case-sensitively against the service and account attributes
    /// of the generic passwords in the store's configured keychain. A wrapper
    /// for each matching credential is returned. If no `service` or `user` is
    /// specified, all credentials in the store's configured keychain are
    /// returned.
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let spec = parse_attributes(&["service", "user"], spec)?;
        let keychains = [get_keychain(&self.keychain)?];
        let mut options = item::ItemSearchOptions::new();
        options
            .keychains(&keychains)
            .class(item::ItemClass::generic_password())
            .limit(item::Limit::All)
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
                            domain: self.keychain.clone(),
                            service: service.to_string(),
                            account: account.to_string(),
                        };
                        result.push(Entry::new_with_credential(Arc::new(cred)))
                    }
                }
            }
        }
        Ok(result)
    }

    /// Return the underlying builder object with an `Any` type so that it can
    /// be downgraded to a [Store] for platform-specific processing.
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// The four pre-defined Mac keychains.
pub enum MacKeychainDomain {
    User,
    System,
    Common,
    Dynamic,
}

impl std::fmt::Display for MacKeychainDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MacKeychainDomain::User => "User".fmt(f),
            MacKeychainDomain::System => "System".fmt(f),
            MacKeychainDomain::Common => "Common".fmt(f),
            MacKeychainDomain::Dynamic => "Dynamic".fmt(f),
        }
    }
}

impl std::str::FromStr for MacKeychainDomain {
    type Err = ErrorCode;

    /// Convert a keychain specification string to a keychain domain.
    ///
    /// We accept any case in the string,
    /// but the value has to match a known keychain domain name
    /// or else we assume the login keychain is meant.
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "user" => Ok(MacKeychainDomain::User),
            "system" => Ok(MacKeychainDomain::System),
            "common" => Ok(MacKeychainDomain::Common),
            "dynamic" => Ok(MacKeychainDomain::Dynamic),
            _ => Err(ErrorCode::Invalid(
                "keychain".to_string(),
                format!("'{s}' is not User, System, Common, or Dynamic"),
            )),
        }
    }
}

fn get_keychain(domain: &MacKeychainDomain) -> Result<SecKeychain> {
    let domain = match domain {
        MacKeychainDomain::User => SecPreferencesDomain::User,
        MacKeychainDomain::System => SecPreferencesDomain::System,
        MacKeychainDomain::Common => SecPreferencesDomain::Common,
        MacKeychainDomain::Dynamic => SecPreferencesDomain::Dynamic,
    };
    match SecKeychain::default_for_domain(domain) {
        Ok(keychain) => Ok(keychain),
        Err(err) => Err(decode_error(err)),
    }
}

/// Map a Mac API error to a crate error with appropriate annotation
///
/// The macOS error code values used here are from
/// [this reference](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-78/lib/SecBase.h.auto.html)
pub fn decode_error(err: Error) -> ErrorCode {
    match err.code() {
        -25291 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecNotAvailable
        -25292 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecReadOnly
        -25294 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecNoSuchKeychain
        -25295 => ErrorCode::NoStorageAccess(Box::new(err)), // errSecInvalidKeychain
        -25300 => ErrorCode::NoEntry,                        // errSecItemNotFound
        _ => ErrorCode::PlatformFailure(Box::new(err)),
    }
}
