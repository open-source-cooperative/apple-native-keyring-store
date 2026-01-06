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
are treated as wildcards when looking up credentials.)

## Ambiguity

Both the local and cloud-synchronized stores are application-specific, in
that each application is given its own _access group_ in which it stores its
items. Since there can be only one generic password item in each access group
with a given _account_ and _service_, an application that can access only one
access group will never encounter ambiguity. It also means that, by default,
applications can never share credentials for the same service and account.

Because there are occasions when credentials must be shared between applications,
sandboxed applications can be given access to multiple access groups. When an
application has been configured to have multiple access groups, its protected
store will search across all those access groups for a given entry, so ambiguity
is possible. To avoid this, an application can create one store for each available
access group, passing the access group name as the value of the`access-group`
modifier when creating each store. (This is also how such an application can specify
which group it wants to use when creating a new credential.)

If you have retrieved a wrapper entry and want to know the access group of the
underlying item, you can downcast the wrapper entry to the `Cred` type and look
at its `access_group` field. For more information about this, see the many Apple
developer docs about sharing access groups among applications. Also look at the
`tests` example code for the tests of ambiguity.

## Access control

Protected data items _in the local store_ can be created with varying levels of
protection. This module uses a default access policy of "accessible when device
is unlocked", but entry modifiers can be used to change this. See the docs for
[build](Store::build) for details.

## Attributes

This store exposes no attributes.

## Search

This store exposes search over both the local and cloud-synchronized stores.
You can search for credentials by service and/or user (case-sensitive exact match),
and you can restrict searches to a specific access group.
If you specify neither a service nor a user, then the search will return all
credentials in the store (or access group), but read on for restrictions.

The OS, by design, does not expose the access policy on existing secrets in the
store. So the wrapper entries returned from search will always have the default
access policy, not the policy of the entry that was found.

Items whose access policy requires user interaction will pop an authentication
dialog during the search. To avoid this, the default behavior of searches is
to skip over these entries. You can specify in the search spec that you want
them not to be skipped, but this is not recommended.
 */

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use log::error;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error;
use security_framework::item;
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};

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
    AfterFirstUnlockThisDeviceOnly,
    #[default]
    WhenUnlocked,
    WhenUnlockedThisDeviceOnly,
    WhenPasscodeSetThisDeviceOnly,
    RequireUserPresence,
}

impl AccessPolicy {
    fn as_ref(&self) -> &AccessPolicy {
        self
    }
}

impl From<&AccessPolicy> for ProtectionMode {
    fn from(value: &AccessPolicy) -> Self {
        match value {
            AccessPolicy::AfterFirstUnlock => ProtectionMode::AccessibleAfterFirstUnlock,
            AccessPolicy::AfterFirstUnlockThisDeviceOnly => {
                ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly
            }
            AccessPolicy::WhenUnlocked => ProtectionMode::AccessibleWhenUnlocked,
            AccessPolicy::WhenUnlockedThisDeviceOnly => {
                ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly
            }
            AccessPolicy::WhenPasscodeSetThisDeviceOnly => {
                ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly
            }
            AccessPolicy::RequireUserPresence => ProtectionMode::AccessibleWhenUnlocked,
        }
    }
}

/// The representation of a generic password credential.
///
/// If there is no access group, the credential will be created in a
/// default group as chosen by the OS per
/// [these guidelines](https://developer.apple.com/documentation/security/ksecattraccessgroup).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cred {
    pub service: String,
    pub account: String,
    pub access_policy: AccessPolicy,
    pub access_group: Option<String>,
    pub cloud_synchronize: bool,
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
        access_policy: AccessPolicy,
        access_group: Option<String>,
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
        let cred = Self {
            service: service.to_string(),
            account: user.to_string(),
            access_policy,
            access_group,
            cloud_synchronize,
        };
        Ok(Entry::new_with_credential(Arc::new(cred)))
    }

    fn build_from_search_result(result: &item::SearchResult, cloud_sync: bool) -> Result<Entry> {
        if let Some(attrs) = result.simplify_dict() {
            let service = attrs.get("svce").ok_or_else(|| {
                ErrorCode::Invalid("search result".to_string(), "has no service".to_string())
            })?;
            let account = attrs.get("acct").ok_or_else(|| {
                ErrorCode::Invalid("search result".to_string(), "has no account".to_string())
            })?;
            let group = attrs.get("agrp").cloned();
            Ok(Entry::new_with_credential(Arc::new(Cred {
                service: service.clone(),
                account: account.clone(),
                access_group: group,
                access_policy: Default::default(),
                cloud_synchronize: cloud_sync,
            })))
        } else {
            // should never happen
            Err(ErrorCode::Invalid(
                "search result".to_string(),
                "has no attributes".to_string(),
            ))
        }
    }

    fn clone_from_search_result(&self, result: &item::SearchResult) -> Self {
        let mut cred = self.clone();
        if let Some(attrs) = result.simplify_dict() {
            if let Some(group) = attrs.get("agrp") {
                cred.access_group = Some(group.to_string());
            } else {
                // should never happen, so warn if it does
                error!("Search result credential has no access group; using entry's group")
            }
        } else {
            // should never happen, so warn if it does
            error!("Search result credential has no attributes; using entry's group")
        }
        cred
    }
}

impl CredentialApi for Cred {
    /// See the keychain-core API docs.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
        options.use_protected_keychain();
        if let Some(access_group) = &self.access_group {
            options.set_access_group(access_group);
        }
        if self.cloud_synchronize {
            options.set_access_synchronized(Some(true));
        } else {
            match &self.access_policy {
                AccessPolicy::RequireUserPresence => {
                    let access_control = SecAccessControl::create_with_protection(
                        Some(self.access_policy.as_ref().into()),
                        AccessControlOptions::USER_PRESENCE.bits(),
                    )
                    .map_err(decode_error)?;
                    options.set_access_control(access_control);
                }
                other => {
                    options.set_access_control(
                        SecAccessControl::create_with_protection(
                            Some(other.into()),
                            Default::default(),
                        )
                        .map_err(decode_error)?,
                    );
                }
            }
        }
        set_generic_password_options(secret, options).map_err(decode_error)?;
        Ok(())
    }

    /// See the keychain-core API docs.
    fn get_secret(&self) -> Result<Vec<u8>> {
        let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
        options.use_protected_keychain();
        if let Some(access_group) = &self.access_group {
            options.set_access_group(access_group);
        }
        if self.cloud_synchronize {
            options.set_access_synchronized(Some(true));
        }
        generic_password(options).map_err(decode_error)
    }

    /// See the keychain-core API docs.
    fn delete_credential(&self) -> Result<()> {
        let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
        options.use_protected_keychain();
        if let Some(access_group) = &self.access_group {
            options.set_access_group(access_group);
        }
        if self.cloud_synchronize {
            options.set_access_synchronized(Some(true));
        }
        delete_generic_password_options(options).map_err(decode_error)?;
        Ok(())
    }

    /// See the keychain-core API docs.
    ///
    /// There are two cases:
    /// 1. If the cred has an access group, then it can't be ambiguous,
    ///    so we just make sure that it exists before returning None.
    /// 2. If the cred has no access group, then we do a search to
    ///    check for ambiguity and, if none, return a wrapper that has
    ///    the access group attached.
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        if let Some(access_group) = &self.access_group {
            let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
            options.use_protected_keychain();
            options.set_access_group(access_group);
            if self.cloud_synchronize {
                options.set_access_synchronized(Some(true));
            }
            generic_password(options).map_err(decode_error)?;
            Ok(None)
        } else {
            let results = search_items(
                Some(&self.service),
                Some(&self.account),
                self.access_group.as_deref(),
                self.cloud_synchronize,
                false,
            )?;
            match results.len() {
                0 => Err(ErrorCode::NoEntry),
                1 => Ok(Some(Arc::new(self.clone_from_search_result(&results[0])))),
                _ => {
                    let entries: Vec<Entry> = results
                        .iter()
                        .map(|r| {
                            Entry::new_with_credential(Arc::new(self.clone_from_search_result(r)))
                        })
                        .collect();
                    Err(ErrorCode::Ambiguous(entries))
                }
            }
        }
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

/// The builder for iOS keychain credentials
pub struct Store {
    id: String,
    access_group: Option<String>,
    cloud_synchronize: bool,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("vendor", &self.vendor())
            .field("id", &self.id())
            .field("access_group", &self.access_group)
            .field("cloud_synchronize", &self.cloud_synchronize)
            .finish()
    }
}

impl Store {
    /// Create a default store, which does *not* synchronize with the cloud.
    pub fn new() -> Result<Arc<Self>> {
        Ok(Self::new_internal(None, false))
    }

    /// Create a configured store.
    ///
    /// There are two allowed configuration keys:
    /// - `cloud-sync` (`true` or `false`), default false. Specifying this key as true
    ///   will sync all items in the store with iCloud.
    /// - `access-group`. If non-empty, this store will store all its items in the
    ///   specified access group. If empty or not specified, as in the default configuration,
    ///   all items will be stored in the app's default access group.
    pub fn new_with_configuration(config: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        let config = parse_attributes(&["access-group", "*cloud-sync"], Some(config))?;
        let mut cloud_synchronize = false;
        let mut access_group = None;
        if let Some(option) = config.get("cloud-sync") {
            cloud_synchronize = option.eq("true");
        }
        if let Some(option) = config.get("access-group") {
            if !option.is_empty() {
                access_group = Some(option.to_string());
            }
        }
        Ok(Self::new_internal(access_group, cloud_synchronize))
    }

    fn new_internal(access_group: Option<String>, cloud_synchronize: bool) -> Arc<Self> {
        let now = SystemTime::now();
        let elapsed = if now.lt(&UNIX_EPOCH) {
            UNIX_EPOCH.duration_since(now).unwrap()
        } else {
            now.duration_since(UNIX_EPOCH).unwrap()
        };
        let id = format!(
            "Protected Data Storage, Crate version {}, Instantiated at {}",
            env!("CARGO_PKG_VERSION"),
            elapsed.as_secs_f64()
        );
        Arc::new(Store {
            id,
            access_group,
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
    /// There is only one allowed modifier: `access-policy`, which can be one of
    /// these (case-insensitive) values (ordered least to most restrictive):
    /// - `AfterFirstUnlock` (or `after-first-unlock`)
    /// - `AfterFirstUnlockThisDeviceOnly` (or `after-first-unlock-this-device-only`)
    /// - `WhenUnlocked` (or `when-unlocked`), the default
    /// - `WhenUnlockedThisDeviceOnly` (or `when-unlocked-this-device-only`)
    /// - `WhenPasscodeSetThisDeviceOnly` (or `when-passcode-set-this-device-only`)
    /// - `RequireUserPresence` (or `require-user-presence`)
    ///
    /// These correspond to similarly named values of the `kSecAttrAccessible` attribute,
    /// described in the
    /// [Apple docs](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility),
    /// except for `RequireUserPresence` which is like
    /// `WhenUnlocked` but adds a requirement to do biometric authentication whenever
    /// the credential is accessed.
    ///
    /// Note: You cannot specify an access policy in a cloud-synchronized store: the
    /// OS controls this access to manage synchronization.
    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let mods = parse_attributes(&["access-policy"], modifiers)?;
        if self.cloud_synchronize && mods.contains_key("access-policy") {
            return Err(ErrorCode::Invalid(
                "access-policy".to_string(),
                "cannot be specified in a cloud-synchronized store".to_string(),
            ));
        }
        Cred::build(
            service,
            user,
            determine_access_policy(&mods)?,
            self.access_group.clone(),
            self.cloud_synchronize,
        )
    }

    /// See the keychain-core API docs.
    ///
    /// The primary spec keys are `service`, `account`, and `access-group`, which
    /// restrict the search to items which match (case-sensitive) the given values.
    /// Without any restrictions, every generic password item in the store is returned.
    ///
    /// There is a `show-authentication-ui` key (value true or false, default false)
    /// which can be used to prevent the default behavior of skipping
    /// any items whose access policy requires user interaction.
    ///
    /// Because the OS hides the access policy information
    /// of existing items, every wrapper returned from a search has a
    /// default access policy which may or may not match that of the item
    /// it wraps. This default access policy has no effect unless you
    /// delete the underlying item and re-create it from the wrapper
    /// by setting its password.
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let spec = parse_attributes(
            &[
                "service",
                "account",
                "access-group",
                "*show-authentication-ui",
            ],
            Some(spec),
        )?;
        let cloud_sync = self.cloud_synchronize;
        let show_ui = spec
            .get("show-authentication-ui")
            .is_some_and(|s| s.eq("true"));
        let items = search_items(
            spec.get("service").map(String::as_str),
            spec.get("account").map(String::as_str),
            spec.get("access-group").map(String::as_str),
            cloud_sync,
            !show_ui,
        )?;
        let mut results = Vec::new();
        for item in items.iter() {
            results.push(Cred::build_from_search_result(item, cloud_sync)?)
        }
        Ok(results)
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

fn search_items(
    service: Option<&str>,
    account: Option<&str>,
    access_group: Option<&str>,
    cloud_sync: bool,
    suppress_ui: bool,
) -> Result<Vec<item::SearchResult>> {
    let mut options = item::ItemSearchOptions::new();
    options
        .class(item::ItemClass::generic_password())
        .load_attributes(true)
        .limit(item::Limit::All)
        .skip_authenticated_items(suppress_ui);
    if let Some(service) = service {
        options.service(service);
    }
    if let Some(account) = account {
        options.account(account);
    }
    if let Some(access_group) = access_group {
        options.access_group(access_group);
    }
    options.cloud_sync(Some(cloud_sync));
    #[cfg(target_os = "macos")]
    options.ignore_legacy_keychains();
    let result = options.search();
    match result {
        Ok(results) => Ok(results),
        Err(err) => match decode_error(err) {
            ErrorCode::NoEntry => Ok(Vec::new()),
            other => Err(other),
        },
    }
}

fn determine_access_policy(mods: &HashMap<String, String>) -> Result<AccessPolicy> {
    if let Some(policy) = mods.get("access-policy") {
        match policy.to_ascii_lowercase().as_str() {
            "after-first-unlock" | "afterfirstunlock" => Ok(AccessPolicy::AfterFirstUnlock),
            "after-first-unlock-this-device-only" | "afterfirstunlockthisdeviceonly" => {
                Ok(AccessPolicy::AfterFirstUnlock)
            }
            "when-unlocked" | "whenunlocked" | "default" => Ok(AccessPolicy::WhenUnlocked),
            "when-unlocked-this-device-only" | "whenunlockedthisdeviceonly" => {
                Ok(AccessPolicy::WhenUnlocked)
            }
            "require-user-presence" | "requireuserpresence" => {
                Ok(AccessPolicy::RequireUserPresence)
            }
            "when-passcode-set-this-device-only" | "whenpasscodesetthisdeviceonly" => {
                Ok(AccessPolicy::WhenPasscodeSetThisDeviceOnly)
            }
            _ => Err(ErrorCode::Invalid(
                "access-policy".to_string(),
                format!("unknown value: {policy}"),
            )),
        }
    } else {
        Ok(AccessPolicy::default())
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
        -34018 => ErrorCode::PlatformFailure(Box::new(err)), // errSecMissingEntitlement
        _ => ErrorCode::PlatformFailure(Box::new(err)),
    }
}
