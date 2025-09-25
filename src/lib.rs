/*!

# Apple native credential store

This is a
[keyring credential store provider](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring)
that stores credentials in the native macOS and iOS secure stores.

On iOS there is just one secure store: the "protected data" store.
Its _items_ are stored in "access groups" associated with specific applications.

On macOS there are two secure stores: the "legacy keychain" store and the "protected data" store.

- The "legacy keychain" store is available to all applications, and its credentials are stored
  in _keychain entries_ in encrypted files.
- The "protected data" store is available to sandboxed applications
  in macOS 10.15 (_Catalina_, 2019) or later. Some of its features are only available
  to applications with provisioning profiles.

Because the two native stores are different, this crate provides two different modules,
one for each store. Choose the one that best suits your needs or use both. See the module
documentation for the details of each store.

## Features

Each module has a feature that enables it. At least one relevant feature must be enabled,
and both can be enabled.

- `keychain`: Provides access to the "legacy keychain" store. Ignored on iOS.
- `protected`: Provides access to the "protected data" store. Requires macOS 10.15 or later.

This crate has no default features.

 */

#[cfg(all(
    target_os = "macos",
    not(any(feature = "keychain", feature = "protected"))
))]
compile_error!("At least one of the `keychain` or `protected` features must be enabled on macOS");

#[cfg(all(target_os = "macos", feature = "keychain"))]
pub mod keychain;

#[cfg(all(target_os = "macos", feature = "keychain", not(feature = "protected")))]
#[cfg(test)]
mod keychain_test;

#[cfg(all(target_os = "ios", not(feature = "protected")))]
compile_error!("The `protected` feature is required on iOS");

#[cfg(feature = "protected")]
pub mod protected;
