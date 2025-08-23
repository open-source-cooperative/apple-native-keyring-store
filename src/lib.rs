/*!

# Apple native credential store

This is a
[keyring credential store provider](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring)
that stores credentials in the native macOS and iOS secure stores. It contains two
different credential store providers: one for the legacy macOS keychain (in the
[keychain] module), and one for the newer "protected data" store (in the
[protected] module).

 */

#[cfg(target_os = "macos")]
pub mod keychain;
#[cfg(target_os = "macos")]
#[cfg(test)]
mod keychain_test;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod protected;
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[cfg(test)]
mod protected_test;
