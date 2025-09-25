# Apple-native Keyring Store

This is a [keyring credential store provider](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring) that stores credentials in the native macOS and iOS secure stores. It’s compatible with [keyring-core](https://crates.io/crates/keyring-core) v0.4 and later.

If you are writing clients app that are _not_ code-signed by a provisioning profile (e.g., command-line apps), then you should use the `keychain` module of this store, which accesses the macOS keychain. (This is the module which is most compatible with [keyring v3](https://crates.io/crates/keyring/3.6.3) and earlier.)

If you are writing client apps that _are_ code-signed by a provisioning profile, then you should use the `protected` module of this store, which accesses the Apple Protected Data store. This module supports synchronizing credentials across devices via iCloud. It also supports requiring biometric authentication for credential access (although such credentials can be not be sync’d across devices).

**NOTE:** Because the cloud-sync capabilities of this store depend on a not-yet-published version of the Rust security-framework and security-framework-sys crates, they have been conditionalized against a `sync` feature which is off by default. If you are willing to build the crate locally, you can turn `sync` on and build the security framework from this git source specification:

```cargo
security-framework = { version = "3", git = "https://github.com/brotskydotcom/rust-security-framework.git", branch = "composite" }
security-framework-sys = { version = "2", git = "https://github.com/brotskydotcom/rust-security-framework.git", branch = "composite" }
```

## Usage

To use this keychain-compatible credential store provider, you must take a dependency on the [keyring-core crate](https://crates.io/crates/keyring-core) and on [this crate](https://crates.io/crates/apple-native-keyring-store). Then the exact formula for how to instantiate a credential store and/or a specific entry depends on whether you are using keychain or protected storage, and whether you are using features such as biometric authentication or iCloud synchronization. See the [docs for this crate](https://docs.rs/docs/apple-native-credential-store) for more detail. The `instantiation` example in this crate shows all of the various possibilities and how to use them. The `item_options` example in this crate builds a static library that can be embedded in an XCode app with a provisioning profile such as the [rust-on-ios test harness](https://github.com/brotskydotcom/rust-on-ios)

## Changelog

See the [release history on GitHub](https://github.com/open-source-cooperative/apple-native-keyring-store/releases) for full details.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.
