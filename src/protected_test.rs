//! Protected store tests, run on the iOS simulator with the entitlements in
//! `tests/ios-simulator.entitlements` linked into the test binary.
//!
//! User presence is not covered because the simulator does not enforce it.

use keyring_core::{Entry, Error, api::CredentialStoreApi};

use super::protected::Store;

/// Deletes the entry when dropped, so a failing test cleans up too.
struct Cleanup(Entry);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.delete_credential();
    }
}

/// Runs `body` on an entry whose service name is unique to `test`.
fn with_entry(test: &str, body: impl FnOnce(&Entry)) {
    let service = format!("apple-native-keyring-store-{test}-{}", std::process::id());
    let cleanup = Cleanup(Store::new().unwrap().build(&service, "user", None).unwrap());
    body(&cleanup.0);
}

#[test]
fn set_then_get_returns_the_secret() {
    with_entry("set-then-get", |entry| {
        entry.set_password("first secret").unwrap();
        assert_eq!(entry.get_password().unwrap(), "first secret");
    });
}

#[test]
fn second_set_overwrites() {
    with_entry("second-set", |entry| {
        entry.set_password("first secret").unwrap();
        entry.set_password("second secret").unwrap();
        assert_eq!(entry.get_password().unwrap(), "second secret");
    });
}

#[test]
fn delete_removes_the_entry() {
    with_entry("delete", |entry| {
        entry.set_password("first secret").unwrap();
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    });
}

#[test]
fn missing_entry_is_no_entry() {
    with_entry("missing", |entry| {
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        assert!(matches!(entry.delete_credential(), Err(Error::NoEntry)));
    });
}

#[test]
fn binary_secret_round_trips() {
    with_entry("binary", |entry| {
        let secret = [0u8, 1, 0x7f, 0x80, 0xfe, 0xff];
        entry.set_secret(&secret).unwrap();
        assert_eq!(entry.get_secret().unwrap(), secret);
    });
}
