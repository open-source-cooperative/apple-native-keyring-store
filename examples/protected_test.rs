/*!

# Static library for protected feature testing

This is a static library meant to be linked into the
[Rust-on-ios test harness](https://github.com/brotskydotcom/rust-on-ios/).
It provides testing in a provisioned-profile environment for the
protected data store.

*/

use std::backtrace;
use std::collections::HashMap;
use std::ffi::{CString, c_char};
use std::io::Write;
use std::panic::catch_unwind;
use std::sync::{Arc, LazyLock};

use linkme::distributed_slice;

use keyring_core::{CredentialStore, Entry, Error, api::CredentialPersistence, get_default_store};

use apple_native_keyring_store::protected::Cred;
use apple_native_keyring_store::protected::Store;

static OP_STRINGS: &str = "
    run tests
    delete all credentials
    ";

static OP_STRING: LazyLock<CString> = LazyLock::new(|| CString::new(OP_STRINGS).unwrap());

#[unsafe(no_mangle)]
extern "C" fn choices() -> *const c_char {
    let ret = &*OP_STRING;
    ret.as_ptr()
}

#[unsafe(no_mangle)]
extern "C" fn test(op: i32) {
    match op {
        0 => run_tests(),
        1 => delete_all_credentials(),
        _ => println!("unexpected op: {op}"),
    }
}

fn delete_all_credentials() {
    let local: Arc<CredentialStore> = Store::new().unwrap();
    println!("Deleting all non-cloud-synchronized items...");
    list_and_delete_credentials(local);
    let mods = HashMap::from([("cloud-sync", "true")]);
    let cloud: Arc<CredentialStore> = Store::new_with_configuration(&mods).unwrap();
    println!("Deleting all cloud-synchronized items...");
    list_and_delete_credentials(cloud);
    println!("Done.");
}

fn list_and_delete_credentials(store: Arc<CredentialStore>) {
    match store.search(&HashMap::from([("show-authentication-ui", "true")])) {
        Ok(entries) => {
            if entries.is_empty() {
                println!("Nothing to delete.");
                return;
            }
            println!("Found {} to delete:", entries.len());
            for entry in entries {
                println!("  {:?}", entry.get_specifiers().unwrap());
                entry.delete_credential().unwrap_or_else(|err| {
                    println!("Couldn't delete credential: {err:?}");
                });
            }
        }
        Err(err) => println!("Search failed: {err:?}"),
    }
}

#[distributed_slice]
static TESTS: [fn()];

fn run_tests() {
    keyring_core::set_default_store(Store::new().unwrap());
    let mut tests = TESTS.to_vec();
    tests.reverse();
    let count = tests.len();
    println!("running {count} tests:");
    let mut succeeded = 0;
    let mut failed = 0;
    for test in tests {
        match catch_unwind(test) {
            Ok(()) => {
                succeeded += 1;
                let total = succeeded + failed;
                print!(".");
                if total % 5 == 0 {
                    println!(" {total}/{count}");
                } else {
                    std::io::stdout().flush().unwrap();
                }
            }
            Err(err) => {
                failed += 1;
                let backtrace = backtrace::Backtrace::force_capture();
                if backtrace.status() == backtrace::BacktraceStatus::Captured {
                    println!("Test failed: {err:?}\nBacktrace:\n{backtrace:?}\n")
                } else {
                    println!("Test failed: {err:?}\n");
                }
            }
        }
    }
    println!("\n{count} tests complete: {succeeded} succeeded, {failed} failed");
    keyring_core::unset_default_store();
}

#[distributed_slice(TESTS)]
fn test_persistence() {
    assert!(matches!(
        get_default_store().unwrap().persistence(),
        CredentialPersistence::UntilDelete
    ));
}

#[distributed_slice(TESTS)]
fn test_store_methods() {
    let store = get_default_store().unwrap();
    let vendor1 = store.vendor();
    let id1 = store.id();
    let vendor2 = store.vendor();
    let id2 = store.id();
    assert_eq!(vendor1, vendor2);
    assert_eq!(id1, id2);
    let store2: Arc<CredentialStore> = Store::new().unwrap();
    let vendor3 = store2.vendor();
    let id3 = store2.id();
    assert_eq!(vendor1, vendor3);
    assert_ne!(id1, id3);
}

fn entry_new(service: &str, user: &str) -> Entry {
    Entry::new(service, user).unwrap_or_else(|err| {
        panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
    })
}

fn generate_random_string() -> String {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(fastrand::alphanumeric).take(12).collect()
}

fn generate_random_bytes() -> Vec<u8> {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(|| fastrand::u8(..)).take(24).collect()
}

// A round-trip password test that doesn't delete the credential afterward
fn test_round_trip_no_delete(case: &str, entry: &Entry, in_pass: &str) {
    entry
        .set_password(in_pass)
        .unwrap_or_else(|err| panic!("Can't set password for {case}: {err:?}"));
    let out_pass = entry
        .get_password()
        .unwrap_or_else(|err| panic!("Can't get password: {case}: {err:?}"));
    assert_eq!(
        in_pass, out_pass,
        "Passwords don't match for {case}: set='{in_pass}', get='{out_pass}'",
    )
}

// A round-trip password test that does delete the credential afterward
fn test_round_trip(case: &str, entry: &Entry, in_pass: &str) {
    test_round_trip_no_delete(case, entry, in_pass);
    entry
        .delete_credential()
        .unwrap_or_else(|err| panic!("Can't delete password: {case}: {err:?}"));
    let password = entry.get_password();
    assert!(
        matches!(password, Err(Error::NoEntry)),
        "Got a deleted password: {case}",
    );
}

// A round-trip secret test that does delete the credential afterward
pub fn test_round_trip_secret(case: &str, entry: &Entry, in_secret: &[u8]) {
    entry
        .set_secret(in_secret)
        .unwrap_or_else(|err| panic!("Can't set secret for {case}: {err:?}"));
    let out_secret = entry
        .get_secret()
        .unwrap_or_else(|err| panic!("Can't get secret for {case}: {err:?}"));
    assert_eq!(
        in_secret, &out_secret,
        "Secrets don't match for {case}: set='{in_secret:?}', get='{out_secret:?}'",
    );
    entry
        .delete_credential()
        .unwrap_or_else(|err| panic!("Can't delete credential for {case}: {err:?}"));
    let secret = entry.get_secret();
    assert!(
        matches!(secret, Err(Error::NoEntry)),
        "Got a deleted password: {case}",
    );
}

#[distributed_slice(TESTS)]
fn test_invalid_parameter() {
    Entry::new("service", "").unwrap_err();
    Entry::new("", "service").unwrap_err();
    let mods = HashMap::from([("access-policy", "incorrect")]);
    Entry::new_with_modifiers("service", "user", &mods).unwrap_err();
    let mods = HashMap::from([("cloud-sync", "true")]);
    let sync_store: Arc<CredentialStore> = Store::new_with_configuration(&mods).unwrap();
    let mods = HashMap::from([("access-policy", "anything")]);
    sync_store
        .build("service", "user", Some(&mods))
        .unwrap_err();
}

#[distributed_slice(TESTS)]
fn test_missing_entry() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

#[distributed_slice(TESTS)]
fn test_empty_password() {
    let name = generate_random_string();
    let in_pass = "";
    test_round_trip("empty password", &entry_new(&name, &name), in_pass);
}

#[distributed_slice(TESTS)]
fn test_round_trip_ascii_password() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip("ascii password", &entry, "test ascii password");
}

#[distributed_slice(TESTS)]
fn test_round_trip_non_ascii_password() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip("non-ascii password", &entry, "このきれいな花は桜です");
}

#[distributed_slice(TESTS)]
fn test_entries_with_same_and_different_specifiers() {
    let name1 = generate_random_string();
    let name2 = generate_random_string();
    let entry1 = entry_new(&name1, &name2);
    let entry2 = entry_new(&name1, &name2);
    let entry3 = entry_new(&name2, &name1);
    entry1.set_password("test password").unwrap();
    let pw2 = entry2.get_password().unwrap();
    assert_eq!(pw2, "test password");
    _ = entry3.get_password().unwrap_err();
    entry1.delete_credential().unwrap();
    _ = entry2.get_password().unwrap_err();
    entry3.delete_credential().unwrap_err();
}

#[distributed_slice(TESTS)]
fn test_round_trip_random_secret() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let secret = generate_random_bytes();
    test_round_trip_secret("non-ascii password", &entry, secret.as_slice());
}

#[distributed_slice(TESTS)]
fn test_update() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip_no_delete("initial ascii password", &entry, "test ascii password");
    test_round_trip(
        "updated non-ascii password",
        &entry,
        "このきれいな花は桜です",
    );
}

#[distributed_slice(TESTS)]
fn test_duplicate_entries() {
    let name = generate_random_string();
    let entry1 = entry_new(&name, &name);
    let entry2 = entry_new(&name, &name);
    entry1.set_password("password for entry1").unwrap();
    let password = entry2.get_password().unwrap();
    assert_eq!(password, "password for entry1");
    entry2.set_password("password for entry2").unwrap();
    let password = entry1.get_password().unwrap();
    assert_eq!(password, "password for entry2");
    entry1.delete_credential().unwrap();
    entry2.delete_credential().expect_err("Can delete entry2");
}

#[distributed_slice(TESTS)]
fn test_get_credential_and_specifiers() {
    let name = generate_random_string();
    let entry1 = entry_new(&name, &name);
    assert!(matches!(entry1.get_credential(), Err(Error::NoEntry)));
    entry1.set_password("password for entry1").unwrap();
    let cred1 = entry1.as_any().downcast_ref::<Cred>().unwrap();
    assert!(cred1.access_group.is_none());
    let wrapper = entry1.get_credential().unwrap();
    let cred2 = wrapper.as_any().downcast_ref::<Cred>().unwrap();
    assert!(cred2.access_group.is_some());
    let (service, user) = wrapper.get_specifiers().unwrap();
    assert_eq!(service, name);
    assert_eq!(user, name);
    wrapper.delete_credential().unwrap();
    entry1.delete_credential().unwrap_err();
    wrapper.delete_credential().unwrap_err();
}

#[distributed_slice(TESTS)]
fn test_create_then_move() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let test = move || {
        let password = "test ascii password";
        entry.set_password(password).unwrap();
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, password);
        let password = "このきれいな花は桜です";
        entry.set_password(password).unwrap();
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, password);
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    };
    let handle = std::thread::spawn(test);
    assert!(handle.join().is_ok(), "Couldn't execute on thread")
}

#[distributed_slice(TESTS)]
fn test_simultaneous_create_then_move() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("{}-{}", generate_random_string(), i);
        let entry = entry_new(&name, &name);
        let test = move || {
            entry.set_password(&name).unwrap();
            let stored_password = entry.get_password().unwrap();
            assert_eq!(stored_password, name);
            entry.delete_credential().unwrap();
            assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[distributed_slice(TESTS)]
fn test_create_set_then_move() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let password = "test ascii password";
    entry.set_password(password).unwrap();
    let test = move || {
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, password);
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    };
    let handle = std::thread::spawn(test);
    assert!(handle.join().is_ok(), "Couldn't execute on thread")
}

#[distributed_slice(TESTS)]
fn test_simultaneous_create_set_then_move() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("{}-{}", generate_random_string(), i);
        let entry = entry_new(&name, &name);
        entry.set_password(&name).unwrap();
        let test = move || {
            let stored_password = entry.get_password().unwrap();
            assert_eq!(stored_password, name);
            entry.delete_credential().unwrap();
            assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[distributed_slice(TESTS)]
fn test_simultaneous_independent_create_set() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("thread_entry{i}");
        let test = move || {
            let entry = entry_new(&name, &name);
            entry.set_password(&name).unwrap();
            let stored_password = entry.get_password().unwrap();
            assert_eq!(stored_password, name);
            entry.delete_credential().unwrap();
            assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[distributed_slice(TESTS)]
fn test_multiple_create_delete_single_thread() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let repeats = 10;
    for _i in 0..repeats {
        entry.set_password(&name).unwrap();
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, name);
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    }
}

#[distributed_slice(TESTS)]
fn test_simultaneous_multiple_create_delete_single_thread() {
    let mut handles = vec![];
    for t in 0..10 {
        let name = generate_random_string();
        let test = move || {
            let name = format!("{name}-{t}");
            let entry = entry_new(&name, &name);
            let repeats = 10;
            for _i in 0..repeats {
                entry.set_password(&name).unwrap();
                let stored_password = entry.get_password().unwrap();
                assert_eq!(stored_password, name);
                entry.delete_credential().unwrap();
                assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
            }
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[distributed_slice(TESTS)]
fn test_shared_access_groups() {
    let name = generate_random_string();
    let standard_entry = entry_new(&name, &name);
    standard_entry.set_password("app group").unwrap();
    let mods = HashMap::from([("access-group", "group.com.brotsky.test-harness")]);
    let store: Arc<CredentialStore> = Store::new_with_configuration(&mods).unwrap();
    let shared_entry = store.build(&name, &name, None).unwrap();
    // the shared entry has a specific access group, so it will be created there
    shared_entry.set_password("shared group").unwrap();
    // the shared entry has a specific access group, so it will be found there
    assert_eq!(shared_entry.get_password().unwrap(), "shared group");
    // the shared entry has a specific access group, so it is its own wrapper
    let wrapper = shared_entry.get_credential().unwrap();
    assert_eq!(
        shared_entry.as_any().downcast_ref::<Cred>().unwrap() as *const _,
        wrapper.as_any().downcast_ref::<Cred>().unwrap() as *const _
    );
    // the standard entry, which has no access group, will be found before the shared entry
    assert_eq!(standard_entry.get_password().unwrap(), "app group");
    // but the standard entry is, in fact, ambiguous
    let result = standard_entry.get_credential();
    if let Err(Error::Ambiguous(entries)) = result {
        assert_eq!(entries.len(), 2);
        let cred1 = entries[0].as_any().downcast_ref::<Cred>().unwrap();
        let cred2 = entries[1].as_any().downcast_ref::<Cred>().unwrap();
        assert_ne!(
            cred1.access_group.as_ref().unwrap(),
            "group.com.brotsky.test-harness"
        );
        assert_eq!(
            cred2.access_group.as_ref().unwrap(),
            "group.com.brotsky.test-harness"
        );
        print!(" (App ID is: {}) ", cred1.access_group.as_ref().unwrap());
        std::io::stdout().flush().unwrap();
    } else {
        panic!("Expected ambiguous error, get credential returned {result:?}");
    }
    test_round_trip("shared access group", &shared_entry, "test ascii password");
    // make sure the standard entry is still there and is now unambiguous
    assert_eq!(standard_entry.get_password().unwrap(), "app group");
    standard_entry.get_credential().unwrap();
    standard_entry.delete_credential().unwrap();
}

#[distributed_slice(TESTS)]
fn test_separate_sync_store() {
    let name = generate_random_string();
    let standard_entry = entry_new(&name, &name);
    standard_entry.set_password("non-sync entry").unwrap();
    let mods = HashMap::from([("cloud-sync", "true")]);
    let store: Arc<CredentialStore> = Store::new_with_configuration(&mods).unwrap();
    let sync_entry = store.build(&name, &name, None).unwrap();
    sync_entry.set_password("sync entry").unwrap();
    assert_eq!(sync_entry.get_password().unwrap(), "sync entry");
    assert_eq!(standard_entry.get_password().unwrap(), "non-sync entry");
    let standard_wrapper = standard_entry.get_credential().unwrap();
    let sync_wrapper = sync_entry.get_credential().unwrap();
    assert_eq!(
        standard_wrapper
            .as_any()
            .downcast_ref::<Cred>()
            .unwrap()
            .access_group,
        sync_wrapper
            .as_any()
            .downcast_ref::<Cred>()
            .unwrap()
            .access_group
    );
    standard_entry.delete_credential().unwrap();
    sync_entry.get_credential().unwrap();
    sync_entry.delete_credential().unwrap();
}

#[distributed_slice(TESTS)]
fn test_search_with_ui() {
    let base_count = Entry::search(&HashMap::new()).unwrap().len();
    let name1 = generate_random_string();
    let name2 = generate_random_string();
    let entry1 = entry_new(&name1, &name1);
    entry1.set_password("unprotected").unwrap();
    let count = Entry::search(&HashMap::new()).unwrap().len();
    assert_eq!(count, base_count + 1);
    let mods = HashMap::from([("access-policy", "require-user-presence")]);
    let entry2 = Entry::new_with_modifiers(&name2, &name2, &mods).unwrap();
    entry2.set_password("protected").unwrap();
    let count = Entry::search(&HashMap::new()).unwrap().len();
    assert_eq!(count, base_count + 1);
    let spec = HashMap::from([("show-authentication-ui", "true")]);
    let count = Entry::search(&spec).unwrap().len();
    assert_eq!(count, base_count + 2);
    entry1.delete_credential().unwrap();
    entry2.delete_credential().unwrap();
    let count = Entry::search(&spec).unwrap().len();
    assert_eq!(count, base_count);
}
