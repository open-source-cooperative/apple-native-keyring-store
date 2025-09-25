/*!

# Static library for protected feature testing

This is a static library meant to be linked into the
[Rust-on-ios test harness](https://github.com/brotskydotcom/rust-on-ios/).
It provides sample operations over default, presence-required, and cloud-synced items.

*/

use std::collections::HashMap;
use std::ffi::{CString, c_char};
use std::sync::{Arc, LazyLock};

use apple_native_keyring_store::protected::Store;
use keyring_core::{CredentialStore, Entry, Error, set_default_store};

static SERVICE: &str = "item-service";
static USER: &str = "item-account";

static LOCAL_STORE: LazyLock<Arc<CredentialStore>> = LazyLock::new(|| Store::new().unwrap());

static SYNC_STORE: LazyLock<Arc<CredentialStore>> = LazyLock::new(|| {
    let options = HashMap::from([("cloud-sync", "true")]);
    Store::new_with_configuration(&options).unwrap()
});

static OP_STRINGS: &str = "
    create default
    create sensitive
    create sync
    create sync insensitive
    set default
    set sensitive
    set sync
    set sync insensitive
    get default
    get default attributes
    get sync
    delete default
    delete sync
    search default
    search sync
    ";

static OP_STRING: LazyLock<CString> = LazyLock::new(|| CString::new(OP_STRINGS).unwrap());

#[unsafe(no_mangle)]
extern "C" fn choices() -> *const c_char {
    let ret = &*OP_STRING;
    ret.as_ptr()
}

#[unsafe(no_mangle)]
extern "C" fn test(op: i32) {
    let ops: Vec<fn()> = vec![
        create_default,
        create_sensitive,
        create_sync,
        create_sync_insensitive,
        set_default,
        set_sensitive,
        set_sync,
        set_sync_insensitive,
        get_default,
        get_default_credential,
        get_sync,
        delete_default,
        delete_sync,
        search_default,
        search_sync,
    ];
    let max_op = ops.len() as i32 - 1;
    if op >= 0 && op <= max_op {
        ops[op as usize]();
    }
}

fn create_default() {
    set_default_store((*LOCAL_STORE).clone());
    let entry = Entry::new(SERVICE, USER).unwrap();
    match entry.delete_credential() {
        Ok(_) => println!("There was a prior entry; deleting and recreating default"),
        Err(Error::NoEntry) => println!("There was no prior entry; creating default"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
    match entry.set_password("create-time default password") {
        Ok(_) => println!("Successfully set the default password"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn create_sensitive() {
    set_default_store((*LOCAL_STORE).clone());
    let modifiers = HashMap::from([("access-policy", "require-user-presence")]);
    let entry = Entry::new_with_modifiers(SERVICE, USER, &modifiers).unwrap();
    match entry.delete_credential() {
        Ok(_) => println!("There was a prior entry; deleting and recreating sensitive"),
        Err(Error::NoEntry) => println!("There was no prior entry; creating sensitive"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
    match entry.set_password("create-time sensitive password") {
        Ok(_) => println!("Successfully set the sensitive password"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn create_sync() {
    set_default_store((*SYNC_STORE).clone());
    let entry = Entry::new(SERVICE, USER).unwrap();
    match entry.delete_credential() {
        Ok(_) => println!("There was a prior entry; deleting and recreating sync"),
        Err(Error::NoEntry) => {
            println!("There was no prior entry; creating sync")
        }
        Err(err) => println!("Unexpected error: {err:?}"),
    }
    match entry.set_password("create-time sync password") {
        Ok(_) => println!("Successfully set the sync password"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn create_sync_insensitive() {
    set_default_store((*SYNC_STORE).clone());
    let modifiers = HashMap::from([("access-policy", "after-first-unlock")]);
    let entry = Entry::new_with_modifiers(SERVICE, USER, &modifiers).unwrap();
    match entry.delete_credential() {
        Ok(_) => println!("There was a prior entry; deleting and recreating sync-insensitive"),
        Err(Error::NoEntry) => {
            println!("There was no prior entry; creating sync-insensitive")
        }
        Err(err) => println!("Unexpected error: {err:?}"),
    }
    match entry.set_password("create-time sync-insensitive password") {
        Ok(_) => println!("Successfully set the sync-insensitive password"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn set_default() {
    set_default_store((*LOCAL_STORE).clone());
    let entry = Entry::new(SERVICE, USER).unwrap();
    match entry.get_credential() {
        Ok(_) => println!("Existing entry; updating it"),
        Err(Error::NoEntry) => println!("No existing entry; will create one"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
    match entry.set_password("set-time default password") {
        Ok(_) => println!("Successfully set the default password"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn set_sensitive() {
    set_default_store((*LOCAL_STORE).clone());
    let modifiers = HashMap::from([("access-policy", "require-user-presence")]);
    let entry = Entry::new_with_modifiers(SERVICE, USER, &modifiers).unwrap();
    match entry.get_credential() {
        Ok(_) => println!("There was a prior entry; setting sensitive"),
        Err(Error::NoEntry) => println!("There was no prior entry; creating sensitive"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
    match entry.set_password("set-time sensitive password") {
        Ok(_) => println!("Successfully set the sensitive password"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn set_sync() {
    set_default_store((*SYNC_STORE).clone());
    let entry = Entry::new(SERVICE, USER).unwrap();
    match entry.get_credential() {
        Ok(_) => println!("Existing cloud-sync entry; updating it"),
        Err(Error::NoEntry) => println!("No existing cloud-sync entry; will create one"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
    match entry.set_password("set-time sync password") {
        Ok(_) => println!("Successfully set the sync password"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn set_sync_insensitive() {
    set_default_store((*SYNC_STORE).clone());
    let modifiers = HashMap::from([("access-policy", "after-first-unlock")]);
    let entry = Entry::new_with_modifiers(SERVICE, USER, &modifiers).unwrap();
    match entry.get_credential() {
        Ok(_) => println!("Existing cloud-sync entry; updating it"),
        Err(Error::NoEntry) => println!("No existing cloud-sync entry; will create one"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
    match entry.set_password("set-time sync-insensitive password") {
        Ok(_) => println!("Successfully set the sync-insensitive password"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn get_default() {
    set_default_store((*LOCAL_STORE).clone());
    let entry = Entry::new(SERVICE, USER).unwrap();
    let password = entry.get_password();
    match password {
        Ok(password) => println!("Got password: {password}"),
        Err(Error::NoEntry) => println!("No entry found"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn get_default_credential() {
    set_default_store((*LOCAL_STORE).clone());
    let entry = Entry::new(SERVICE, USER).unwrap();
    match entry.get_credential() {
        Ok(credential) => println!("Got credential: {credential:?}"),
        Err(Error::NoEntry) => println!("No entry found"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn get_sync() {
    set_default_store((*SYNC_STORE).clone());
    let entry = Entry::new(SERVICE, USER).unwrap();
    let password = entry.get_password();
    match password {
        Ok(password) => println!("Got password: {password}"),
        Err(Error::NoEntry) => println!("No entry found"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn delete_default() {
    set_default_store((*LOCAL_STORE).clone());
    let entry = Entry::new(SERVICE, USER).unwrap();
    match entry.delete_credential() {
        Ok(_) => println!("Deleted entry"),
        Err(Error::NoEntry) => println!("No entry found to delete"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn delete_sync() {
    set_default_store((*SYNC_STORE).clone());
    let entry = Entry::new(SERVICE, USER).unwrap();
    match entry.delete_credential() {
        Ok(_) => println!("Deleted sync entry"),
        Err(Error::NoEntry) => println!("No sync entry found to delete"),
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn search_default() {
    set_default_store((*LOCAL_STORE).clone());
    match Entry::search(&HashMap::new()) {
        Ok(entries) => {
            println!("Found {} entries:", entries.len());
            for (i, wrapper) in entries.iter().enumerate() {
                println!("    {i}: {wrapper:?}");
            }
        }
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}

fn search_sync() {
    set_default_store((*SYNC_STORE).clone());
    match Entry::search(&HashMap::new()) {
        Ok(entries) => {
            println!("Found {} entries", entries.len());
            for (i, wrapper) in entries.iter().enumerate() {
                println!("    {i}: {wrapper:?}");
            }
        }
        Err(err) => println!("Unexpected error: {err:?}"),
    }
}
