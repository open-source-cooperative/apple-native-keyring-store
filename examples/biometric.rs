use std::collections::HashMap;

use apple_native_keyring_store::keychain;
use keyring_core::{Entry, Result};

const SERVICE: &str = "biometric-test";
const ACCOUNT: &str = "test-user";
const SECRET: &str = "s3cret-p@ssw0rd";

fn main() {
    let touch_id = std::env::args().nth(1).as_deref() == Some("--touch-id");

    println!("=== mode: {} ===\n", if touch_id { "touch-id" } else { "plain" });

    if touch_id {
        if apple_native_keyring_store::biometric::is_available() {
            println!("Touch ID: available");
        } else {
            println!("Touch ID: NOT available — operations will fail");
        }
    }

    let store = if touch_id {
        let config = HashMap::from([("touch-id", "true")]);
        keychain::Store::new_with_configuration(&config)
    } else {
        keychain::Store::new()
    };
    let store = store.unwrap();
    keyring_core::set_default_store(store);

    run("set password", || {
        let entry = Entry::new(SERVICE, ACCOUNT)?;
        entry.set_password(SECRET)?;
        println!("  stored '{SECRET}'");
        Ok(())
    });

    run("get password", || {
        let entry = Entry::new(SERVICE, ACCOUNT)?;
        let pw = entry.get_password()?;
        println!("  retrieved '{pw}'");
        assert_eq!(pw, SECRET, "password mismatch: expected '{SECRET}', got '{pw}'");
        Ok(())
    });

    run("delete credential", || {
        let entry = Entry::new(SERVICE, ACCOUNT)?;
        entry.delete_credential()?;
        println!("  deleted");
        Ok(())
    });

    run("verify deleted", || {
        let entry = Entry::new(SERVICE, ACCOUNT)?;
        match entry.get_password() {
            Err(keyring_core::Error::NoEntry) => {
                println!("  confirmed gone");
                Ok(())
            }
            Ok(pw) => panic!("expected NoEntry, got password '{pw}'"),
            Err(e) => Err(e),
        }
    });

    keyring_core::unset_default_store();
    println!("\ndone.");
}

fn run(label: &str, f: impl FnOnce() -> Result<()>) {
    print!("[{label}] ");
    match f() {
        Ok(()) => println!("  OK"),
        Err(e) => println!("  FAILED: {e:?}"),
    }
}
