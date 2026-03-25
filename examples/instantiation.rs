use std::collections::HashMap;

use keyring_core::{Entry, Result};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut done = false;
    if args.len() < 2 || args[1] == "user" {
        done = true;
        #[cfg(feature = "keychain")]
        report_error("login keychain sample", login_keychain_sample());
        #[cfg(not(feature = "keychain"))]
        println!("You must enable the 'keychain' feature to run this example.")
    }
    if args.len() > 1 && args[1] == "system" {
        done = true;
        #[cfg(feature = "keychain")]
        report_error("system keychain sample", system_keychain_sample());
        #[cfg(not(feature = "keychain"))]
        println!("You must enable the 'keychain' feature to run this example.")
    }
    if args.len() > 1 && args[1] == "protected" {
        done = true;
        #[cfg(feature = "protected")]
        {
            report_error("protected keychain sample", protected_keychain_sample());
            report_error("cloud keychain sample", cloud_keychain_sample());
        }
        #[cfg(not(feature = "protected"))]
        println!("You must enable the 'protected' feature to run this example.")
    }
    if !done {
        println!("Usage: {} [user|system|protected]", args[0]);
    }
}

#[cfg(feature = "keychain")]
fn login_keychain_sample() -> Result<()> {
    use apple_native_keyring_store::keychain;
    keyring_core::set_default_store(keychain::Store::new()?);
    let e1 = Entry::new("test-service", "test-user")?;
    e1.set_password("login keychain test succeeded")?;
    println!("The test password is '{:?}'", e1.get_password()?);
    e1.delete_credential()?;
    keyring_core::unset_default_store();
    Ok(())
}

#[cfg(feature = "keychain")]
fn system_keychain_sample() -> Result<()> {
    use apple_native_keyring_store::keychain;
    if sudo::check() != sudo::RunningAs::Root {
        println!("Using the system keychain requires root privileges.");
        println!("You will be prompted for your password to escalate privileges.");
    }
    sudo::escalate_if_needed().expect("sudo failed");
    let config = HashMap::from([("keychain", "system")]);
    keyring_core::set_default_store(keychain::Store::new_with_configuration(&config)?);
    let e1 = Entry::new("test-system-service", "test-system-user")?;
    e1.set_password("system keychain test succeeded")?;
    println!("The test password is '{:?}'", e1.get_password()?);
    e1.delete_credential()?;
    keyring_core::unset_default_store();
    Ok(())
}

#[cfg(feature = "protected")]
fn protected_keychain_sample() -> Result<()> {
    use apple_native_keyring_store::protected;
    keyring_core::set_default_store(protected::Store::new()?);
    let e1 = Entry::new("test-protected-service", "test-protected-user")?;
    e1.set_password("protected keychain test succeeded")?;
    println!("The test password is '{:?}'", e1.get_password()?);
    e1.delete_credential()?;
    // don't require per-use unlock on a specific entry
    let mods = HashMap::from([("access-policy", "after-first-unlock")]);
    let e1 = Entry::new_with_modifiers("test-protected-service", "test-protected-user", &mods)?;
    e1.set_password("after-first-access, protected keychain test succeeded")?;
    println!("The test password is '{:?}'", e1.get_password()?);
    e1.delete_credential()?;
    // require biometric authentication on a specific entry
    let mods = HashMap::from([("access-policy", "require-user-presence")]);
    let e1 = Entry::new_with_modifiers("test-protected-service", "test-protected-user", &mods)?;
    e1.set_password("biometric, protected keychain test succeeded")?;
    println!("The test password is '{:?}'", e1.get_password()?);
    e1.delete_credential()?;
    keyring_core::unset_default_store();
    Ok(())
}

#[cfg(feature = "protected")]
fn cloud_keychain_sample() -> Result<()> {
    use apple_native_keyring_store::protected;
    let config = HashMap::from([("cloud-sync", "true")]);
    keyring_core::set_default_store(protected::Store::new_with_configuration(&config)?);
    let e1 = Entry::new("test-icloud-service", "test-icloud-user")?;
    e1.set_password("this is a cloud test")?;
    println!("The test password is {:?}", e1.get_password()?);
    e1.delete_credential()?;
    keyring_core::unset_default_store();
    Ok(())
}

fn report_error(example: &str, result: Result<()>) {
    if let Err(e) = result {
        println!("{example} failed with error: {e:?}");
        keyring_core::unset_default_store();
    } else {
        println!("{example} ran with no errors.");
    }
}
