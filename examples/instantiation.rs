use std::collections::HashMap;

use apple_native_keyring_store::{keychain, protected};
use keyring_core::{Entry, Result};

fn main() {
    report_error("login keychain sample", login_keychain_sample());
    report_error("system keychain sample", system_keychain_sample());
    report_error("protected keychain sample", protected_keychain_sample());
    report_error("cloud keychain sample", cloud_keychain_sample());
}

fn login_keychain_sample() -> Result<()> {
    keyring_core::set_default_store(keychain::Store::new()?);
    let e1 = Entry::new("test-service", "test-user")?;
    e1.set_password("login keychain test succeeded")?;
    println!("The test password is '{:?}'", e1.get_password()?);
    e1.delete_credential()?;
    keyring_core::unset_default_store();
    Ok(())
}

fn system_keychain_sample() -> Result<()> {
    let config = HashMap::from([("keychain", "system")]);
    keyring_core::set_default_store(keychain::Store::new_with_configuration(&config)?);
    let e1 = Entry::new("test-system-service", "test-system-user")?;
    e1.set_password("system keychain test succeeded")?;
    println!("The test password is '{:?}'", e1.get_password()?);
    e1.delete_credential()?;
    keyring_core::unset_default_store();
    Ok(())
}

fn protected_keychain_sample() -> Result<()> {
    keyring_core::set_default_store(protected::Store::new()?);
    let e1 = Entry::new("test-protected-service", "test-protected-user")?;
    e1.set_password("protected keychain test succeeded")?;
    println!("The test password is '{:?}'", e1.get_password()?);
    e1.delete_credential()?;
    // don't require unlock on a specific entry
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

fn cloud_keychain_sample() -> Result<()> {
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
