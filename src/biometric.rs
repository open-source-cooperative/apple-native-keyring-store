/*!

# Touch ID / biometric authentication via LAContext

Provides app-level biometric gating for keychain operations,
mirroring the approach used by
[keychain-fingerprint](https://github.com/dss99911/keychain-fingerprint):
authenticate with Touch ID first, then proceed with regular keychain access.

This module requires the `biometric` feature and only works on macOS
with Touch ID hardware.

*/

use std::sync::mpsc;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use keyring_core::error::{Error as ErrorCode, Result};

const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthentication;

/// Check whether biometric authentication (Touch ID) is available on this device.
pub fn is_available() -> bool {
    let context = unsafe { LAContext::new() };
    unsafe { context.canEvaluatePolicy_error(POLICY) }.is_ok()
}

/// Authenticate via Touch ID. Blocks until the user accepts, rejects, or
/// the system cancels the prompt.
///
/// `reason` is the user-visible string shown in the Touch ID dialog.
/// Returns `Ok(())` on success or an appropriate `ErrorCode` on failure.
pub fn authenticate(reason: &str) -> Result<()> {
    let context = unsafe { LAContext::new() };

    unsafe { context.canEvaluatePolicy_error(POLICY) }
        .map_err(|e| decode_la_error(&e))?;

    let reason = NSString::from_str(reason);
    let (tx, rx) = mpsc::channel::<std::result::Result<(), ErrorCode>>();

    let block = RcBlock::new(move |success: Bool, error: *mut NSError| {
        if success.as_bool() {
            tx.send(Ok(())).ok();
        } else if !error.is_null() {
            // SAFETY: non-null pointer provided by the OS callback
            let err = unsafe { &*error };
            tx.send(Err(decode_la_error(err))).ok();
        } else {
            tx.send(Err(ErrorCode::PlatformFailure(
                Box::new(BiometricError::unknown(0)),
            )))
            .ok();
        }
    });

    unsafe {
        context.evaluatePolicy_localizedReason_reply(POLICY, &reason, &block);
    }

    rx.recv()
        .map_err(|_| ErrorCode::PlatformFailure(Box::new(ChannelError)))?
}

/// LAError codes from Apple documentation.
const LA_ERROR_AUTHENTICATION_FAILED: isize = -1;
const LA_ERROR_USER_CANCEL: isize = -2;
const LA_ERROR_USER_FALLBACK: isize = -3;
const LA_ERROR_SYSTEM_CANCEL: isize = -4;
const LA_ERROR_PASSCODE_NOT_SET: isize = -5;
const LA_ERROR_BIOMETRY_NOT_AVAILABLE: isize = -6;
const LA_ERROR_BIOMETRY_NOT_ENROLLED: isize = -7;
const LA_ERROR_BIOMETRY_LOCKOUT: isize = -8;

fn decode_la_error(err: &NSError) -> ErrorCode {
    let code = err.code();
    match code {
        LA_ERROR_BIOMETRY_NOT_AVAILABLE
        | LA_ERROR_BIOMETRY_NOT_ENROLLED
        | LA_ERROR_PASSCODE_NOT_SET => {
            ErrorCode::NoStorageAccess(Box::new(BiometricError::not_available(code)))
        }
        LA_ERROR_AUTHENTICATION_FAILED | LA_ERROR_BIOMETRY_LOCKOUT => {
            ErrorCode::NoStorageAccess(Box::new(BiometricError::auth_failed(code)))
        }
        LA_ERROR_USER_CANCEL | LA_ERROR_SYSTEM_CANCEL | LA_ERROR_USER_FALLBACK => {
            ErrorCode::NoStorageAccess(Box::new(BiometricError::cancelled(code)))
        }
        _ => ErrorCode::PlatformFailure(Box::new(BiometricError::unknown(code))),
    }
}

#[derive(Debug)]
struct BiometricError {
    message: String,
}

impl BiometricError {
    fn not_available(code: isize) -> Self {
        Self {
            message: format!("Touch ID not available (LAError code={code})"),
        }
    }
    fn auth_failed(code: isize) -> Self {
        Self {
            message: format!("Touch ID authentication failed (LAError code={code})"),
        }
    }
    fn cancelled(code: isize) -> Self {
        Self {
            message: format!("Touch ID authentication cancelled (LAError code={code})"),
        }
    }
    fn unknown(code: isize) -> Self {
        Self {
            message: format!("Touch ID unexpected error (LAError code={code})"),
        }
    }
}

impl std::fmt::Display for BiometricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for BiometricError {}

#[derive(Debug)]
struct ChannelError;

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Touch ID callback channel disconnected unexpectedly")
    }
}

impl std::error::Error for ChannelError {}
