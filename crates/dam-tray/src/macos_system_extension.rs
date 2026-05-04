use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    process::Command,
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationOutcome {
    Ready(String),
    NeedsApproval(String),
}

const RETURN_READY: i32 = 0;
const RETURN_NEEDS_APPROVAL: i32 = 1;
const RETURN_FAILED: i32 = 2;
const RETURN_INVALID_ARGUMENT: i32 = 3;
const RETURN_TIMED_OUT: i32 = 4;
const APPROVAL_MESSAGE: &str =
    "approve DAM Network Protection in System Settings, then click Connect/Resume again";

unsafe extern "C" {
    fn dam_tray_activate_system_extension(
        bundle_identifier: *const c_char,
        timeout_seconds: f64,
        message_buffer: *mut c_char,
        message_buffer_len: usize,
    ) -> i32;
}

pub fn activate(bundle_identifier: &str, timeout: Duration) -> Result<ActivationOutcome, String> {
    if let Some(outcome) = installed_extension_outcome(bundle_identifier) {
        return Ok(outcome);
    }

    let bundle_identifier = CString::new(bundle_identifier)
        .map_err(|_| "System Extension bundle identifier contains a null byte".to_string())?;
    let mut message = vec![0 as c_char; 2048];
    let status = unsafe {
        dam_tray_activate_system_extension(
            bundle_identifier.as_ptr(),
            timeout.as_secs_f64(),
            message.as_mut_ptr(),
            message.len(),
        )
    };
    let message = unsafe { CStr::from_ptr(message.as_ptr()) }
        .to_string_lossy()
        .trim()
        .to_string();

    match status {
        RETURN_READY => Ok(ActivationOutcome::Ready(non_empty_message(
            message,
            "DAM Network Protection is active",
        ))),
        RETURN_NEEDS_APPROVAL => Ok(ActivationOutcome::NeedsApproval(non_empty_message(
            message,
            APPROVAL_MESSAGE,
        ))),
        RETURN_INVALID_ARGUMENT => Err(non_empty_message(
            message,
            "invalid System Extension activation request",
        )),
        RETURN_TIMED_OUT => Err(non_empty_message(
            message,
            "macOS did not register the DAM Network Protection activation request",
        )),
        RETURN_FAILED => {
            installed_extension_outcome(bundle_identifier.to_str().unwrap_or_default())
                .map(Ok)
                .unwrap_or_else(|| {
                    Err(non_empty_message(
                        message,
                        "DAM Network Protection activation failed",
                    ))
                })
        }
        _ => Err(non_empty_message(
            message,
            "DAM Network Protection activation returned an unknown result",
        )),
    }
}

fn installed_extension_outcome(bundle_identifier: &str) -> Option<ActivationOutcome> {
    let output = Command::new("/usr/bin/systemextensionsctl")
        .arg("list")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_systemextensionsctl_outcome(&stdout, bundle_identifier)
}

fn parse_systemextensionsctl_outcome(
    output: &str,
    bundle_identifier: &str,
) -> Option<ActivationOutcome> {
    let line = output.lines().find(|line| {
        line.split_whitespace()
            .any(|part| part == bundle_identifier)
    })?;
    if line.contains("[activated enabled]") {
        return Some(ActivationOutcome::Ready(
            "DAM Network Protection is active".to_string(),
        ));
    }
    if line.contains("[activated waiting for user]") {
        return Some(ActivationOutcome::NeedsApproval(
            APPROVAL_MESSAGE.to_string(),
        ));
    }
    None
}

fn non_empty_message(message: String, fallback: &str) -> String {
    if message.is_empty() {
        fallback.to_string()
    } else {
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_empty_message_uses_fallback_for_blank_messages() {
        assert_eq!(non_empty_message(String::new(), "fallback"), "fallback");
        assert_eq!(non_empty_message("ready".to_string(), "fallback"), "ready");
    }

    #[test]
    fn parses_enabled_system_extension_as_ready() {
        let output = concat!(
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n",
            "*\t*\t2T6856RWGV\tcom.rpblc.dam.network-extension (1.0/1)\tDAM Network Protection\t[activated enabled]\n",
        );

        assert_eq!(
            parse_systemextensionsctl_outcome(output, "com.rpblc.dam.network-extension"),
            Some(ActivationOutcome::Ready(
                "DAM Network Protection is active".to_string()
            ))
        );
    }

    #[test]
    fn parses_waiting_for_user_system_extension_as_needs_approval() {
        let output = concat!(
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n",
            "\t*\t2T6856RWGV\tcom.rpblc.dam.network-extension (1.0/1)\tDAM Network Protection\t[activated waiting for user]\n",
        );

        assert_eq!(
            parse_systemextensionsctl_outcome(output, "com.rpblc.dam.network-extension"),
            Some(ActivationOutcome::NeedsApproval(
                APPROVAL_MESSAGE.to_string()
            ))
        );
    }

    #[test]
    fn ignores_other_system_extension_states() {
        let output = concat!(
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n",
            "\t\t2T6856RWGV\tcom.rpblc.dam.network-extension (1.0/1)\tDAM Network Protection\t[terminated waiting to uninstall on reboot]\n",
        );

        assert_eq!(
            parse_systemextensionsctl_outcome(output, "com.rpblc.dam.network-extension"),
            None
        );
    }
}
