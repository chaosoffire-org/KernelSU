use anyhow::{bail, Result};
use std::path::Path;

const MARKER: &str = "/data/adb/ksu/no-flash";

/// True when KernelSU is late-loaded (jailbreak mode) or the device profile
/// explicitly armed the lockdown marker.
pub fn is_active() -> bool {
    if Path::new(MARKER).exists() {
        return true;
    }

    #[cfg(target_os = "android")]
    {
        crate::ksucalls::is_late_load()
    }
    #[cfg(not(target_os = "android"))]
    {
        false
    }
}

fn bail_if_active(action: &str) -> Result<()> {
    if is_active() {
        bail!(
            "no-flash lockdown: refusing to {action}. KernelSU here is late-loaded on a locked \
             bootloader; writing boot/init_boot/vbmeta breaks AVB and can brick the device. \
             Marker: {MARKER}"
        );
    }
    Ok(())
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn deny_flash() -> Result<()> {
    bail_if_active("flash a partition")
}

pub fn deny_image_write(target: &Path) -> Result<()> {
    let Some(text) = target.to_str() else {
        return Ok(());
    };
    if text.starts_with("/dev/") {
        bail_if_active(&format!("write an image to {text}"))?;
    }
    Ok(())
}
