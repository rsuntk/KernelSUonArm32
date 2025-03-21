mod apk_sign;
mod assets;
mod boot_patch;
mod cli;
mod debug;
mod defs;
mod init_event;
mod ksucalls;
#[cfg(target_os = "android")]
mod magic_mount;
mod module;
mod dummy_profile;
mod sepolicy;
mod restorecon;
mod su;
mod utils;

fn main() -> anyhow::Result<()> {
    cli::run()
}
