use anyhow::Result;
use std::path::Path;

pub fn live_patch(policy: &str) -> Result<()> {
    Ok(())
}

pub fn apply_file<P: AsRef<Path>>(_path: P) -> Result<()> {
    Ok(())
}

pub fn check_rule(_policy: &str) -> Result<()> {
    Ok(())
}
