use anyhow::Result;

pub fn set_sepolicy(_pkg: String, _policy: String) -> Result<()> {
    Ok(())
}

pub fn get_sepolicy(_pkg: String) -> Result<()> {
    Ok(())
}

// ksud doesn't guarteen the correctness of template, it just save
pub fn set_template(_id: String, _template: String) -> Result<()> {
    Ok(())
}

pub fn get_template(_id: String) -> Result<()> {
    Ok(())
}

pub fn delete_template(_id: String) -> Result<()> {
    Ok(())
}

pub fn list_templates() -> Result<()> {
    Ok(())
}

pub fn apply_sepolies() -> Result<()> {
    Ok(())
}
