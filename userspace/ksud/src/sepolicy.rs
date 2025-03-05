use anyhow::{bail, Result};
use derive_new::new;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while1, take_while_m_n},
    character::{
        complete::{space0, space1},
        is_alphanumeric,
    },
    combinator::map,
    sequence::Tuple,
    IResult, Parser,
};
use std::{ffi, path::Path, vec};

pub fn live_patch(policy: &str) -> Result<()> {
    Ok(())
}

pub fn apply_file<P: AsRef<Path>>(path: P) -> Result<()> {
    Ok(())
}

pub fn check_rule(policy: &str) -> Result<()> {
    Ok(())
}
