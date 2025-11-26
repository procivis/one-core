use std::env;
use std::fs::File;
use std::io::Write;

use shadow_rs::{SdResult, ShadowBuilder};

fn main() -> SdResult<()> {
    ShadowBuilder::builder().hook(hook).build()?;
    Ok(())
}

fn hook(mut file: &File) -> SdResult<()> {
    // Here we need to extract and put variables to the file one by one.
    let ci_pipeline_id = env::var("CI_PIPELINE_ID").unwrap_or("NOT PROVIDED".to_owned());
    let hook_const: &str = &format!("pub const CI_PIPELINE_ID: &str = \"{ci_pipeline_id}\";");
    writeln!(file, "{hook_const}")?;
    Ok(())
}
