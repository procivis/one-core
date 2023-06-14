use shadow_rs::SdResult;
use std::fs::File;
use std::io::Write;

fn main() -> SdResult<()> {
    shadow_rs::new_hook(hook)
}

fn hook(mut file: &File) -> SdResult<()> {
    // Here we need to extract and put variables to the file one by one.
    let ci_pipeline_id = envmnt::get_or("CI_PIPELINE_ID", "NOT PROVIDED");
    let hook_const: &str = &format!("pub const CI_PIPELINE_ID: &str = \"{ci_pipeline_id}\";");
    writeln!(file, "{hook_const}")?;
    Ok(())
}
