use shadow_rs::SdResult;
use std::fs::File;
use std::io::Write;

fn main() -> SdResult<()> {
    shadow_rs::new_hook(hook)
}

fn get_app_version_string() -> String {
    let value = envmnt::get_or("APP_VERSION", "");
    if value.is_empty() {
        "None".to_string()
    } else {
        format!(r#"Some("{value}")"#)
    }
}

fn hook(mut file: &File) -> SdResult<()> {
    // Here we need to extract and put variables to the file one by one.
    let app_version = get_app_version_string();
    let ci_pipeline_id = envmnt::get_or("CI_PIPELINE_ID", "NOT PROVIDED");
    let hook_const: &str = &format!(
        r#"#[allow(dead_code)] pub const APP_VERSION: Option<&str> = {app_version};
           #[allow(dead_code)] pub const CI_PIPELINE_ID: &str = "{ci_pipeline_id}";"#
    );
    writeln!(file, "{hook_const}")?;
    Ok(())
}
