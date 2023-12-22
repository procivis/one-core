use std::env;
use std::fs::File;
use std::io::Write;

use shadow_rs::SdResult;

fn main() -> SdResult<()> {
    shadow_rs::new_hook(hook)
}

fn get_app_version_string() -> String {
    let value = env::var("APP_VERSION").unwrap_or_default();
    if value.is_empty() {
        "None".to_string()
    } else {
        format!(r#"Some("{value}")"#)
    }
}

fn hook(mut file: &File) -> SdResult<()> {
    // Here we need to extract and put variables to the file one by one.
    let app_version = get_app_version_string();
    let ci_pipeline_id = env::var("CI_PIPELINE_ID").unwrap_or("NOT PROVIDED".to_owned());
    let hook_const: &str = &format!(
        r#"#[allow(dead_code)] pub const APP_VERSION: Option<&str> = {app_version};
           #[allow(dead_code)] pub const CI_PIPELINE_ID: &str = "{ci_pipeline_id}";"#
    );
    writeln!(file, "{hook_const}")?;
    Ok(())
}
