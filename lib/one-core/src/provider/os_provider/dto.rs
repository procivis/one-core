use strum::{Display, EnumString};

#[derive(Debug, Display, EnumString)]
#[strum(ascii_case_insensitive, serialize_all = "UPPERCASE")]
pub enum OSName {
    Android,
    Ios,
    Web,
}
