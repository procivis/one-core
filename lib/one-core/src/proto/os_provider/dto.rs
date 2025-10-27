use one_dto_mapper::Into;
use strum::{Display, EnumString};

use crate::model::wallet_unit::WalletUnitOs;

#[derive(Debug, Display, EnumString, Into, Clone, Copy)]
#[into(WalletUnitOs)]
#[strum(ascii_case_insensitive, serialize_all = "UPPERCASE")]
pub enum OSName {
    Android,
    Ios,
    Web,
}
