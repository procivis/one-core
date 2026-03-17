use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustListRoleEnum {
    PidProvider,
    WalletProvider,
    WrpAcProvider,
    PubEeaProvider,
    QeaaProvider,
    QesrcProvider,
    WrpRcProvider,
    NationalRegistryRegistrar,
    Issuer,
    Verifier,
}
