use one_dto_mapper::Into;
use serde::{Deserialize, Serialize};
use shared_types::{TrustListSubscriberId, TrustListSubscriptionId};

use crate::model::trust_list_role::TrustListRoleEnum;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RemoteTrustCollection {
    pub name: String,
    pub trust_lists: Vec<RemoteTrustList>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RemoteTrustList {
    pub name: String,
    pub id: TrustListSubscriptionId,
    pub role: RemoteTrustListRole,
    pub reference: String,
    pub r#type: TrustListSubscriberId,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, Serialize, Deserialize)]
#[into(TrustListRoleEnum)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum RemoteTrustListRole {
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
