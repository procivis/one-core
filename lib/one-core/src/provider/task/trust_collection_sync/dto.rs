use serde::Deserialize;
use shared_types::HolderWalletUnitId;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum Params {
    HolderWalletUnitId(HolderWalletUnitId),
    VerifierInstanceId, // TODO ONE-9261: Implement handling verifier instance id
}
