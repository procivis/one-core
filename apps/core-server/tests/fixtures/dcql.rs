use dcql::DcqlQuery;
use one_core::model::identifier::Identifier;
use one_core::model::interaction::InteractionType;
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::proof::{Proof, ProofStateEnum};
use serde_json::json;

use crate::utils::context::TestContext;

pub(crate) async fn proof_for_dcql_query(
    context: &TestContext,
    org: &Organisation,
    identifier: &Identifier,
    key: Key,
    dcql_query: &DcqlQuery,
    protocol: &str,
) -> Proof {
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data_dcql(dcql_query),
            org,
            InteractionType::Verification,
        )
        .await;

    context
        .db
        .proofs
        .create(
            None,
            identifier,
            None,
            None,
            ProofStateEnum::Requested,
            protocol,
            Some(&interaction),
            key,
            None,
            None,
        )
        .await
}

fn interaction_data_dcql(dcql_query: &DcqlQuery) -> Vec<u8> {
    json!({
        "response_type": "vp_token",
        "state": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
        "nonce": "xKpt9wiB4apJ1MVTzQv1zdDty2dVWkl7",
        "client_id_scheme": "redirect_uri",
        "client_id": "http://0.0.0.0:3000/ssi/openid4vp/final-1.0/response",
        "response_mode": "direct_post",
        "response_uri": "http://0.0.0.0:3000/ssi/openid4vp/final-1.0/response",
        "dcql_query": dcql_query,
    })
    .to_string()
    .into_bytes()
}
