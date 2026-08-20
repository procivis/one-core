use one_core::model::identifier::Identifier;
use one_core::model::interaction::InteractionType;
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::proof::{Proof, ProofStateEnum};
use one_core::provider::credential_formatter::model::IdentifierDetails;
use serde_json::json;
use standardized_types::openid4vp::dcql::DcqlQuery;

use crate::utils::context::TestContext;
use crate::utils::db_clients::interactions::TestingInteractionParams;

pub(crate) async fn proof_for_dcql_query(
    context: &TestContext,
    org: &Organisation,
    identifier: &Identifier,
    key: Key,
    dcql_query: &DcqlQuery,
    protocol: &str,
    verifier_details: Option<IdentifierDetails>,
) -> Proof {
    let interaction = context
        .db
        .interactions
        .create(
            org,
            InteractionType::Verification,
            TestingInteractionParams {
                data: Some(interaction_data_dcql(dcql_query, verifier_details)),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proofs
        .create(
            None,
            identifier,
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

fn interaction_data_dcql(
    dcql_query: &DcqlQuery,
    verifier_details: Option<IdentifierDetails>,
) -> Vec<u8> {
    json!({
        "response_type": "vp_token",
        "state": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
        "nonce": "xKpt9wiB4apJ1MVTzQv1zdDty2dVWkl7",
        "client_id_scheme": "redirect_uri",
        "client_id": "http://0.0.0.0:3000/ssi/openid4vp/final-1.0/response",
        "response_mode": "direct_post",
        "response_uri": "http://0.0.0.0:3000/ssi/openid4vp/final-1.0/response",
        "dcql_query": dcql_query,
        "verifier_details": verifier_details
    })
    .to_string()
    .into_bytes()
}
