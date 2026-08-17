use serde_json::{Map, Value};
use shared_types::ProofId;

use crate::error::ContextWithErrorCode;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::verification_protocol::openid4vp::mapper::format_authorization_request_client_id_scheme_did;
use crate::service::oid4vp_final1_0::error::OID4VPFinal1_0ServiceError;
use crate::service::oid4vp_final1_0_swiyu::OID4VPFinal1_0SwiyuService;

impl OID4VPFinal1_0SwiyuService {
    pub async fn get_client_request(
        &self,
        id: ProofId,
    ) -> Result<String, OID4VPFinal1_0ServiceError> {
        let request = self.inner.get_client_request(id).await?;
        let proof = self
            .proof_repository
            .get_proof(&id, None)
            .await
            .error_while("getting proof")?;

        let mut decomposed: DecomposedJwt<serde_json::Value> =
            Jwt::decompose_token(&request).error_while("decomposing token")?;
        let payload = decomposed.payload.custom.as_object_mut().ok_or_else(|| {
            OID4VPFinal1_0ServiceError::MappingError("expected payload to be an object".to_string())
        })?;
        payload.insert(
            "client_id_scheme".to_string(),
            Value::String("did".to_string()),
        );
        payload.insert(
            "response_mode".to_string(),
            Value::String("direct_post".to_string()),
        );
        remove_required_flag_from_claims(payload);

        let adjusted_request = format_authorization_request_client_id_scheme_did(
            &proof,
            &self.key_algorithm_provider,
            &*self.key_provider,
            payload,
        )
        .await
        .error_while("formatting authorization request")?;
        Ok(adjusted_request)
    }
}
fn remove_required_flag_from_claims(payload: &mut Map<String, Value>) {
    let Some(dcql_query) = payload.get_mut("dcql_query") else {
        return;
    };
    let Some(credentials) = dcql_query.get_mut("credentials") else {
        return;
    };
    let Some(credentials) = credentials.as_array_mut() else {
        return;
    };
    for credential in credentials {
        let Some(credential) = credential.as_object_mut() else {
            continue;
        };
        let Some(claims) = credential.get_mut("claims") else {
            continue;
        };
        let Some(claims) = claims.as_array_mut() else {
            continue;
        };
        for claim in claims {
            let Some(claim_obj) = claim.as_object_mut() else {
                continue;
            };
            claim_obj.remove("required");
        }
    }
}
