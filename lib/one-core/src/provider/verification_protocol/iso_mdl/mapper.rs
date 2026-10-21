use serde::Serialize;
use shared_types::ProofId;
use standardized_types::openid4vp::dcql::{
    ClaimPath, ClaimQuery, CredentialFormat, CredentialQuery, DcqlQuery, MsoMdocMeta, PathSegment,
};
use uuid::Uuid;

use super::common::DeviceRequest;
use crate::model::interaction::{Interaction, InteractionEcosystems, InteractionType};
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::serialize_interaction_data;

pub(super) fn device_request_to_dcql_query(device_request: &DeviceRequest) -> DcqlQuery {
    let mut credentials = Vec::with_capacity(device_request.doc_requests.len());
    for doc_request in &device_request.doc_requests {
        let request = doc_request.items_request.inner();
        let mut claims = vec![];
        for (namespace, elements) in &request.name_spaces {
            for (element, intent_to_retain) in elements {
                claims.push(ClaimQuery {
                    id: None,
                    path: ClaimPath {
                        segments: vec![
                            PathSegment::PropertyName(namespace.to_owned()),
                            PathSegment::PropertyName(element.to_owned()),
                        ],
                    },
                    values: None,
                    required: Some(false),
                    intent_to_retain: Some(*intent_to_retain),
                });
            }
        }

        let doctype_value = request.doc_type.to_owned();
        credentials.push(CredentialQuery {
            id: doctype_value.to_owned().into(),
            format: CredentialFormat::MsoMdoc(MsoMdocMeta { doctype_value }),
            claims: Some(claims),
            claim_sets: None,
            trusted_authorities: None,
            multiple: false,
            require_cryptographic_holder_binding: true,
        });
    }

    DcqlQuery {
        credentials,
        credential_sets: None,
    }
}

pub(super) fn interaction_with_data<T: Serialize>(
    data: &T,
    organisation: Organisation,
) -> Result<Interaction, VerificationProtocolError> {
    let now = crate::clock::now_utc();

    Ok(Interaction {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        data: Some(serialize_interaction_data(data)?),
        organisation: organisation.into(),
        interaction_type: InteractionType::Verification,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: InteractionEcosystems::default(),
        dpop_key: None,
    })
}

pub(super) fn holder_proof_for_dc_api(
    proof_id: ProofId,
    protocol: &str,
    interaction: Interaction,
    transport: String,
) -> Proof {
    let now = crate::clock::now_utc();
    Proof {
        id: proof_id,
        created_date: now,
        last_modified: now,
        protocol: protocol.to_owned(),
        redirect_uri: None,
        transport,
        state: ProofStateEnum::Requested,
        role: ProofRole::Holder,
        requested_date: Some(now),
        completed_date: None,
        profile: None,
        schema: None,
        claims: Default::default(),
        verifier_identifier: None,
        interaction: Some(interaction.into()),
        verifier_key: None,
        verifier_certificate: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
        ecosystem: None,
    }
}
