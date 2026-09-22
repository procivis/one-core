use std::sync::Arc;

use one_core::model::certificate::Certificate;
use one_core::model::claim::Claim;
use one_core::model::identifier::{Identifier, IdentifierData};
use one_core::model::interaction::Interaction;
use one_core::model::key::Key;
use one_core::model::proof::{Proof, ProofClaim, ProofRole, ProofStateEnum, UpdateProofRequest};
use one_core::model::proof_schema::ProofSchema;
use one_core::model::relation::Related;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::proof_repository::ProofRepository;
use one_dto_mapper::convert_inner;
use shared_types::{BlobId, EcosystemId, ProofId};
use sql_data_provider::test_utilities::get_dummy_date;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct TestingProofParams {
    pub id: Option<ProofId>,
    pub created_date: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub requested_date: Option<Option<OffsetDateTime>>,
    pub completed_date: Option<Option<OffsetDateTime>>,
    pub proof_schema: Option<ProofSchema>,
    pub ecosystem: Option<EcosystemId>,
    pub interaction: Option<Interaction>,
    pub role: Option<ProofRole>,
    pub claims: Option<Vec<ProofClaim>>,
    pub transport: Option<String>,
    pub redirect_uri: Option<String>,
    pub verifier_identifier: Option<Identifier>,
    pub verifier_key: Option<Key>,
    pub verifier_certificate: Option<Certificate>,
    pub profile: Option<String>,
    pub proof_blob_id: Option<BlobId>,
    pub engagement: Option<String>,
    pub webhook_url: Option<String>,
    pub subscriber_information: Option<String>,
}

pub struct ProofsDB {
    repository: Arc<dyn ProofRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
}

impl ProofsDB {
    pub fn new(
        repository: Arc<dyn ProofRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
    ) -> Self {
        Self {
            repository,
            credential_repository,
        }
    }

    pub async fn create(
        &self,
        state: ProofStateEnum,
        protocol: &str,
        params: TestingProofParams,
    ) -> Proof {
        let computed_requested_date = match state {
            ProofStateEnum::Pending
            | ProofStateEnum::Requested
            | ProofStateEnum::Accepted
            | ProofStateEnum::Rejected
            | ProofStateEnum::Error => Some(get_dummy_date()),
            _ => None,
        };

        let computed_completed_date = match state {
            ProofStateEnum::Accepted | ProofStateEnum::Rejected => Some(get_dummy_date()),
            _ => None,
        };

        let computed_role = if params.proof_schema.is_some() {
            ProofRole::Verifier
        } else {
            ProofRole::Holder
        };

        let computed_verifier_certificate = {
            let certs = params
                .verifier_identifier
                .as_ref()
                .and_then(|verifier_identifier| match &verifier_identifier.data {
                    IdentifierData::Certificate(certs)
                    | IdentifierData::CertificateAuthority(certs) => Some(certs),
                    _ => None,
                });

            match certs {
                None => None,
                Some(certs) => certs.as_ref().await.unwrap().first().cloned(),
            }
        };

        let proof = Proof {
            ecosystem: params.ecosystem,
            id: params.id.unwrap_or_else(|| Uuid::new_v4().into()),
            created_date: params.created_date.unwrap_or(get_dummy_date()),
            last_modified: params.last_modified.unwrap_or(get_dummy_date()),
            protocol: protocol.to_owned(),
            transport: params.transport.unwrap_or("HTTP".to_string()),
            redirect_uri: params.redirect_uri,
            state,
            role: params.role.unwrap_or(computed_role),
            requested_date: params.requested_date.unwrap_or(computed_requested_date),
            completed_date: params.completed_date.unwrap_or(computed_completed_date),
            claims: params.claims.unwrap_or_default().into(),
            schema: convert_inner(params.proof_schema),
            verifier_identifier: convert_inner(params.verifier_identifier),
            verifier_key: convert_inner(params.verifier_key),
            verifier_certificate: convert_inner(
                params
                    .verifier_certificate
                    .or(computed_verifier_certificate),
            ),
            interaction: convert_inner(params.interaction),
            profile: params.profile,
            proof_blob_id: params.proof_blob_id,
            engagement: params.engagement,
            webhook_url: params.webhook_url,
            subscriber_information: params.subscriber_information,
        };

        let proof_id = self.repository.create_proof(proof.clone()).await.unwrap();

        self.get(&proof_id).await
    }

    pub async fn set_proof_claims(&self, id: &ProofId, claims: Vec<Claim>) {
        let claims = claims
            .into_iter()
            .map(|claim| ProofClaim {
                credential: Related::new(claim.credential_id, self.credential_repository.clone()),
                claim,
            })
            .collect();
        self.repository.set_proof_claims(id, claims).await.unwrap()
    }

    pub async fn update(&self, id: &ProofId, request: UpdateProofRequest) {
        self.repository
            .update_proof(id, request, None)
            .await
            .unwrap()
    }

    pub async fn get(&self, proof_id: &ProofId) -> Proof {
        self.repository.get_proof(proof_id, None).await.unwrap()
    }
}
