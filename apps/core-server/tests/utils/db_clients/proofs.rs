use std::sync::Arc;

use one_core::model::claim::Claim;
use one_core::model::identifier::{Identifier, IdentifierData};
use one_core::model::interaction::Interaction;
use one_core::model::key::Key;
use one_core::model::proof::{Proof, ProofRelations, ProofRole, ProofStateEnum};
use one_core::model::proof_schema::ProofSchema;
use one_core::repository::proof_repository::ProofRepository;
use shared_types::{BlobId, ProofId};
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct ProofsDB {
    repository: Arc<dyn ProofRepository>,
}

impl ProofsDB {
    pub fn new(repository: Arc<dyn ProofRepository>) -> Self {
        Self { repository }
    }

    #[expect(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        id: Option<ProofId>,
        verifier_identifier: &Identifier,
        proof_schema: Option<&ProofSchema>,
        state: ProofStateEnum,
        exchange: &str,
        interaction: Option<&Interaction>,
        verifier_key: Key,
        proof_blob_id: Option<BlobId>,
        engagement: Option<String>,
    ) -> Proof {
        self.create_with_profile(
            id,
            verifier_identifier,
            proof_schema,
            state,
            exchange,
            interaction,
            verifier_key,
            None,
            proof_blob_id,
            engagement,
        )
        .await
    }

    #[expect(clippy::too_many_arguments)]
    pub async fn create_with_profile(
        &self,
        id: Option<ProofId>,
        verifier_identifier: &Identifier,
        proof_schema: Option<&ProofSchema>,
        state: ProofStateEnum,
        exchange: &str,
        interaction: Option<&Interaction>,
        verifier_key: Key,
        profile: Option<String>,
        proof_blob_id: Option<BlobId>,
        engagement: Option<String>,
    ) -> Proof {
        let requested_date = match state {
            ProofStateEnum::Pending
            | ProofStateEnum::Requested
            | ProofStateEnum::Accepted
            | ProofStateEnum::Rejected
            | ProofStateEnum::Error => Some(get_dummy_date()),
            _ => None,
        };

        let completed_date = match state {
            ProofStateEnum::Accepted | ProofStateEnum::Rejected => Some(get_dummy_date()),
            _ => None,
        };

        let role = if proof_schema.is_some() {
            ProofRole::Verifier
        } else {
            ProofRole::Holder
        };

        let proof = Proof {
            ecosystem: None,
            id: id.unwrap_or_else(|| Uuid::new_v4().into()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            protocol: exchange.to_owned(),
            transport: "HTTP".to_string(),
            redirect_uri: None,
            state,
            role,
            requested_date,
            completed_date,
            claims: None,
            schema: proof_schema.cloned(),
            verifier_identifier: Some(verifier_identifier.to_owned()),
            verifier_key: Some(verifier_key),
            verifier_certificate: match &verifier_identifier.data {
                IdentifierData::Certificate(certs)
                | IdentifierData::CertificateAuthority(certs) => {
                    certs.as_ref().await.unwrap().first().cloned()
                }
                _ => None,
            },
            interaction: interaction.cloned(),
            profile,
            proof_blob_id,
            engagement,
            webhook_url: None,
            subscriber_information: None,
        };

        let proof_id = self.repository.create_proof(proof.clone()).await.unwrap();

        self.get(&proof_id).await
    }

    pub async fn set_proof_claims(&self, id: &ProofId, claims: Vec<Claim>) {
        self.repository.set_proof_claims(id, claims).await.unwrap()
    }

    pub async fn get(&self, proof_id: &ProofId) -> Proof {
        self.repository
            .get_proof(
                proof_id,
                &ProofRelations {
                    claims: Some(Default::default()),
                    schema: Some(Default::default()),
                    verifier_identifier: Some(Default::default()),
                    interaction: Some(Default::default()),
                    verifier_key: Some(Default::default()),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap()
    }
}
