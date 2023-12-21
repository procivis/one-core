use crate::{
    model::{
        credential::{
            Credential, CredentialId, CredentialRelations, GetCredentialList, GetCredentialQuery,
            UpdateCredentialRequest,
        },
        interaction::InteractionId,
    },
    repository::error::DataLayerError,
};
use mockall::*;
use shared_types::DidId;

#[derive(Default)]
struct CredentialRepository;

mock! {
    pub CredentialRepository {
        pub fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError>;

        pub fn delete_credential(&self, id: &CredentialId) -> Result<(), DataLayerError>;

        pub fn get_credential(
            &self,
            id: &CredentialId,
            relations: &CredentialRelations,
        ) -> Result<Credential, DataLayerError>;

        pub fn get_credentials_by_interaction_id(
            &self,
            interaction_id: &InteractionId,
            relations: &CredentialRelations,
        ) -> Result<Vec<Credential>, DataLayerError>;

        pub fn get_credentials_by_issuer_did_id(
            &self,
            issuer_did_id: &DidId,
            relations: &CredentialRelations
        ) -> Result<Vec<Credential>, DataLayerError>;

        pub fn get_credentials_by_claim_names(
            &self,
            claim_names: Vec<String>,
            relations: &CredentialRelations,
        ) -> Result<Vec<Credential>, DataLayerError>;

        pub fn get_credential_list(
            &self,
            query_params: GetCredentialQuery,
        ) -> Result<GetCredentialList, DataLayerError>;

        pub fn update_credential(
            &self,
            credential: UpdateCredentialRequest,
        ) -> Result<(), DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::credential_repository::CredentialRepository for MockCredentialRepository {
    async fn create_credential(&self, request: Credential) -> Result<CredentialId, DataLayerError> {
        self.create_credential(request)
    }

    async fn delete_credential(&self, id: &CredentialId) -> Result<(), DataLayerError> {
        self.delete_credential(id)
    }

    async fn get_credential(
        &self,
        id: &CredentialId,
        relations: &CredentialRelations,
    ) -> Result<Credential, DataLayerError> {
        self.get_credential(id, relations)
    }

    async fn get_credentials_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        self.get_credentials_by_interaction_id(interaction_id, relations)
    }

    async fn get_credentials_by_issuer_did_id(
        &self,
        issuer_did_id: &DidId,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        self.get_credentials_by_issuer_did_id(issuer_did_id, relations)
    }

    async fn get_credential_list(
        &self,
        query_params: GetCredentialQuery,
    ) -> Result<GetCredentialList, DataLayerError> {
        self.get_credential_list(query_params)
    }

    async fn update_credential(
        &self,
        credential: UpdateCredentialRequest,
    ) -> Result<(), DataLayerError> {
        self.update_credential(credential)
    }

    async fn get_credentials_by_claim_names(
        &self,
        claim_names: Vec<String>,
        relations: &CredentialRelations,
    ) -> Result<Vec<Credential>, DataLayerError> {
        self.get_credentials_by_claim_names(claim_names, relations)
    }
}
