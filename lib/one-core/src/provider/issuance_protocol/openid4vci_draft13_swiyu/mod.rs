use std::sync::Arc;

use serde_json::Value;
use shared_types::CredentialId;
use url::Url;

use crate::config::core_config::CoreConfig;
use crate::config::core_config::DidType::WebVh;
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::dto::IssuanceProtocolCapabilities;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::openid4vci_draft13::OpenID4VCI13;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    InvitationResponseDTO, OpenID4VCIParams, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::issuance_protocol::{HandleInvitationOperationsAccess, IssuanceProtocol};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::storage_proxy::StorageAccess;

pub(crate) const OID4VCI_DRAFT13_SWIYU_VERSION: &str = "draft-13-swiyu";

pub(crate) struct OpenID4VCI13Swiyu {
    inner: OpenID4VCI13,
}

impl OpenID4VCI13Swiyu {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn HttpClient>,
        credential_repository: Arc<dyn CredentialRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCIParams,
    ) -> Self {
        Self {
            inner: OpenID4VCI13::new_with_custom_version(
                client,
                credential_repository,
                validity_credential_repository,
                revocation_list_repository,
                history_repository,
                formatter_provider,
                revocation_provider,
                did_method_provider,
                key_algorithm_provider,
                key_provider,
                base_url,
                config,
                params,
                OID4VCI_DRAFT13_SWIYU_VERSION,
            ),
        }
    }
}

#[async_trait::async_trait]
impl IssuanceProtocol for OpenID4VCI13Swiyu {
    fn holder_can_handle(&self, url: &Url) -> bool {
        self.inner.holder_can_handle(url)
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, IssuanceProtocolError> {
        self.inner
            .holder_handle_invitation(
                url,
                organisation,
                storage_access,
                handle_invitation_operations,
            )
            .await
    }

    async fn holder_accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, IssuanceProtocolError> {
        self.inner
            .holder_accept_credential(
                credential,
                holder_did,
                key,
                jwk_key_id,
                format,
                storage_access,
                tx_code,
            )
            .await
    }

    async fn holder_reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), IssuanceProtocolError> {
        self.inner.holder_reject_credential(credential).await
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse<Value>, IssuanceProtocolError> {
        let mut credential = credential.clone();

        // SWIYU only supports credential offer by value and does not create a preview from the offer.
        // So we drop all the claims from the offer to not run into problems with large claim values
        // e.g. for images.
        if let Some(claims) = credential.claims.as_mut() {
            *claims = vec![]
        }

        self.inner.issuer_share_credential(&credential).await
    }

    async fn issuer_issue_credential(
        &self,
        credential_id: &CredentialId,
        holder_did: Did,
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        self.inner
            .issuer_issue_credential(credential_id, holder_did, holder_identifier, holder_key_id)
            .await
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        IssuanceProtocolCapabilities {
            did_methods: vec![WebVh],
        }
    }
}
