use std::sync::Arc;

use secrecy::SecretSlice;
use serde::Deserialize;
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
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::IssuanceProtocol;
use crate::provider::issuance_protocol::dto::{ContinueIssuanceDTO, IssuanceProtocolCapabilities};
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::model::{
    ContinueIssuanceResponseDTO, InvitationResponseEnum, OpenID4VCRedirectUriParams, ShareResponse,
    SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::issuance_protocol::openid4vci_draft13::OpenID4VCI13;
use crate::provider::issuance_protocol::openid4vci_draft13::handle_invitation_operations::HandleInvitationOperations;
use crate::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCIDraft13Params;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::storage_proxy::StorageAccess;
use crate::util::params::deserialize_encryption_key;

pub(crate) const OID4VCI_DRAFT13_SWIYU_VERSION: &str = "draft-13-swiyu";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCISwiyuParams {
    pub pre_authorized_code_expires_in: u64,
    pub token_expires_in: u64,
    pub refresh_expires_in: u64,
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub encryption: SecretSlice<u8>,
    pub redirect_uri: OpenID4VCRedirectUriParams,
}

impl From<OpenID4VCISwiyuParams> for OpenID4VCIDraft13Params {
    fn from(value: OpenID4VCISwiyuParams) -> Self {
        Self {
            pre_authorized_code_expires_in: value.pre_authorized_code_expires_in,
            token_expires_in: value.token_expires_in,
            refresh_expires_in: value.refresh_expires_in,
            credential_offer_by_value: true,
            encryption: value.encryption,
            url_scheme: "swiyu".to_string(),
            redirect_uri: value.redirect_uri,
            rejection_identifier: None,
            enable_credential_preview: false,
        }
    }
}

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
        certificate_validator: Arc<dyn CertificateValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCISwiyuParams,
        handle_invitation_operations: Arc<dyn HandleInvitationOperations>,
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
                certificate_validator,
                blob_storage_provider,
                base_url,
                config,
                params.into(),
                OID4VCI_DRAFT13_SWIYU_VERSION,
                handle_invitation_operations,
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
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum, IssuanceProtocolError> {
        self.inner
            .holder_handle_invitation(url, organisation, storage_access, redirect_uri)
            .await
    }

    async fn holder_accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, IssuanceProtocolError> {
        self.inner
            .holder_accept_credential(
                credential,
                holder_did,
                key,
                jwk_key_id,
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
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        self.inner
            .issuer_issue_credential(credential_id, holder_identifier, holder_key_id)
            .await
    }

    async fn holder_continue_issuance(
        &self,
        continue_issuance_dto: ContinueIssuanceDTO,
        organisation: Organisation,
        storage_access: &StorageAccess,
    ) -> Result<ContinueIssuanceResponseDTO, IssuanceProtocolError> {
        self.inner
            .holder_continue_issuance(continue_issuance_dto, organisation, storage_access)
            .await
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        IssuanceProtocolCapabilities {
            features: vec![],
            did_methods: vec![WebVh],
        }
    }
}
