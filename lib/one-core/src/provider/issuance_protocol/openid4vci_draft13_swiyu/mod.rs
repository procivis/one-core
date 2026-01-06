use std::sync::Arc;

use secrecy::SecretSlice;
use serde::Deserialize;
use shared_types::{CredentialId, HolderWalletUnitId};
use time::Duration;
use url::Url;

use crate::config::core_config::DidType::WebVh;
use crate::config::core_config::{CoreConfig, IssuanceProtocolType};
use crate::mapper::params::{deserialize_duration_seconds, deserialize_encryption_key};
use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::dto::{ContinueIssuanceDTO, IssuanceProtocolCapabilities};
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::model::{
    ContinueIssuanceResponseDTO, InvitationResponseEnum, OpenID4VCRedirectUriParams, ShareResponse,
    SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::issuance_protocol::openid4vci_draft13::OpenID4VCI13;
use crate::provider::issuance_protocol::openid4vci_draft13::handle_invitation_operations::HandleInvitationOperations;
use crate::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCIDraft13Params;
use crate::provider::issuance_protocol::{HolderBindingInput, IssuanceProtocol};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::storage_proxy::StorageAccess;

pub(crate) const OID4VCI_DRAFT13_SWIYU_VERSION: &str = "draft-13-swiyu";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCISwiyuParams {
    #[serde(deserialize_with = "deserialize_duration_seconds")]
    pub pre_authorized_code_expires_in: Duration,
    #[serde(deserialize_with = "deserialize_duration_seconds")]
    pub token_expires_in: Duration,
    #[serde(deserialize_with = "deserialize_duration_seconds")]
    pub refresh_expires_in: Duration,
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
            enable_credential_preview: false,
        }
    }
}

pub(crate) struct OpenID4VCI13Swiyu {
    inner: OpenID4VCI13,
}

impl OpenID4VCI13Swiyu {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn HttpClient>,
        metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
        credential_repository: Arc<dyn CredentialRepository>,
        key_repository: Arc<dyn KeyRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
        key_provider: Arc<dyn KeyProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCISwiyuParams,
        handle_invitation_operations: Arc<dyn HandleInvitationOperations>,
    ) -> Self {
        Self {
            inner: OpenID4VCI13::new_with_custom_version(
                client,
                metadata_cache,
                credential_repository,
                key_repository,
                validity_credential_repository,
                formatter_provider,
                revocation_provider,
                did_method_provider,
                key_algorithm_provider,
                key_security_level_provider,
                key_provider,
                certificate_validator,
                identifier_creator,
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
    async fn holder_can_handle(&self, url: &Url) -> bool {
        self.inner.holder_can_handle(url).await
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum, IssuanceProtocolError> {
        self.inner
            .holder_handle_invitation_with_protocol(
                url,
                organisation,
                IssuanceProtocolType::OpenId4VciDraft13Swiyu,
                storage_access,
                redirect_uri,
            )
            .await
    }

    async fn holder_accept_credential(
        &self,
        interaction: Interaction,
        holder_binding: Option<HolderBindingInput>,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
        _holder_wallet_unit_id: Option<HolderWalletUnitId>,
    ) -> Result<UpdateResponse, IssuanceProtocolError> {
        self.inner
            .holder_accept_credential(interaction, holder_binding, storage_access, tx_code, None)
            .await
    }

    async fn holder_reject_credential(
        &self,
        credential: Credential,
        storage_access: &StorageAccess,
    ) -> Result<(), IssuanceProtocolError> {
        self.inner
            .holder_reject_credential(credential, storage_access)
            .await
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse, IssuanceProtocolError> {
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
            .holder_continue_issuance_with_protocol(
                continue_issuance_dto,
                organisation,
                IssuanceProtocolType::OpenId4VciDraft13Swiyu,
                storage_access,
            )
            .await
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        IssuanceProtocolCapabilities {
            features: vec![],
            did_methods: vec![WebVh],
        }
    }
}
