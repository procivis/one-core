mod proxy_http_client;

use std::sync::Arc;

use secrecy::SecretSlice;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{CredentialId, HolderWalletUnitId};
use time::Duration;
use url::Url;

use super::dto::{ContinueIssuanceDTO, IssuanceProtocolCapabilities};
use super::error::IssuanceProtocolError;
use super::model::{
    CommonParams, ContinueIssuanceResponseDTO, InvitationResponseEnum, OpenID4VCRedirectUriParams,
    ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use super::{HolderBindingInput, IssuanceProtocol};
use crate::config::core_config::CoreConfig;
use crate::config::core_config::DidType::WebVh;
use crate::mapper::params::deserialize_encryption_key;
use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::wallet_unit::HolderWalletUnitProto;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::dto::Features;
use crate::provider::issuance_protocol::openid4vci_final1_0::OpenID4VCIFinal1_0;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCIFinal1Params, OpenID4VCNonceParams,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::storage_proxy::StorageAccess;

pub(crate) const OID4VCI_FINAL1_0_SWIYU_VERSION: &str = "final-1.0-swiyu";

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCISwiyuParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub pre_authorized_code_expires_in: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub token_expires_in: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub refresh_expires_in: Duration,
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub encryption: SecretSlice<u8>,
    pub redirect_uri: OpenID4VCRedirectUriParams,
    pub nonce: Option<OpenID4VCNonceParams>,
    pub oauth_attestation_leeway: u64,
    pub key_attestation_leeway: u64,

    #[serde(flatten)]
    pub common: CommonParams,
}

impl From<OpenID4VCISwiyuParams> for OpenID4VCIFinal1Params {
    fn from(value: OpenID4VCISwiyuParams) -> Self {
        Self {
            pre_authorized_code_expires_in: value.pre_authorized_code_expires_in,
            token_expires_in: value.token_expires_in,
            refresh_expires_in: value.refresh_expires_in,
            credential_offer_by_value: true,
            encryption: value.encryption,
            url_scheme: "swiyu".to_string(),
            redirect_uri: value.redirect_uri,
            nonce: value.nonce,
            oauth_attestation_leeway: value.oauth_attestation_leeway,
            key_attestation_leeway: value.key_attestation_leeway,
            common: value.common,
        }
    }
}

pub(crate) struct OpenID4VCISwiyu {
    inner: OpenID4VCIFinal1_0,
}

impl OpenID4VCISwiyu {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn HttpClient>,
        metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
        credential_repository: Arc<dyn CredentialRepository>,
        key_repository: Arc<dyn KeyRepository>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCISwiyuParams,
        config_id: String,
        holder_wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        let protocol_base_url = base_url
            .as_ref()
            .map(|base_url| format!("{base_url}/ssi/openid4vci/final-1.0-swiyu"));
        let client = Arc::new(proxy_http_client::ProxySwiyuHttpClient { client });
        Self {
            inner: OpenID4VCIFinal1_0::new_with_custom_protocol_base_url(
                protocol_base_url,
                client,
                metadata_cache,
                credential_repository,
                key_repository,
                identifier_creator,
                credential_schema_importer,
                validity_credential_repository,
                formatter_provider,
                revocation_provider,
                did_method_provider,
                key_algorithm_provider,
                key_provider,
                key_security_level_provider,
                blob_storage_provider,
                base_url,
                config,
                params.into(),
                config_id,
                holder_wallet_unit_proto,
                certificate_validator,
            ),
        }
    }
}

#[async_trait::async_trait]
impl IssuanceProtocol for OpenID4VCISwiyu {
    async fn holder_can_handle(&self, url: &Url) -> bool {
        url.scheme() == "swiyu"
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
        self.inner.issuer_share_credential(credential).await
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
        let mut features = vec![];
        if self
            .inner
            .get_capabilities()
            .features
            .contains(&Features::SupportsWebhooks)
        {
            features.push(Features::SupportsWebhooks);
        }

        IssuanceProtocolCapabilities {
            features,
            did_methods: vec![WebVh],
        }
    }
}
