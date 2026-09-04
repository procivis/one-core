use std::sync::Arc;

use proc_macros::Provider;
use secrecy::SecretSlice;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{
    CredentialId, CredentialSchemaFormatId, CredentialSchemaId, SerializedCredential,
};
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::openid4vci::CredentialIssuerMetadata;
use time::Duration;
use url::Url;

use super::dto::{ContinueIssuanceDTO, Features, IssuanceProtocolCapabilities};
use super::error::IssuanceProtocolError;
use super::model::{
    CommonParams, ContinueIssuanceResponseDTO, InvitationResponseEnum, IssuanceAcceptResponse,
    OpenID4VCRedirectUriParams, ShareResponse,
};
use super::openid4vci_final1_0::OpenID4VCIFinal1_0;
use super::openid4vci_final1_0::model::{
    CredentialEndpointEncryptionParams, OpenID4VCIFinal1Params, OpenID4VCNonceParams,
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
use crate::proto::session_provider::SessionProvider;
use crate::proto::swiyu_http_client;
use crate::proto::wallet_instance::HolderWalletUnitProto;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;

pub(crate) const OID4VCI_FINAL1_0_SWIYU_VERSION: &str = "final-1.0-swiyu";

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCISwiyuParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub pre_authorized_code_expires_in_seconds: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub token_expires_in_seconds: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub refresh_expires_in_seconds: Duration,
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub encryption: SecretSlice<u8>,
    pub redirect_uri: OpenID4VCRedirectUriParams,
    pub nonce: Option<OpenID4VCNonceParams>,

    #[serde_as(as = "DurationSeconds<i64>")]
    pub oauth_attestation_leeway_seconds: Duration,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub key_attestation_leeway_seconds: Duration,

    #[serde(default)]
    pub credential_encryption: CredentialEndpointEncryptionParams,

    #[serde(flatten)]
    pub common: CommonParams,
}

impl From<OpenID4VCISwiyuParams> for OpenID4VCIFinal1Params {
    fn from(value: OpenID4VCISwiyuParams) -> Self {
        Self {
            pre_authorized_code_expires_in_seconds: value.pre_authorized_code_expires_in_seconds,
            token_expires_in_seconds: value.token_expires_in_seconds,
            refresh_expires_in_seconds: value.refresh_expires_in_seconds,
            credential_offer_by_value: true,
            encryption: value.encryption,
            url_scheme: "swiyu".to_string(),
            redirect_uri: value.redirect_uri,
            nonce: value.nonce,
            oauth_attestation_leeway_seconds: value.oauth_attestation_leeway_seconds,
            key_attestation_leeway_seconds: value.key_attestation_leeway_seconds,
            credential_endpoint_encryption: value.credential_encryption,
            common: value.common,
        }
    }
}

#[derive(Provider)]
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
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: serde_json::Value,
        config_id: String,
        holder_wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
        holder_wallet_unit_repository: Arc<dyn InstanceRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
        interaction_repository: Arc<dyn InteractionRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
    ) -> Result<Self, InitializationError> {
        let params: OpenID4VCISwiyuParams =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        let protocol_base_url = base_url
            .as_ref()
            .map(|base_url| format!("{base_url}/ssi/openid4vci/final-1.0-swiyu"));
        let client = Arc::new(swiyu_http_client::ProxySwiyuHttpClient { client });
        Ok(Self {
            inner: OpenID4VCIFinal1_0::new_with_custom_protocol_base_url(
                protocol_base_url,
                client,
                metadata_cache,
                credential_repository,
                key_repository,
                identifier_creator,
                credential_schema_importer,
                credential_schema_repository,
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
                holder_wallet_unit_repository,
                certificate_validator,
                history_repository,
                session_provider,
                interaction_repository,
                identifier_repository,
            ),
        })
    }
}

#[async_trait::async_trait]
impl IssuanceProtocol for OpenID4VCISwiyu {
    fn holder_can_handle(&self, url: &Url) -> bool {
        url.scheme() == "swiyu"
    }

    async fn holder_handle_invitation<'a>(
        &self,
        url: Url,
        organisation: Organisation,
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum<'a>, IssuanceProtocolError> {
        self.inner
            .holder_handle_invitation(url, organisation, redirect_uri)
            .await
    }

    async fn holder_accept_credential(
        &self,
        interaction: Interaction,
        holder_binding: Option<HolderBindingInput>,
        tx_code: Option<String>,
    ) -> Result<IssuanceAcceptResponse, IssuanceProtocolError> {
        self.inner
            .holder_accept_credential(interaction, holder_binding, tx_code)
            .await
    }

    async fn holder_reject_credential(
        &self,
        credential: Credential,
    ) -> Result<(), IssuanceProtocolError> {
        self.inner.holder_reject_credential(credential).await
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
        format_id: CredentialSchemaFormatId,
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SerializedCredential, IssuanceProtocolError> {
        self.inner
            .issuer_issue_credential(credential_id, format_id, holder_identifier, holder_key_id)
            .await
    }

    async fn holder_continue_issuance<'a>(
        &self,
        continue_issuance_dto: ContinueIssuanceDTO,
        organisation: Organisation,
    ) -> Result<ContinueIssuanceResponseDTO<'a>, IssuanceProtocolError> {
        self.inner
            .holder_continue_issuance(continue_issuance_dto, organisation)
            .await
    }

    async fn issuer_metadata(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
        issuer_identifier: &Identifier,
    ) -> Result<CredentialIssuerMetadata, IssuanceProtocolError> {
        self.inner
            .issuer_metadata_inner(
                protocol_id,
                credential_schema_id,
                issuer_identifier,
                self.get_capabilities().supported_encryption_algorithms,
            )
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
            supported_encryption_algorithms: vec![
                EncryptionAlgorithm::A128GCM,
                EncryptionAlgorithm::A256GCM,
            ],
        }
    }

    async fn holder_refresh_credential(
        &self,
        interaction: &Interaction,
        update_credential: Option<CredentialId>,
    ) -> Result<Vec<Credential>, IssuanceProtocolError> {
        self.inner
            .holder_refresh_credential(interaction, update_credential)
            .await
    }

    fn config_name(&self) -> &str {
        self.inner.config_name()
    }
}
