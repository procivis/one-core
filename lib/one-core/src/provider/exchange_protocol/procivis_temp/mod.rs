mod mapper;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use dto_mapper::convert_inner;
use one_providers::common_dto::PublicKeyJwkDTO;
use one_providers::common_models::claim::OpenClaim;
use one_providers::common_models::claim_schema::OpenClaimSchema;
use one_providers::common_models::credential::{
    OpenCredential, OpenCredentialRole, OpenCredentialState, OpenCredentialStateEnum,
};
use one_providers::common_models::credential_schema::{
    OpenCredentialSchema, OpenCredentialSchemaClaim,
};
use one_providers::common_models::did::{DidType, KeyRole, OpenDid};
use one_providers::common_models::key::{KeyId, OpenKey};
use one_providers::common_models::organisation::OpenOrganisation;
use one_providers::common_models::proof::{OpenProof, OpenProofStateEnum};
use one_providers::credential_formatter::model::{DetailCredential, FormatPresentationCtx};
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::exchange_protocol::openid4vc::model::{
    CredentialGroup, CredentialGroupItem, DatatypeType, InvitationResponseDTO, OpenID4VPFormat,
    PresentationDefinitionResponseDTO, PresentedCredential, ShareResponse, SubmitIssuerResponse,
    UpdateResponse,
};
use one_providers::exchange_protocol::openid4vc::service::FnMapExternalFormatToExternalDetailed;
use one_providers::exchange_protocol::openid4vc::validator::throw_if_latest_proof_state_not_eq;
use one_providers::exchange_protocol::openid4vc::{
    ExchangeProtocolImpl, FormatMapper, HandleInvitationOperationsAccess, StorageAccess,
    TypeToDescriptorMapper,
};
use one_providers::http_client::HttpClient;
use one_providers::key_storage::provider::KeyProvider;
use shared_types::CredentialId;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use self::mapper::{
    get_base_url, get_proof_claim_schemas_from_proof, presentation_definition_from_proof,
    remote_did_from_value,
};
use super::dto::{ConnectVerifierResponse, ProofClaimSchema};
use super::mapper::get_relevant_credentials_to_credential_schemas;
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::CoreConfig;
use crate::model::credential_schema::LayoutType;
use crate::provider::exchange_protocol::mapper::{
    interaction_from_handle_invitation, proof_from_handle_invitation,
};
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::service::credential::dto::{
    DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
};
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::ssi_issuer::dto::ConnectIssuerResponseDTO;

const REDIRECT_URI_QUERY_PARAM_KEY: &str = "redirect_uri";

pub(crate) struct ProcivisTemp {
    client: Arc<dyn HttpClient>,
    base_url: Option<String>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    config: Arc<CoreConfig>,
}

impl ProcivisTemp {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_url: Option<String>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<CoreConfig>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            client,
            base_url,
            formatter_provider,
            key_provider,
            config,
        }
    }
}

enum InvitationType {
    CredentialIssuance,
    ProofRequest { proof_id: String, protocol: String },
}

fn categorize_url(url: &Url) -> Result<InvitationType, ExchangeProtocolError> {
    let query_value_for = |query_name| {
        url.query_pairs()
            .find_map(|(k, v)| (k == query_name).then_some(v))
    };

    let protocol = query_value_for("protocol")
        .ok_or(ExchangeProtocolError::Failed(
            "Missing protocol query param".to_string(),
        ))?
        .to_string();

    if query_value_for("credential").is_some() {
        return Ok(InvitationType::CredentialIssuance);
    } else if let Some(proof) = query_value_for("proof") {
        return Ok(InvitationType::ProofRequest {
            proof_id: proof.to_string(),
            protocol,
        });
    }

    Err(ExchangeProtocolError::Failed("Invalid Query".to_owned()))
}

#[async_trait]
impl ExchangeProtocolImpl for ProcivisTemp {
    type VCInteractionContext = ();
    type VPInteractionContext = Vec<ProofClaimSchema>;

    fn can_handle(&self, url: &Url) -> bool {
        categorize_url(url).is_ok()
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: OpenOrganisation,
        storage_access: &StorageAccess,
        _handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        let invitation_type = categorize_url(&url)?;

        let base_url = get_base_url(&url)?;

        let redirect_uri = url
            .query_pairs()
            .filter(|(k, _)| k == REDIRECT_URI_QUERY_PARAM_KEY)
            .map(|(_, v)| v.to_string())
            .next();

        let response = self
            .client
            .post(url.as_str())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?;

        let response = response
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;

        Ok(match invitation_type {
            InvitationType::CredentialIssuance { .. } => {
                let issuer_response = response
                    .json()
                    .context("parsing error")
                    .map_err(ExchangeProtocolError::Transport)?;

                handle_credential_invitation(
                    base_url,
                    organisation.to_owned(),
                    issuer_response,
                    storage_access,
                )
                .await?
            }
            InvitationType::ProofRequest { proof_id, protocol } => {
                let proof_request = response
                    .json()
                    .context("parsing error")
                    .map_err(ExchangeProtocolError::Transport)?;

                handle_proof_invitation(
                    base_url,
                    proof_id,
                    proof_request,
                    &protocol,
                    organisation,
                    redirect_uri,
                    storage_access,
                )
                .await?
            }
        })
    }

    async fn reject_proof(&self, proof: &OpenProof) -> Result<(), ExchangeProtocolError> {
        let mut url = super::get_base_url_from_interaction(proof.interaction.as_ref())?;
        url.set_path("/ssi/temporary-verifier/v1/reject");
        url.set_query(Some(&format!("proof={}", proof.id)));

        self.client
            .post(url.as_str())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;

        Ok(())
    }

    async fn submit_proof(
        &self,
        proof: &OpenProof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &OpenDid,
        key: &OpenKey,
        jwk_key_id: Option<String>,
        _format_map: HashMap<String, String>,
        _presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        let presentation_formatter = self
            .formatter_provider
            .get_formatter("JWT")
            .ok_or_else(|| ExchangeProtocolError::Failed("JWT formatter not found".to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key.to_owned(), jwk_key_id)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let tokens: Vec<String> = credential_presentations
            .into_iter()
            .map(|presented_credential| presented_credential.presentation)
            .collect();

        let presentation = presentation_formatter
            .format_presentation(
                &tokens,
                &holder_did.did.clone(),
                &key.key_type,
                auth_fn,
                FormatPresentationCtx::default(),
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let mut url = super::get_base_url_from_interaction(proof.interaction.as_ref())?;
        url.set_path("/ssi/temporary-verifier/v1/submit");
        url.set_query(Some(&format!(
            "proof={}&didValue={}",
            proof.id, holder_did.did
        )));

        let response = self
            .client
            .post(url.as_str())
            .body(presentation.into_bytes())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?;
        response
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;

        Ok(UpdateResponse {
            result: (),
            update_proof: None,
            create_did: None,
            update_credential: None,
            update_credential_schema: None,
        })
    }

    async fn accept_credential(
        &self,
        credential: &OpenCredential,
        holder_did: &OpenDid,
        _key: &OpenKey,
        _jwk_key_id: Option<String>,
        _format: &str,
        _storage_access: &StorageAccess,
        _map_oidc_format_to_external: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        let mut url = super::get_base_url_from_interaction(credential.interaction.as_ref())?;
        url.set_path("/ssi/temporary-issuer/v1/submit");
        url.set_query(Some(&format!(
            "credentialId={}&didValue={}",
            credential.id, holder_did.did
        )));

        let response = self
            .client
            .post(url.as_str())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?;
        let response = response
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;

        let result =
            serde_json::from_slice(&response.body).map_err(ExchangeProtocolError::JsonError)?;

        Ok(UpdateResponse {
            result,
            update_proof: None,
            create_did: None,
            update_credential: None,
            update_credential_schema: None,
        })
    }

    async fn reject_credential(
        &self,
        credential: &OpenCredential,
    ) -> Result<(), ExchangeProtocolError> {
        let mut url = super::get_base_url_from_interaction(credential.interaction.as_ref())?;
        url.set_path("/ssi/temporary-issuer/v1/reject");
        url.set_query(Some(&format!("credentialId={}", credential.id)));

        let response = self
            .client
            .post(url.as_str())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?;
        response
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;

        Ok(())
    }

    async fn validate_proof_for_submission(
        &self,
        proof: &OpenProof,
    ) -> Result<(), ExchangeProtocolError> {
        throw_if_latest_proof_state_not_eq(proof, OpenProofStateEnum::Pending)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
    }

    async fn share_credential(
        &self,
        credential: &OpenCredential,
        _credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        let base_url = self
            .base_url
            .as_ref()
            .ok_or(ExchangeProtocolError::MissingBaseUrl)?;
        let connect_url = format!("{}/ssi/temporary-issuer/v1/connect", base_url);
        let mut url =
            Url::parse(&connect_url).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("protocol", &credential.exchange);
        pairs.append_pair("credential", &credential.id.to_string());

        if let Some(redirect_uri) = credential.redirect_uri.as_ref() {
            pairs.append_pair("redirect_uri", redirect_uri);
        }

        Ok(ShareResponse {
            url: pairs.finish().to_string(),
            id: Uuid::new_v4(),
            context: (),
        })
    }

    async fn share_proof(
        &self,
        proof: &OpenProof,
        _format_to_type_mapper: FormatMapper,
        _key_id: KeyId,
        _encryption_key_jwk: PublicKeyJwkDTO,
        _vp_formats: HashMap<String, OpenID4VPFormat>,
        _type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        let base_url = self
            .base_url
            .as_ref()
            .ok_or(ExchangeProtocolError::MissingBaseUrl)?;
        let connect_url = format!("{}/ssi/temporary-verifier/v1/connect", base_url);
        let mut url =
            Url::parse(&connect_url).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("protocol", &proof.exchange);
        pairs.append_pair("proof", &proof.id.to_string());

        if let Some(redirect_uri) = proof.redirect_uri.as_ref() {
            pairs.append_pair("redirect_uri", redirect_uri);
        }

        Ok(ShareResponse {
            url: pairs.finish().to_string(),
            id: Uuid::new_v4(),
            context: vec![],
        })
    }

    async fn get_presentation_definition(
        &self,
        proof: &OpenProof,
        proof_claim_schemas: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        _format_map: HashMap<String, String>,
        _types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let requested_claims = get_proof_claim_schemas_from_proof(proof)?;
        let mut credential_groups: Vec<CredentialGroup> = vec![];
        let mut group_id_to_schema_id: HashMap<String, String> = HashMap::new();

        let allowed_formats: HashSet<&str> = proof_claim_schemas
            .iter()
            .map(|proof_claim_schema| proof_claim_schema.credential_schema.format.as_str())
            .collect();

        for requested_claim in requested_claims {
            let group_id = requested_claim.credential_schema.id;
            let credential_group_item = CredentialGroupItem {
                id: requested_claim.id,
                key: requested_claim.key,
                required: requested_claim.required,
            };

            if let Some(group) = credential_groups
                .iter_mut()
                .find(|group| group.id == group_id)
            {
                group.claims.push(credential_group_item);
            } else {
                group_id_to_schema_id.insert(
                    group_id.clone(),
                    requested_claim.credential_schema.schema_id,
                );
                credential_groups.push(CredentialGroup {
                    id: group_id,
                    name: Some(requested_claim.credential_schema.name),
                    purpose: None,
                    claims: vec![credential_group_item],
                    applicable_credentials: vec![],
                    validity_credential_nbf: None,
                });
            }
        }

        let (credentials, credential_groups) = get_relevant_credentials_to_credential_schemas(
            storage_access,
            credential_groups,
            group_id_to_schema_id,
            &allowed_formats,
        )
        .await?;

        presentation_definition_from_proof(proof, credentials, credential_groups, &self.config)
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &OpenProof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        unimplemented!()
    }
}

async fn handle_credential_invitation(
    base_url: Url,
    organisation: OpenOrganisation,
    issuer_response: ConnectIssuerResponseDTO,
    storage_access: &StorageAccess,
) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
    let now = OffsetDateTime::now_utc();
    let credential_schema = match storage_access
        .get_schema(
            &issuer_response.schema.schema_id,
            &issuer_response.schema.schema_type.to_string(),
            organisation.id,
        )
        .await
        .map_err(ExchangeProtocolError::StorageAccessError)?
    {
        Some(credential_schema) => {
            if credential_schema.schema_type != issuer_response.schema.schema_type.to_string() {
                return Err(ExchangeProtocolError::IncorrectCredentialSchemaType);
            }

            storage_access
                .get_schema(
                    &credential_schema.id.to_string(),
                    &credential_schema.schema_type,
                    organisation.id,
                )
                .await
                .map_err(ExchangeProtocolError::StorageAccessError)?
                .ok_or(ExchangeProtocolError::Failed(
                    "Credential schema error".to_string(),
                ))?
        }
        None => {
            let credential_schema = OpenCredentialSchema {
                id: issuer_response.schema.id.into(),
                deleted_at: None,
                created_date: now,
                last_modified: now,
                name: issuer_response.schema.name,
                format: issuer_response.schema.format,
                revocation_method: issuer_response.schema.revocation_method,
                wallet_storage_type: issuer_response.schema.wallet_storage_type,
                layout_type: issuer_response
                    .schema
                    .layout_type
                    .unwrap_or(LayoutType::Card)
                    .into(),
                layout_properties: convert_inner(issuer_response.schema.layout_properties),
                schema_id: issuer_response.schema.schema_id,
                schema_type: issuer_response.schema.schema_type.to_string(),
                claim_schemas: Some(extract_claim_schemas_from_incoming(
                    &issuer_response.schema.claims,
                    now,
                    "",
                )?),
                organisation: Some(organisation.to_owned()),
            };

            let _ = storage_access
                .create_credential_schema(credential_schema.clone())
                .await
                .map_err(ExchangeProtocolError::StorageAccessError)?;

            credential_schema
        }
    };

    // insert issuer did if not yet known
    let issuer_did_value = issuer_response.issuer_did.did.into();
    let did = storage_access
        .get_did_by_value(&issuer_did_value)
        .await
        .map_err(ExchangeProtocolError::StorageAccessError)?;

    let issuer_did = match did {
        Some(did) => did,
        None => {
            let issuer_did =
                remote_did_from_value(issuer_did_value.to_owned(), organisation.into());
            let _ = storage_access
                .create_did(issuer_did.clone())
                .await
                .map_err(ExchangeProtocolError::StorageAccessError)?;
            issuer_did
        }
    };

    let interaction = interaction_from_handle_invitation(base_url, None, now);
    let interaction_id = storage_access
        .create_interaction(interaction.clone())
        .await
        .map_err(ExchangeProtocolError::StorageAccessError)?;

    // create credential
    let credential_id = issuer_response.id;
    let incoming_claims = issuer_response.claims;

    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "claim_schemas is None".to_string(),
            ))?;

    let claims = incoming_claims
        .iter()
        .map(|value| unnest_incoming_claim(credential_id, value, claim_schemas, now, ""))
        .collect::<Result<Vec<Vec<_>>, ExchangeProtocolError>>()?
        .into_iter()
        .flatten()
        .collect();

    let credential = OpenCredential {
        id: Uuid::from(credential_id).into(),
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri: issuer_response.redirect_uri,
        role: OpenCredentialRole::Holder,
        state: Some(vec![OpenCredentialState {
            created_date: now,
            state: OpenCredentialStateEnum::Pending,
            suspend_end_date: None,
        }]),
        claims: Some(claims),
        issuer_did: Some(issuer_did),
        holder_did: None,
        schema: Some(credential_schema),
        interaction: Some(interaction),
        key: None,
    };

    Ok(InvitationResponseDTO::Credential {
        credentials: vec![credential],
        interaction_id,
    })
}

fn extract_claim_schemas_from_incoming(
    incoming_claims: &[CredentialClaimSchemaDTO],
    now: OffsetDateTime,
    prefix: &str,
) -> Result<Vec<OpenCredentialSchemaClaim>, ExchangeProtocolError> {
    let mut result = vec![];

    incoming_claims.iter().try_for_each(|incoming_claim| {
        let key = format!("{prefix}{}", incoming_claim.key);
        result.push(OpenCredentialSchemaClaim {
            schema: OpenClaimSchema {
                id: Uuid::from(incoming_claim.id).into(),
                key: key.to_owned(),
                data_type: incoming_claim.datatype.to_owned(),
                created_date: now,
                last_modified: now,
                array: false,
            },
            required: incoming_claim.required,
        });

        let nested_claims = &incoming_claim.claims;
        if !nested_claims.is_empty() {
            result.extend(extract_claim_schemas_from_incoming(
                nested_claims,
                now,
                &format!("{key}{NESTED_CLAIM_MARKER}"),
            )?);
        }

        Ok(())
    })?;

    Ok(result)
}

fn unnest_incoming_claim(
    credential_id: CredentialId,
    incoming_claim: &DetailCredentialClaimResponseDTO,
    claim_schemas: &[OpenCredentialSchemaClaim],
    now: OffsetDateTime,
    prefix: &str,
) -> Result<Vec<OpenClaim>, ExchangeProtocolError> {
    let value =
        match &incoming_claim.value {
            DetailCredentialClaimValueResponseDTO::Boolean(value) => serde_json::to_string(value)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string())),
            DetailCredentialClaimValueResponseDTO::Float(value) => serde_json::to_string(value)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string())),
            DetailCredentialClaimValueResponseDTO::Integer(value) => serde_json::to_string(value)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string())),
            DetailCredentialClaimValueResponseDTO::String(value) => Ok(value.to_owned()),
            DetailCredentialClaimValueResponseDTO::Nested(value) => {
                let result = value
                    .iter()
                    .map(|value| {
                        unnest_incoming_claim(
                            credential_id,
                            value,
                            claim_schemas,
                            now,
                            &format!("{prefix}{}{NESTED_CLAIM_MARKER}", incoming_claim.schema.key),
                        )
                    })
                    .collect::<Result<Vec<Vec<_>>, ExchangeProtocolError>>()?
                    .into_iter()
                    .flatten()
                    .collect();
                return Ok(result);
            }
        }?;

    let expected_key = format!("{prefix}{}", incoming_claim.schema.key);

    let current_claim_schema = claim_schemas
        .iter()
        .find(|claim_schema| claim_schema.schema.key == expected_key)
        .ok_or(ExchangeProtocolError::Failed(format!(
            "missing claim schema with key {expected_key}",
        )))?;
    Ok(vec![OpenClaim {
        id: Uuid::new_v4().into(),
        credential_id: Uuid::from(credential_id).into(),
        path: current_claim_schema.schema.key.to_owned(),
        schema: Some(current_claim_schema.schema.to_owned()),
        value,
        created_date: now,
        last_modified: now,
    }])
}

async fn handle_proof_invitation(
    base_url: Url,
    proof_id: String,
    proof_request: ConnectVerifierResponse,
    protocol: &str,
    organisation: OpenOrganisation,
    redirect_uri: Option<String>,
    storage_access: &StorageAccess,
) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
    let verifier_did_result = storage_access
        .get_did_by_value(&proof_request.verifier_did.clone().into())
        .await
        .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

    let now = OffsetDateTime::now_utc();
    let verifier_did = match verifier_did_result {
        Some(did) => did,
        None => {
            let id = Uuid::new_v4();
            let new_did = OpenDid {
                id: id.into(),
                created_date: now,
                last_modified: now,
                name: format!("verifier {id}"),
                did: proof_request.verifier_did.into(),
                did_type: DidType::Remote,
                did_method: "KEY".to_owned(),
                keys: None,
                deactivated: false,
                organisation: Some(organisation),
            };
            storage_access
                .create_did(new_did.clone())
                .await
                .map_err(ExchangeProtocolError::StorageAccessError)?;

            new_did
        }
    };

    let verifier_key = verifier_did
        .keys
        .as_ref()
        .map(|vec| {
            vec.iter()
                .find(|f| f.role == KeyRole::AssertionMethod)
                .map(|key| key.key.to_owned())
        })
        .and_then(|key| key);

    let data = serde_json::to_string(&proof_request.claims)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?
        .as_bytes()
        .to_vec();

    let interaction = interaction_from_handle_invitation(base_url, Some(data), now);

    let interaction_id = storage_access
        .create_interaction(interaction.clone())
        .await
        .map_err(ExchangeProtocolError::StorageAccessError)?;

    let proof_id: Uuid = proof_id
        .parse()
        .map_err(|_| ExchangeProtocolError::Failed("Cannot parse proof id".to_string()))?;

    let proof = proof_from_handle_invitation(
        &proof_id.into(),
        protocol,
        redirect_uri,
        Some(verifier_did),
        interaction,
        now,
        verifier_key,
        "HTTP",
    );

    Ok(InvitationResponseDTO::ProofRequest {
        interaction_id,
        proof: Box::new(proof),
    })
}

#[cfg(test)]
mod test;
