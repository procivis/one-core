use serde::Serialize;
use shared_types::OrganisationId;
use standardized_types::oauth2::dynamic_client_registration::TokenEndpointAuthMethod;
use time::Duration;
use uuid::Uuid;

use super::mapper::configuration_to_accepted_key_storage_security;
use super::model::{HolderCredentialConfiguration, TokenRequestWalletAttestationRequest};
use super::{
    HolderInteractionData, IssuanceProtocolError, OpenID4VCIFinal1_0, WalletAttestationResult,
};
use crate::error::ContextWithErrorCode;
use crate::model::instance::{InstanceRole, InstanceStatus};
use crate::model::key::Key;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::wallet_instance::{
    IssueWalletAttestationRequest, WIARequestParams, WUARequestParams,
};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::validator::key_security::match_key_security_level;

#[derive(Debug, PartialEq)]
#[expect(clippy::upper_case_acronyms)]
pub(super) enum AttestationType {
    WUA,
    WIA,
}

impl OpenID4VCIFinal1_0 {
    /// Prepares wallet attestations (WIA/WUA) based on issuer requirements.
    pub(super) async fn prepare_wallet_attestations(
        &self,
        interaction_data: &HolderInteractionData,
        configuration: Option<&HolderCredentialConfiguration>,
        attested_keys: &[&Key],
        organisation_id: OrganisationId,
        attestation_types: &[AttestationType],
    ) -> Result<WalletAttestationResult, IssuanceProtocolError> {
        let holder_wallet_unit = self
            .holder_wallet_unit_repository
            .get_by_role(InstanceRole::Wallet, organisation_id)
            .await
            .error_while("getting holder wallet instance")?;
        let wallet_unit_provided = holder_wallet_unit
            .as_ref()
            .is_some_and(|unit| unit.status == InstanceStatus::Active);

        // WIA requirements

        // DEVIATION: RFC8414 specifies `client_secret_basic` as the default when
        // token_endpoint_auth_methods_supported is absent, but some issuers (e.g. swiyu) don't publish this field.
        // Treating empty/missing as `none` to avoid interop issues
        let default_auth_methods = [TokenEndpointAuthMethod::None];
        let token_endpoint_auth_methods = interaction_data
            .token_endpoint_auth_methods_supported
            .as_deref()
            .unwrap_or(&default_auth_methods);

        let wallet_attestation_supported =
            token_endpoint_auth_methods.contains(&TokenEndpointAuthMethod::AttestJwtClientAuth);
        let wallet_attestation_required = requires_wia(token_endpoint_auth_methods);

        if attestation_types.contains(&AttestationType::WIA)
            && wallet_attestation_required
            && !wallet_unit_provided
        {
            return Err(IssuanceProtocolError::Failed(
                "Active holder wallet unit id is required".to_string(),
            ));
        }

        let use_wallet_attestation = attestation_types.contains(&AttestationType::WIA)
            && (wallet_attestation_required
                || (wallet_attestation_supported && wallet_unit_provided));

        // WUA requirements
        let required_key_storage_security_level =
            if attestation_types.contains(&AttestationType::WUA) {
                let issuer_accepted_levels =
                    configuration.and_then(configuration_to_accepted_key_storage_security);

                issuer_accepted_levels
                    .map(|accepted_levels| {
                        Ok::<_, IssuanceProtocolError>(
                            match_key_security_level(
                                &attested_keys
                                    .first()
                                    .ok_or(IssuanceProtocolError::Failed(
                                        "No keys for holder binding".to_string(),
                                    ))?
                                    .storage_type,
                                &accepted_levels,
                                &*self.key_security_level_provider,
                            )
                            .error_while("matching key security")?,
                        )
                    })
                    .transpose()?
            } else {
                None
            };

        if required_key_storage_security_level.is_some() && !wallet_unit_provided {
            return Err(IssuanceProtocolError::Failed(
                "key storage attestation requires active holder wallet unit id".to_string(),
            ));
        }

        let attestations_issuance_request =
            match (use_wallet_attestation, required_key_storage_security_level) {
                (true, Some(security_level)) => Some(IssueWalletAttestationRequest::WuaAndWia(
                    WUARequestParams {
                        attested_keys,
                        security_level,
                    },
                    self.prepare_wia_request_params(interaction_data)?,
                )),
                (true, None) => Some(IssueWalletAttestationRequest::Wia(
                    self.prepare_wia_request_params(interaction_data)?,
                )),
                (false, Some(security_level)) => {
                    Some(IssueWalletAttestationRequest::Wua(WUARequestParams {
                        attested_keys,
                        security_level,
                    }))
                }
                (false, None) => None,
            };

        let attestations_issuance_response = match attestations_issuance_request {
            None => None,
            Some(request) => {
                let holder_wallet_unit_id = holder_wallet_unit
                    .as_ref()
                    .ok_or(IssuanceProtocolError::Failed(
                        "holder wallet unit is required".to_string(),
                    ))?
                    .id;

                let response = self
                    .holder_wallet_unit_proto
                    .issue_wallet_attestations(&holder_wallet_unit_id, request)
                    .await
                    .error_while("issuing attestations")?;

                Some(response)
            }
        };

        // Create WIA proof-of-possession if using WIA
        let wia_tokens =
            match (use_wallet_attestation, &attestations_issuance_response) {
                (true, Some(issuance_response)) => {
                    let wia = issuance_response.provider_response.wia.first().ok_or(
                        IssuanceProtocolError::Failed("Wallet attestation is required".to_string()),
                    )?;

                    let wia_pop_key = issuance_response.wia_pop_key.as_ref().ok_or(
                        IssuanceProtocolError::Failed("WIA PoP key missing".to_string()),
                    )?;

                    // Per https://drafts.oauth.net/draft-ietf-oauth-attestation-based-client-auth/draft-ietf-oauth-attestation-based-client-auth.html#section-5
                    // The WIA sub (subject) claim MUST specify client_id value of the OAuth Client.
                    let wia_jwt: Jwt<()> = Jwt::build_from_token(wia, None, None)
                        .await
                        .error_while("parsing WIA JWT")?;

                    let client_id =
                        wia_jwt
                            .payload
                            .subject
                            .ok_or(IssuanceProtocolError::Failed(
                                "WIA missing subject claim".to_string(),
                            ))?;

                    let challenge =
                        if let Some(challenge_endpoint) = &interaction_data.challenge_endpoint {
                            Some(self.holder_fetch_challenge(challenge_endpoint).await?)
                        } else {
                            None
                        };

                    let signed_proof = create_wallet_unit_attestation_pop(
                        wia_pop_key,
                        &interaction_data.issuer_url,
                        challenge,
                        &client_id,
                    )
                    .await?;

                    Ok(Some(TokenRequestWalletAttestationRequest {
                        wallet_attestation: wia.to_owned(),
                        wallet_attestation_pop: signed_proof,
                    }))
                }
                (true, None) => Err(IssuanceProtocolError::Failed(
                    "Wallet attestation issuance failed".to_string(),
                )),
                (false, _) => Ok(None),
            }?;

        // Extract WUA proof if key attestation is required
        let key_attestations_required = required_key_storage_security_level.is_some();
        let wua_proofs = match (key_attestations_required, attestations_issuance_response) {
            (true, Some(issuance_response)) => Ok(Some(issuance_response.provider_response.wua)),
            (true, None) => Err(IssuanceProtocolError::Failed(
                "Key attestation is required".to_string(),
            )),
            (false, _) => Ok(None),
        }?;

        Ok(WalletAttestationResult {
            wia_tokens,
            wua_proofs,
        })
    }

    fn prepare_wia_request_params(
        &self,
        interaction_data: &HolderInteractionData,
    ) -> Result<WIARequestParams, IssuanceProtocolError> {
        let alg_values_supported = interaction_data
            .client_attestation_pop_signing_alg_values_supported
            .as_ref()
            .ok_or(IssuanceProtocolError::InvalidRequest(
                "token auth method attest_jwt_client_auth speicified, but client_attestation_pop_signing_alg_values_supported missing".to_string(),
            ))?;

        for alg in alg_values_supported {
            if let Some((key_algorithm, _)) =
                self.key_algorithm_provider.key_algorithm_from_jose_alg(alg)
            {
                return Ok(WIARequestParams { key_algorithm });
            }
        }

        Err(IssuanceProtocolError::InvalidRequest(format!(
            "No suitable alg found in client_attestation_pop_signing_alg_values_supported: {alg_values_supported:?}"
        )))
    }
}

pub(super) fn requires_wia(token_endpoint_auth_methods: &[TokenEndpointAuthMethod]) -> bool {
    // See https://gitlab.procivis.ch/procivis/one/one-core/-/merge_requests/2585#note_86705
    // Some issuers advertise "public", which is not documented / defined by any specification
    // We treat it as the rfc7591 defined "none"
    let public_auth_supported = token_endpoint_auth_methods
        .contains(&TokenEndpointAuthMethod::None)
        || token_endpoint_auth_methods
            .contains(&TokenEndpointAuthMethod::Other("public".to_string()));

    token_endpoint_auth_methods.contains(&TokenEndpointAuthMethod::AttestJwtClientAuth)
        && !public_auth_supported
}

async fn create_wallet_unit_attestation_pop(
    auth_fn: &AuthenticationFn,
    audience: &str,
    challenge: Option<String>,
    client_id: &str,
) -> Result<String, IssuanceProtocolError> {
    #[derive(Serialize)]
    struct WalletUnitPopCustomClaims {
        #[serde(skip_serializing_if = "Option::is_none")]
        challenge: Option<String>,
    }

    let now = crate::clock::now_utc();
    let proof = Jwt::new(
        "oauth-client-attestation-pop+jwt".to_string(),
        auth_fn.jose_alg().error_while("getting JOSE alg")?,
        auth_fn.get_key_id(),
        None,
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + Duration::minutes(60)),
            invalid_before: Some(now),
            audience: Some(vec![audience.to_string()]),
            jwt_id: Some(Uuid::new_v4().to_string()),
            issuer: Some(client_id.to_string()),
            subject: None,
            proof_of_possession_key: None,
            custom: WalletUnitPopCustomClaims { challenge },
        },
    );

    Ok(proof
        .tokenize(Some(auth_fn.as_ref()))
        .await
        .error_while("creating proof token")?)
}
