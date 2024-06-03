use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use shared_types::CredentialId;
use time::OffsetDateTime;

use crate::{
    model::{
        credential::CredentialRelations, credential_schema::CredentialSchemaRelations,
        did::DidRelations, key::KeyRelations, revocation_list::RevocationListRelations,
        validity_credential::ValidityCredentialType,
    },
    provider::{
        credential_formatter::error::FormatterError,
        revocation::{
            self,
            lvvc::{dto::LvvcStatus, mapper::status_from_lvvc_claims},
        },
    },
    service::{
        error::{EntityNotFoundError, MissingProviderError, ServiceError},
        revocation_list::{dto::RevocationListId, RevocationListService},
        ssi_issuer::dto::IssuerResponseDTO,
    },
};

impl RevocationListService {
    pub async fn get_lvvc_by_credential_id(
        &self,
        id: &CredentialId,
        bearer_token: &str,
    ) -> Result<IssuerResponseDTO, ServiceError> {
        // The service should search for the credential and check if it exists. If the credential does not exist throw 404 defined in error codes
        let credential = self
            .credential_repository
            .get_credential(
                id,
                &CredentialRelations {
                    schema: Some(CredentialSchemaRelations::default()),
                    issuer_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    holder_did: Some(DidRelations::default()),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?
            .ok_or(EntityNotFoundError::Credential(*id))?;

        // Use the stored holder did and resolve it. Then use the authentication keys to verify the jwt, and check if one is the correct one
        let holder_did = credential
            .holder_did
            .as_ref()
            .ok_or(ServiceError::MappingError("holder_did is None".to_string()))?;
        let resolved_did = self.did_method_provider.resolve(&holder_did.did).await?;
        let parsed_jwk = self
            .key_algorithm_provider
            .parse_jwk(&resolved_did.verification_method[0].public_key_jwk)?;

        // Check if bearer token is signed with key of the credential holder if not throw error.
        let mut jwt_parts = bearer_token.splitn(3, '.');
        let (Some(header), Some(payload), Some(signature)) =
            (jwt_parts.next(), jwt_parts.next(), jwt_parts.next())
        else {
            return Err(ServiceError::ValidationError(
                "Missing token part".to_owned(),
            ));
        };

        let signature = Base64UrlSafeNoPadding::decode_to_vec(signature, None)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        let input = format!("{header}.{payload}");

        self.crypto_provider
            .get_signer(&parsed_jwk.signer_algorithm_id)?
            .verify(input.as_bytes(), &signature, &parsed_jwk.public_key_bytes)
            .map_err(|e| ServiceError::ValidationError(e.to_string()))?;

        let schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        // In the next step the latest LVVC credential should be obtained from the asked for credential
        let latest_lvvc = self
            .lvvc_repository
            .get_latest_by_credential_id(id.to_owned(), ValidityCredentialType::Lvvc)
            .await
            .map_err(ServiceError::from)?
            .ok_or(EntityNotFoundError::Lvvc(*id))?;

        let credential_content = std::str::from_utf8(&latest_lvvc.credential)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        let format = schema.format.to_string();
        let formatter =
            self.formatter_provider
                .get_formatter(&format)
                .ok_or(ServiceError::MissingProvider(
                    MissingProviderError::Formatter(format.to_owned()),
                ))?;

        let extracted_credential = formatter
            .extract_credentials_unverified(credential_content)
            .await
            .map_err(ServiceError::from)?;

        let status = status_from_lvvc_claims(&extracted_credential.claims.values)?;
        match status {
            // ONE-1780: return current lvvc credential if not active
            LvvcStatus::Revoked | LvvcStatus::Suspended { .. } => {
                return Ok(IssuerResponseDTO {
                    credential: credential_content.to_string(),
                    format,
                });
            }
            LvvcStatus::Accepted => {}
        }

        // If issuanceDate + credentialExpiry < now then a new VC of the LVVC credential needs to be created and saved in database.
        let revocation_method = schema.revocation_method.to_string();
        let revocation_params: revocation::lvvc::Params =
            self.config.revocation.get(&revocation_method)?;
        let expiry = revocation_params.credential_expiry;

        let issuance_date = extracted_credential
            .issued_at
            .ok_or(ServiceError::MappingError("issued_at is None".to_string()))?;

        if OffsetDateTime::now_utc() > issuance_date + expiry {
            let revocation = self
                .revocation_method_provider
                .get_revocation_method(&revocation_method)
                .ok_or(MissingProviderError::RevocationMethod(revocation_method))?;

            let lvvc = revocation::lvvc::create_lvvc_with_status(
                &credential,
                status,
                &self.core_base_url,
                expiry,
                formatter,
                self.lvvc_repository.clone(),
                self.key_provider.clone(),
                self.did_method_provider.clone(),
                revocation.get_json_ld_context()?,
            )
            .await?;

            let credential_content = std::str::from_utf8(&lvvc.credential)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?;

            return Ok(IssuerResponseDTO {
                credential: credential_content.to_string(),
                format,
            });
        }

        // Otherwise, return the current LVVC to holder.
        Ok(IssuerResponseDTO {
            credential: credential_content.to_string(),
            format,
        })
    }

    pub async fn get_revocation_list_by_id(
        &self,
        id: &RevocationListId,
    ) -> Result<String, ServiceError> {
        let result = self
            .revocation_list_repository
            .get_revocation_list(id, &RevocationListRelations::default())
            .await?;

        let Some(result) = result else {
            return Err(EntityNotFoundError::RevocationList(*id).into());
        };

        result.try_into()
    }
}
