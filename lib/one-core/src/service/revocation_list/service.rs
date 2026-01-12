use anyhow::Context;
use shared_types::{CredentialId, RevocationListId};
use time::OffsetDateTime;

use super::dto::RevocationListResponseDTO;
use crate::model::credential::CredentialRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::DidRelations;
use crate::model::identifier::{IdentifierRelations, IdentifierType};
use crate::model::key::KeyRelations;
use crate::model::revocation_list::RevocationListRelations;
use crate::model::validity_credential::{Lvvc, ValidityCredentialType};
use crate::proto::bearer_token::validate_bearer_token;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::revocation::lvvc::create_lvvc_with_status;
use crate::provider::revocation::lvvc::dto::{IssuerResponseDTO, LvvcStatus};
use crate::provider::revocation::lvvc::mapper::status_from_lvvc_claims;
use crate::service::error::{EntityNotFoundError, MissingProviderError, ServiceError};
use crate::service::revocation_list::RevocationListService;

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
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        key: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?
            .ok_or(EntityNotFoundError::Credential(*id))?;

        // In the next step the latest LVVC credential should be obtained from the asked-for credential
        let latest_lvvc = self
            .lvvc_repository
            .get_latest_by_credential_id(id.to_owned(), ValidityCredentialType::Lvvc)
            .await
            .map_err(ServiceError::from)?
            .ok_or(EntityNotFoundError::Lvvc(*id))?;

        let credential_content = std::str::from_utf8(&latest_lvvc.credential)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        let schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let revocation_method = schema.revocation_method.to_string();
        let revocation_params: crate::provider::revocation::lvvc::Params =
            self.config.revocation.get(&revocation_method)?;

        let jwt = validate_bearer_token(
            bearer_token,
            self.did_method_provider.clone(),
            self.key_algorithm_provider.clone(),
            self.certificate_validator.clone(),
            revocation_params.leeway,
        )
        .await?;

        let holder_identifier =
            credential
                .holder_identifier
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "holder_identifier is None".to_string(),
                ))?;

        // validate JWT token was signed with the holder identifier
        match holder_identifier.r#type {
            IdentifierType::Key => {
                let holder_key = holder_identifier
                    .key
                    .as_ref()
                    .ok_or(ServiceError::MappingError("holder_did is None".to_string()))?;

                let token_issuer_key = jwt.header.jwk.ok_or(ServiceError::ValidationError(
                    "Missing token jwk".to_owned(),
                ))?;

                let (alg_type, key_algorithm) = self
                    .key_algorithm_provider
                    .key_algorithm_from_jose_alg(&jwt.header.algorithm)
                    .ok_or(MissingProviderError::KeyAlgorithmProvider(
                        KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                            jwt.header.algorithm,
                        ),
                    ))?;

                let token_issuer_key = key_algorithm.parse_jwk(&token_issuer_key)?;

                if holder_key.key_type != alg_type.to_string()
                    || holder_key.public_key != token_issuer_key.public_key_as_raw()
                {
                    return Err(ServiceError::MappingError(
                        "holder_key mismatch".to_string(),
                    ));
                }
            }
            IdentifierType::Did => {
                let token_issuer = jwt.payload.issuer.ok_or(ServiceError::ValidationError(
                    "Missing token issuer".to_owned(),
                ))?;
                let holder_did = holder_identifier
                    .did
                    .as_ref()
                    .ok_or(ServiceError::MappingError("holder_did is None".to_string()))?;
                if holder_did.did
                    != token_issuer
                        .parse()
                        .context("did parsing error")
                        .map_err(|e| ServiceError::MappingError(e.to_string()))?
                {
                    return Err(ServiceError::MappingError(
                        "holder_did mismatch".to_string(),
                    ));
                }
            }
            IdentifierType::Certificate => {
                return Err(ServiceError::MappingError(
                    "Invalid holder identifier".to_string(),
                ));
            }
        };

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&schema.format)
            .ok_or(ServiceError::MissingProvider(
                MissingProviderError::Formatter(schema.format.to_string()),
            ))?;

        let extracted_credential = formatter
            .extract_credentials_unverified(credential_content, Some(schema))
            .await
            .map_err(ServiceError::from)?;

        let status = status_from_lvvc_claims(&extracted_credential.claims.claims)?;
        match status {
            // ONE-1780: return current lvvc credential if not active
            LvvcStatus::Revoked | LvvcStatus::Suspended { .. } => {
                return Ok(IssuerResponseDTO {
                    credential: credential_content.to_string(),
                });
            }
            LvvcStatus::Accepted => {}
        }

        // If issuanceDate + minimumRefreshTime < now then a new VC of the LVVC credential needs to be created and saved in database.
        let issuance_date = extracted_credential
            .valid_from
            .ok_or(ServiceError::MappingError("issued_at is None".to_string()))?;

        if OffsetDateTime::now_utc() > issuance_date + revocation_params.minimum_refresh_time {
            let revocation = self
                .revocation_method_provider
                .get_revocation_method(&revocation_method)
                .ok_or(MissingProviderError::RevocationMethod(revocation_method))?;

            let lvvc: Lvvc = create_lvvc_with_status(
                &credential,
                status,
                &self.core_base_url,
                revocation_params.credential_expiry,
                formatter,
                self.key_provider.clone(),
                self.key_algorithm_provider.clone(),
                revocation.get_json_ld_context()?,
            )
            .await?
            .into();

            let credential_content = std::str::from_utf8(&lvvc.credential)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?
                .to_string();

            self.lvvc_repository.insert(lvvc.into()).await?;

            return Ok(IssuerResponseDTO {
                credential: credential_content,
            });
        }

        // Otherwise, return the current LVVC to holder.
        Ok(IssuerResponseDTO {
            credential: credential_content.to_string(),
        })
    }

    pub async fn get_revocation_list_by_id(
        &self,
        id: &RevocationListId,
    ) -> Result<RevocationListResponseDTO, ServiceError> {
        let result = self
            .revocation_list_repository
            .get_revocation_list(id, &RevocationListRelations::default())
            .await?;

        let Some(list) = result else {
            return Err(EntityNotFoundError::RevocationList(*id).into());
        };

        Ok(RevocationListResponseDTO {
            revocation_list: list.get_status_credential()?,
            format: list.format,
            r#type: list.r#type,
        })
    }
}
