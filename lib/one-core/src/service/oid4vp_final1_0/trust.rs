use shared_types::OrganisationId;
use uuid::Uuid;

use super::OID4VPFinal1_0Service;
use super::error::OID4VPFinal1_0ServiceError;
use crate::config::core_config::FormatType;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    TrustResolutionMetadata, TrustResolutionResult,
};
use crate::model::proof::Proof;
use crate::proto::openid4vp_proof_validator::ValidatedProofResult;
use crate::proto::session_provider::SessionExt;
use crate::proto::wrp_validator::credential_category;
use crate::proto::wrp_validator::model::TrustMode;
use crate::provider::credential_formatter::model::{
    CertificateDetails, IdentifierDetails, X5References,
};
use crate::provider::trust_list_subscriber::TrustEntityResponse;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::model::ProvedCredential;

impl OID4VPFinal1_0Service {
    pub(super) async fn verify_trust(
        &self,
        proof: &Proof,
        proof_result: &ValidatedProofResult,
    ) -> Result<(), OID4VPFinal1_0ServiceError> {
        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(OID4VPFinal1_0ServiceError::MappingError(
                "missing proof schema".to_string(),
            ))?
            .as_ref()
            .await?;
        let organisation_id = proof_schema.organisation.id();

        let trust_mode = self
            .wrp_validator
            .verifier_trust_mode(organisation_id)
            .await
            .error_while("getting verifier trust mode")?;

        let history_template = History {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            action: HistoryAction::TrustResolved,
            name: proof_schema.name.to_owned(),
            target: None,
            source: HistorySource::Core,
            entity_id: Some(proof.id.into()),
            entity_type: HistoryEntityType::Proof,
            metadata: None,
            metadata_blob_id: None,
            organisation_id: Some(organisation_id),
            user: self.session_provider.session().user(),
        };

        let all_credentials_trusted = self
            .resolve_trust(proof_result, organisation_id, trust_mode, history_template)
            .await?;

        if !all_credentials_trusted && trust_mode == TrustMode::TrustMandatory {
            return Err(VerificationProtocolError::Untrusted
                .error_while("validating trust")
                .into());
        }

        Ok(())
    }

    /// Returns `true` if all proved credentials trusted (meaning no unknown or untrusted)
    async fn resolve_trust(
        &self,
        proof_result: &ValidatedProofResult,
        organisation_id: OrganisationId,
        trust_mode: TrustMode,
        history_template: History,
    ) -> Result<bool, OID4VPFinal1_0ServiceError> {
        let mut all_credentials_trusted = true;

        for credential in &proof_result.proved_credentials {
            let trust_resolution = match trust_mode {
                TrustMode::Disabled => TrustResolutionResult::Unknown,
                _ => {
                    match self
                        .resolve_credential_trust(credential, organisation_id)
                        .await
                    {
                        Ok(Some(_trust_entity)) => TrustResolutionResult::Trusted,
                        Ok(None) => TrustResolutionResult::Unknown,
                        Err(err) => {
                            tracing::info!(%err, "Credential issuer untrusted");
                            TrustResolutionResult::Untrusted
                        }
                    }
                }
            };

            self.history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    target: Some(credential.credential.id.to_string()),
                    metadata: Some(HistoryMetadata::TrustResolution(TrustResolutionMetadata {
                        result: trust_resolution,
                    })),
                    ..history_template.to_owned()
                })
                .await
                .error_while("storing history")?;

            if all_credentials_trusted && trust_resolution != TrustResolutionResult::Trusted {
                all_credentials_trusted = false;
            }
        }

        Ok(all_credentials_trusted)
    }

    async fn resolve_credential_trust(
        &self,
        credential: &ProvedCredential,
        organisation_id: OrganisationId,
    ) -> Result<Option<TrustEntityResponse>, OID4VPFinal1_0ServiceError> {
        let credential_schema = credential.credential.schema.as_ref().await?;

        let (issuer_certificate_pem_chain, issuer_x5_references) = match &credential.issuer_details
        {
            IdentifierDetails::Certificate(CertificateDetails {
                chain,
                x5_references,
                ..
            }) => (Some(chain.as_str()), *x5_references),
            _ => (None, X5References::default()),
        };

        let namespaced = self
            .config
            .format
            .get_fields(&credential_schema.format().await?)
            .error_while("getting format config")?
            .r#type
            == FormatType::Mdoc;

        let claims = credential.credential.claims.as_ref().await?;
        let category = credential_category(&claims, namespaced);

        Ok(self
            .wrp_validator
            .validate_credential_issuer(
                issuer_certificate_pem_chain,
                &credential_schema,
                category,
                issuer_x5_references,
                organisation_id,
            )
            .await
            .error_while("validating credential issuer")?)
    }
}
