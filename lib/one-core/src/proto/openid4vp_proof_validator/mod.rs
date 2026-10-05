use shared_types::CredentialId;
use standardized_types::openid4vp::DirectPostResponse;

use crate::config::core_config::VerificationProtocolType;
use crate::model::claim::Claim;
use crate::model::proof::Proof;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPVerifierInteractionContent, ProvedCredential, SubmissionRequestData,
};

pub mod validated_proof_result;
pub mod validator;

#[cfg(test)]
mod test;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait OpenId4VpProofValidator: Send + Sync {
    async fn validate_submission(
        &self,
        request: SubmissionRequestData,
        proof: Proof,
        interaction_data: OpenID4VPVerifierInteractionContent,
        protocol_type: VerificationProtocolType,
    ) -> Result<(ValidatedProofResult, DirectPostResponse), OpenID4VCError>;
}

#[derive(Debug)]
pub(crate) struct ValidatedProofResult {
    pub proved_credentials: Vec<ProvedCredential>,
    pub proved_claims: Vec<ProvedClaim>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProvedClaim {
    pub credential_id: CredentialId,
    pub claim: Claim,
}
