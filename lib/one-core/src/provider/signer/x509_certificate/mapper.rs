use rcgen::CertificateSigningRequestParams;

use crate::provider::signer::dto::CreateSignatureRequest;
use crate::provider::signer::error::SignerError;
use crate::provider::signer::x509_certificate::RequestData;

pub(super) fn params_from_request(
    request: CreateSignatureRequest,
) -> Result<CertificateSigningRequestParams, SignerError> {
    let request_data: RequestData = serde_json::from_value(request.data)?;
    CertificateSigningRequestParams::from_pem(&request_data.csr)
        .map_err(|e| SignerError::InvalidPayload(Box::new(e)))
}
