use crate::error::ContextWithErrorCode;
use crate::mapper::x509::der_chain_into_pem_chain;
use crate::proto::http_client::HttpClient;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::util::Bstr;

/// Resolves the certificate (chain) referenced by the `x5u` header parameter
/// (IETF RFC 7515 clause 4.1.5 for JOSE, IETF RFC 9360 for COSE). ETSI TS 119 472-1
/// requires QEAA/PuB-EAA to make their signing certificate available this way
/// (QEAA-5.6.2-02, QEAA-6.6.2-02).
///
/// # Returns
/// The referenced resource as a PEM-encoded certificate chain, leaf first.
pub async fn resolve_x5u(
    url: &str,
    http_client: &dyn HttpClient,
) -> Result<String, FormatterError> {
    let response = async {
        http_client
            .get(url)
            .header(
                "Accept",
                "application/pem-certificate-chain, application/x-pem-file, application/cose-x509",
            )
            .send()
            .await?
            .error_for_status()
    }
    .await
    .error_while("fetching x5u certificate")?;

    let content_type = response.header_get("content-type");
    match content_type {
        Some(content_type) if content_type.contains("application/cose-x509") => {
            let cbor: Vec<Bstr> = ciborium::from_reader(response.body.as_slice())?;
            let der_chain = cbor.into_iter().map(|bstr| bstr.0).collect();
            return Ok(der_chain_into_pem_chain(der_chain));
        }
        Some(content_type)
            if content_type.contains("application/pem-certificate-chain")
                || content_type.contains("application/x-pem-file") =>
        {
            // recognized PEM chain - proceed
        }
        Some(unknown_content_type) => {
            tracing::warn!("x5u: unknown Content-Type provided: `{unknown_content_type}`");
            // try fallback to PEM
        }
        None => {
            tracing::warn!("x5u: no Content-Type provided");
            // try fallback to PEM
        }
    };

    String::from_utf8(response.body).map_err(|e| {
        FormatterError::CouldNotExtractCredentials(format!("x5u response is not valid PEM: {e}"))
    })
}

#[cfg(test)]
#[derive(Clone)]
pub struct MockAuth<F: Fn(&[u8]) -> Vec<u8> + Send + Sync>(pub F);

#[cfg(test)]
pub use crate::config::core_config::KeyAlgorithmType;
#[cfg(test)]
pub use crate::provider::credential_formatter::model::SignatureProvider;
#[cfg(test)]
pub use crate::provider::key_algorithm::error::KeyAlgorithmError;

#[cfg(test)]
#[async_trait::async_trait]
impl<F: Fn(&[u8]) -> Vec<u8> + Send + Sync> SignatureProvider for MockAuth<F> {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(self.0(message))
    }

    fn get_key_id(&self) -> Option<String> {
        Some("#key0".to_owned())
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, KeyAlgorithmError> {
        Ok(KeyAlgorithmType::Ecdsa)
    }

    fn jose_alg(&self) -> Result<String, KeyAlgorithmError> {
        Ok("ES256".to_owned())
    }

    fn get_public_key(&self) -> Vec<u8> {
        vec![]
    }
}
