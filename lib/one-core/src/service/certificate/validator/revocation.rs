use time::OffsetDateTime;
use x509_parser::error::X509Error;
use x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;
use x509_parser::prelude::{
    CRLDistributionPoint, CRLDistributionPoints, CertificateRevocationList, DistributionPointName,
    GeneralName, ParsedExtension, X509Certificate,
};

use super::CertificateValidatorImpl;
use crate::provider::caching_loader::{CachingLoaderError, ResolverError};
use crate::provider::revocation::error::RevocationError;
use crate::service::error::{ServiceError, ValidationError};

impl CertificateValidatorImpl {
    /// Returns `true` if certificate revoked, `false` if not revoked
    /// and `Err` if checking fails for some reason
    pub(super) async fn check_revocation(
        &self,
        certificate: &X509Certificate<'_>,
        parent: Option<&X509Certificate<'_>>,
    ) -> Result<bool, ServiceError> {
        let extension = certificate
            .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
            .map_err(|err| ValidationError::CRLCheckFailed(err.to_string()))?;

        if let Some(ParsedExtension::CRLDistributionPoints(crl)) =
            extension.map(|extension| extension.parsed_extension())
        {
            let downloaded_crl = self.download_crl_from_points(crl).await?;
            return self.check_crl_revocation(&downloaded_crl, certificate, parent);
        }

        // OCSP support not implemented

        Ok(false)
    }

    fn check_crl_revocation(
        &self,
        downloaded_crl: &[u8],
        certificate: &X509Certificate<'_>,
        parent: Option<&X509Certificate<'_>>,
    ) -> Result<bool, ServiceError> {
        let (_, crl) = x509_parser::parse_x509_crl(downloaded_crl)
            .map_err(|err| ValidationError::CRLCheckFailed(err.to_string()))?;

        if let Some(parent) = parent {
            self.check_crl_signature(&crl, parent)?;
        }

        // check CRL validity
        if crl.last_update().to_datetime() > OffsetDateTime::now_utc() {
            return Err(ValidationError::CRLOutdated.into());
        }
        if crl
            .next_update()
            .is_some_and(|next_update| next_update.to_datetime() < OffsetDateTime::now_utc())
        {
            return Err(ValidationError::CRLOutdated.into());
        }

        Ok(crl
            .iter_revoked_certificates()
            .any(|revoked| revoked.raw_serial() == certificate.raw_serial()))
    }

    fn check_crl_signature(
        &self,
        crl: &CertificateRevocationList<'_>,
        parent: &X509Certificate<'_>,
    ) -> Result<(), ServiceError> {
        let Some(parent_cert_key_identifier) = parent.extensions().iter().find_map(|extension| {
            if let ParsedExtension::SubjectKeyIdentifier(key_identifier) =
                extension.parsed_extension()
            {
                Some(key_identifier)
            } else {
                None
            }
        }) else {
            return Err(ValidationError::CRLCheckFailed(
                "Parent CA cert subject key identifier not found".to_string(),
            )
            .into());
        };

        // check key usage
        if let Ok(Some(key_usage)) = parent.key_usage() {
            if !key_usage.value.crl_sign() {
                return Err(ValidationError::CRLCheckFailed(
                    "CRL signer certificate key usage does not include crlSign".to_string(),
                )
                .into());
            }
        } else {
            return Err(ValidationError::CRLCheckFailed(
                "Parent CA cert key usage not found".to_string(),
            )
            .into());
        };

        let Some(crl_authority_key_identifier) = crl.extensions().iter().find_map(|extension| {
            if let ParsedExtension::AuthorityKeyIdentifier(key_identifier) =
                extension.parsed_extension()
            {
                key_identifier.key_identifier.as_ref()
            } else {
                None
            }
        }) else {
            return Err(ValidationError::CRLCheckFailed(
                "CRL authority key identifier not found".to_string(),
            )
            .into());
        };

        if crl_authority_key_identifier == parent_cert_key_identifier {
            crl.verify_signature(parent.public_key()).map_err(|err| {
                if err == X509Error::SignatureUnsupportedAlgorithm {
                    ValidationError::CRLCheckFailed(err.to_string())
                } else {
                    ValidationError::CRLSignatureInvalid
                }
            })?;
        } else {
            return Err(ValidationError::CRLCheckFailed(
                "Parent CA key not matching CRL signer".to_string(),
            )
            .into());
        }

        Ok(())
    }

    async fn download_crl_from_points(
        &self,
        points: &CRLDistributionPoints<'_>,
    ) -> Result<Vec<u8>, ServiceError> {
        let mut last_error = None;
        for point in &points.points {
            match self.download_crl_from_point(point).await {
                Ok(crl) => {
                    return Ok(crl);
                }
                Err(err) => {
                    last_error = Some(err);
                }
            };
        }

        Err(last_error.unwrap_or(
            ValidationError::CRLCheckFailed("No CRL download points found".to_string()).into(),
        ))
    }

    async fn download_crl_from_point(
        &self,
        point: &CRLDistributionPoint<'_>,
    ) -> Result<Vec<u8>, ServiceError> {
        let point: &DistributionPointName<'_> =
            point
                .distribution_point
                .as_ref()
                .ok_or(ValidationError::CRLCheckFailed(
                    "no distribution point".to_string(),
                ))?;

        let DistributionPointName::FullName(name) = point else {
            return Err(ValidationError::CRLCheckFailed(
                "CRL distribution point not a full-name".to_string(),
            )
            .into());
        };

        let mut last_error = None;
        for name in name {
            let GeneralName::URI(uri) = name else {
                continue;
            };

            match self.download_crl(uri).await {
                Ok(crl) => {
                    return Ok(crl);
                }
                Err(err) => {
                    last_error = Some(err.into());
                }
            };
        }

        Err(last_error
            .unwrap_or(ValidationError::CRLCheckFailed("No CRL URI found".to_string()).into()))
    }

    async fn download_crl(&self, uri: &str) -> Result<Vec<u8>, RevocationError> {
        self.crl_cache.get(uri).await.map_err(|_err| {
            RevocationError::ResolverError(ResolverError::CachingLoader(
                CachingLoaderError::UnexpectedResolveResult,
            ))
        })
    }
}
