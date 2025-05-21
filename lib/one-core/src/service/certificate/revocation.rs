use time::OffsetDateTime;
use x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;
use x509_parser::prelude::{
    CRLDistributionPoint, CRLDistributionPoints, DistributionPointName, GeneralName,
    ParsedExtension, X509Certificate,
};

use super::CertificateService;
use crate::provider::revocation::error::RevocationError;
use crate::service::error::{ServiceError, ValidationError};

impl CertificateService {
    /// Returns `true` if certificate revoked, `false` if not revoked
    /// and `Err` if checking fails for some reason
    pub(super) async fn check_revocation(
        &self,
        certificate: &X509Certificate<'_>,
        parent: Option<&X509Certificate<'_>>,
    ) -> Result<bool, ServiceError> {
        let extension = certificate
            .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        if let Some(ParsedExtension::CRLDistributionPoints(crl)) =
            extension.map(|extension| extension.parsed_extension())
        {
            let downloaded_crl = self.download_crl_from_points(crl).await?;
            return self.check_crl_revocation(&downloaded_crl, certificate, parent);
        }

        // TODO: support for OCSP

        Ok(false)
    }

    fn check_crl_revocation(
        &self,
        downloaded_crl: &[u8],
        certificate: &X509Certificate<'_>,
        _parent: Option<&X509Certificate<'_>>,
    ) -> Result<bool, ServiceError> {
        let (_, crl) = x509_parser::parse_x509_crl(downloaded_crl)
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        // TODO: check signature of the CRL
        // our current CA produces CRLs with P256-SHA512 signatures that are not usual and not supported by ring
        //  if let Some(parent) = parent {
        //      crl.verify_signature(parent.public_key())
        //          .map_err(|_| ValidationError::CertificateSignatureInvalid)?;
        //  }

        // check CRL validity
        if crl.last_update().to_datetime() > OffsetDateTime::now_utc() {
            return Err(ValidationError::CertificateNotValid.into());
        }
        if crl
            .next_update()
            .is_some_and(|next_update| next_update.to_datetime() < OffsetDateTime::now_utc())
        {
            return Err(ValidationError::CertificateNotValid.into());
        }

        Ok(crl
            .iter_revoked_certificates()
            .any(|revoked| revoked.raw_serial() == certificate.raw_serial()))
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
            ValidationError::CertificateParsingFailed("No CRL download points found".to_string())
                .into(),
        ))
    }

    async fn download_crl_from_point(
        &self,
        point: &CRLDistributionPoint<'_>,
    ) -> Result<Vec<u8>, ServiceError> {
        let point =
            point
                .distribution_point
                .as_ref()
                .ok_or(ValidationError::CertificateParsingFailed(
                    "no distribution point".to_string(),
                ))?;

        let DistributionPointName::FullName(name) = point else {
            return Err(ValidationError::CertificateParsingFailed(
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

        Err(last_error.unwrap_or(
            ValidationError::CertificateParsingFailed("No CRL URI found".to_string()).into(),
        ))
    }

    async fn download_crl(&self, uri: &str) -> Result<Vec<u8>, RevocationError> {
        Ok(self.client.get(uri).send().await?.error_for_status()?.body)
    }
}
