use time::OffsetDateTime;
use x509_parser::error::X509Error;
use x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;
use x509_parser::prelude::{
    CRLDistributionPoint, CRLDistributionPoints, CertificateRevocationList, DistributionPointName,
    GeneralName, ParsedExtension, X509Certificate,
};

use super::{CertificateValidatorImpl, CrlMode, Error};
use crate::error::ErrorCodeMixinExt;
use crate::provider::caching_loader::CacheError;
use crate::provider::caching_loader::android_attestation_crl::CertificateStatus;

impl CertificateValidatorImpl {
    /// Returns `Ok` if not revoked, `Err(CertificateRevoked)` if certificate revoked,
    /// and other `Err` if checking fails for some reason
    pub(crate) async fn check_revocation(
        &self,
        certificate: &X509Certificate<'_>,
        parent: Option<&X509Certificate<'_>>,
        crl_mode: CrlMode,
    ) -> Result<(), Error> {
        match crl_mode {
            CrlMode::X509 => {
                let extension =
                    certificate.get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)?;

                if let Some(ParsedExtension::CRLDistributionPoints(crl)) =
                    extension.map(|extension| extension.parsed_extension())
                {
                    let downloaded_crl = self.download_crl_from_points(crl).await?;
                    if self.check_crl_revocation(&downloaded_crl, certificate, parent)? {
                        return Err(Error::CertificateRevoked);
                    }
                }
            }
            CrlMode::AndroidAttestation => {
                let crl = self
                    .android_attestation_crl_cache
                    .get()
                    .await
                    .map_err(|e| Error::CRLCheckFailed(e.to_string()))?;
                let entry_id = certificate.serial.to_str_radix(16).to_lowercase();
                let entry_status = crl.entries.get(&entry_id).map(|info| &info.status);
                if entry_status.is_some_and(|status| {
                    *status == CertificateStatus::Revoked || *status == CertificateStatus::Suspended
                }) {
                    return Err(Error::CertificateRevoked);
                }
            }
        }

        // OCSP support not implemented

        Ok(())
    }

    fn check_crl_revocation(
        &self,
        downloaded_crl: &[u8],
        certificate: &X509Certificate<'_>,
        parent: Option<&X509Certificate<'_>>,
    ) -> Result<bool, Error> {
        let (_, crl) = x509_parser::parse_x509_crl(downloaded_crl)?;

        if let Some(parent) = parent {
            self.check_crl_signature(&crl, parent)?;
        }

        // check CRL validity
        if crl.last_update().to_datetime() > OffsetDateTime::now_utc() {
            return Err(Error::CRLOutdated);
        }
        if crl
            .next_update()
            .is_some_and(|next_update| next_update.to_datetime() < OffsetDateTime::now_utc())
        {
            return Err(Error::CRLOutdated);
        }

        Ok(crl
            .iter_revoked_certificates()
            .any(|revoked| revoked.raw_serial() == certificate.raw_serial()))
    }

    fn check_crl_signature(
        &self,
        crl: &CertificateRevocationList<'_>,
        parent: &X509Certificate<'_>,
    ) -> Result<(), Error> {
        // check key usage
        let key_usage = parent
            .key_usage()
            .map_err(|e| Error::CRLCheckFailed(e.to_string()))?
            .ok_or(Error::CRLCheckFailed(
                "Parent CA cert key usage not found".to_string(),
            ))?;
        if !key_usage.value.crl_sign() {
            return Err(Error::CRLCheckFailed(
                "CRL signer certificate_validator key usage does not include crlSign".to_string(),
            ));
        }

        let Some(parent_cert_key_identifier) = parent.extensions().iter().find_map(|extension| {
            if let ParsedExtension::SubjectKeyIdentifier(key_identifier) =
                extension.parsed_extension()
            {
                Some(key_identifier)
            } else {
                None
            }
        }) else {
            return Err(Error::CRLCheckFailed(
                "Parent CA cert subject key identifier not found".to_string(),
            ));
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
            return Err(Error::CRLCheckFailed(
                "CRL authority key identifier not found".to_string(),
            ));
        };

        if crl_authority_key_identifier == parent_cert_key_identifier {
            crl.verify_signature(parent.public_key()).map_err(|err| {
                if err == X509Error::SignatureUnsupportedAlgorithm {
                    Error::CRLCheckFailed(err.to_string())
                } else {
                    Error::CRLSignatureInvalid
                }
            })?;
        } else {
            return Err(Error::CRLCheckFailed(
                "Parent CA key not matching CRL signer".to_string(),
            ));
        }

        Ok(())
    }

    async fn download_crl_from_points(
        &self,
        points: &CRLDistributionPoints<'_>,
    ) -> Result<Vec<u8>, Error> {
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

        Err(last_error.unwrap_or(Error::CRLCheckFailed(
            "No CRL download points found".to_string(),
        )))
    }

    async fn download_crl_from_point(
        &self,
        point: &CRLDistributionPoint<'_>,
    ) -> Result<Vec<u8>, Error> {
        let point: &DistributionPointName<'_> = point
            .distribution_point
            .as_ref()
            .ok_or(Error::CRLCheckFailed("no distribution point".to_string()))?;

        let DistributionPointName::FullName(name) = point else {
            return Err(Error::CRLCheckFailed(
                "CRL distribution point not a full-name".to_string(),
            ));
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
                    last_error = Some(err.error_while("fetching CRL").into());
                }
            };
        }

        Err(last_error.unwrap_or(Error::CRLCheckFailed("No CRL URI found".to_string())))
    }

    async fn download_crl(&self, uri: &str) -> Result<Vec<u8>, CacheError> {
        self.crl_cache.get(uri).await
    }
}
