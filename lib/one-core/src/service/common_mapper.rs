use ct_codecs::{Base64, Decoder};
use standardized_types::etsi_119_475::registration_certificate::{Payload, SupervisoryAuthority};

use crate::model::list_filter::ListFilterCondition;
use crate::model::list_query::{ListPagination, ListQuery, ListSorting};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::trust_information::dto::{TrustDetails, WalletRelyingPartyDetails};
use crate::proto::wrp_validator::model::WRPPayload;
use crate::provider::ecosystem::model::TrustDetail;
use crate::service::common_dto::{
    BoundedB64Image, EudiIntermediaryResponseDTO, EudiTrustInformationResponseDTO, ListQueryDTO,
    TrustInformationDetailResponseEnum,
};
use crate::service::error::{ServiceError, ValidationError};
use crate::util::access_cert_parser::EtsiParsedAccessCert;

impl<const MAX: usize> TryFrom<String> for BoundedB64Image<MAX> {
    type Error = ValidationError;

    fn try_from(img: String) -> Result<Self, Self::Error> {
        let mut splits = img.splitn(2, ',');
        match splits.next() {
            Some("data:image/png;base64") | Some("data:image/jpeg;base64") => {}
            Some(data) => {
                return Err(ValidationError::InvalidImage(format!(
                    "Invalid mime type: {data}"
                )));
            }
            None => {
                return Err(ValidationError::InvalidImage(
                    "Missing mime type".to_owned(),
                ));
            }
        };
        let Some(base64) = splits.next() else {
            return Err(ValidationError::InvalidImage(
                "Missing base64 data".to_string(),
            ));
        };
        let mut buf = vec![0; MAX];
        // Decode will fail if data is longer than `buf` (`MAX` bytes)
        Base64::decode(buf.as_mut_slice(), base64, None).map_err(|err| {
            ValidationError::InvalidImage(format!("Failed to decode base64 data: {err}"))
        })?;
        Ok(BoundedB64Image(img))
    }
}
impl<const MAX: usize> From<BoundedB64Image<MAX>> for String {
    fn from(value: BoundedB64Image<MAX>) -> Self {
        value.0
    }
}

impl<Sorting, FilterDTO, Filter, Include> From<ListQueryDTO<Sorting, FilterDTO, Include>>
    for ListQuery<Sorting, Filter, Include>
where
    FilterDTO: Into<ListFilterCondition<Filter>>,
{
    fn from(value: ListQueryDTO<Sorting, FilterDTO, Include>) -> Self {
        Self {
            pagination: Some(ListPagination {
                page: value.page,
                page_size: value.page_size,
            }),
            sorting: value.sort.map(|column| ListSorting {
                column,
                direction: value.sort_direction,
            }),
            filtering: Some(value.filter.into()),
            include: value.include,
        }
    }
}

impl TryFrom<TrustDetails> for EudiTrustInformationResponseDTO {
    type Error = ServiceError;

    fn try_from(value: TrustDetails) -> Result<Self, Self::Error> {
        let trust_detail = match value {
            TrustDetails::Etsi {
                access_certificate,
                wrp,
            } => {
                let (eudi_ecosystem, has_intermediary) = match wrp {
                    WalletRelyingPartyDetails::RegistrationCertificate(reg_cert) => {
                        map_reg_cert(reg_cert)?
                    }
                    WalletRelyingPartyDetails::NationalRegistryInfo(national_registry_info) => {
                        map_national_registry_info(national_registry_info)?
                    }
                };
                let (intermediary, email, phone) =
                    map_access_cert(access_certificate, has_intermediary);
                EudiTrustInformationResponseDTO {
                    intermediary,
                    email,
                    phone,
                    ..eudi_ecosystem
                }
            }
        };
        Ok(trust_detail)
    }
}

impl From<TrustDetail> for TrustInformationDetailResponseEnum {
    fn from(value: TrustDetail) -> Self {
        match value {
            TrustDetail::Eudi(detail) => Self::Eudi(detail),
        }
    }
}

fn map_reg_cert(
    reg_cert: JWTPayload<Payload>,
) -> Result<(EudiTrustInformationResponseDTO, bool), ServiceError> {
    Ok((
        EudiTrustInformationResponseDTO {
            name: reg_cert.custom.name,
            website: reg_cert.custom.support_uri,
            email: None,
            phone: None,
            country: reg_cert.custom.country,
            identifier: reg_cert.subject.ok_or(ServiceError::MappingError(
                "Missing registration certificate subject".to_string(),
            ))?,
            service_description: reg_cert
                .custom
                .service_descriptions
                .into_iter()
                .map(|langs| {
                    langs
                        .into_iter()
                        .map(|lang| (lang.lang, lang.value))
                        .collect()
                })
                .collect(),
            supervisory_authority: reg_cert.custom.supervisory_authority,
            intermediary: None,
            is_public_sector: reg_cert.custom.public_body.unwrap_or_default(),
        },
        reg_cert.custom.intermediary.is_some(),
    ))
}

fn map_national_registry_info(
    national_registry_info: JWTPayload<WRPPayload>,
) -> Result<(EudiTrustInformationResponseDTO, bool), ServiceError> {
    let data = national_registry_info.custom.data;
    Ok((
        EudiTrustInformationResponseDTO {
            name: data
                .trade_name
                .ok_or(ServiceError::MappingError("Missing trade name".to_string()))?,
            website: data
                .support_uri
                .into_iter()
                .next()
                .ok_or(ServiceError::MappingError("Empty support uri".to_string()))?,
            email: data.email.into_iter().next(),
            phone: data.phone.into_iter().next(),
            country: data.country,
            identifier: national_registry_info
                .subject
                .ok_or(ServiceError::MappingError(
                    "Missing registration certificate subject".to_string(),
                ))?,
            service_description: vec![
                data.srv_description
                    .into_iter()
                    .map(|lang| (lang.lang, lang.content))
                    .collect(),
            ],
            supervisory_authority: SupervisoryAuthority {
                email: data.supervisory_authority.email.into_iter().next().ok_or(
                    ServiceError::MappingError("Empty supervisor authority email".to_string()),
                )?,
                phone: data.supervisory_authority.phone.into_iter().next().ok_or(
                    ServiceError::MappingError("Empty supervisor authority phone".to_string()),
                )?,
                uri: data
                    .supervisory_authority
                    .info_uri
                    .into_iter()
                    .next()
                    .ok_or(ServiceError::MappingError(
                        "Empty supervisor authority info_uri".to_string(),
                    ))?,
            },
            intermediary: None,
            is_public_sector: data.is_psb.unwrap_or_default(),
        },
        data.uses_intermediary
            .is_some_and(|intermediaries| !intermediaries.is_empty()),
    ))
}

fn map_access_cert(
    access_certificate: EtsiParsedAccessCert,
    has_intermediary: bool,
) -> (
    Option<EudiIntermediaryResponseDTO>,
    Option<String>,
    Option<String>,
) {
    if has_intermediary {
        (
            Some(EudiIntermediaryResponseDTO {
                name: access_certificate.common_name,
                identifier: access_certificate.rp_id,
                website: access_certificate.support_uri.clone(),
                email: access_certificate.email,
                phone: access_certificate.phone,
                country: access_certificate.country,
            }),
            None,
            None,
        )
    } else {
        (None, access_certificate.email, access_certificate.phone)
    }
}

#[cfg(test)]
mod test {
    use ct_codecs::{Base64, Encoder};

    use super::BoundedB64Image;
    use crate::service::error::ValidationError;

    #[test]
    fn test_bounded_base64_image() {
        let data = vec![0; 10];
        let data_str = format!(
            "data:image/png;base64,{}",
            Base64::encode_to_string(&data).unwrap()
        );
        let result = BoundedB64Image::<10>::try_from(data_str.clone());
        assert!(result.is_ok());

        let result = BoundedB64Image::<9>::try_from(data_str);
        assert!(matches!(result, Err(ValidationError::InvalidImage(_))));

        let result =
            BoundedB64Image::<10>::try_from("data:image/png;base64,NÖT_BÄSE64".to_string());
        assert!(matches!(result, Err(ValidationError::InvalidImage(_))));

        let result = BoundedB64Image::<10>::try_from(format!(
            "data:image/gif;base64,{}", // unsupported mime type
            Base64::encode_to_string(&data).unwrap()
        ));
        assert!(matches!(result, Err(ValidationError::InvalidImage(_))));
    }
}
