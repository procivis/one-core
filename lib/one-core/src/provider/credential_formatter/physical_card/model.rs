use one_dto_mapper::{From, TryFrom};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::{Iso8601, Rfc3339};
use time::OffsetDateTime;

use super::mappers::ProtectedOpticalData;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::model::LdCredential;
use crate::provider::credential_formatter::model::CredentialSchema;

pub const MRZ_CREDENTIAL_SUBJECT_TYPE: &str = "MachineReadableZone";

#[derive(Deserialize, Serialize, TryFrom)]
#[try_from(T = mrtd::IdentityCard, Error = FormatterError)]
pub struct IdentityCard {
    #[serde(rename = "Issuing Country")]
    /// Country (ISO 3166-1 code)
    #[try_from(infallible)]
    pub country: String,

    #[try_from(infallible)]
    #[serde(rename = "Surname(s)")]
    pub surnames: Vec<String>,

    #[try_from(infallible)]
    #[serde(rename = "Given Name(s)")]
    pub given_names: Vec<String>,

    #[try_from(infallible)]
    #[serde(rename = "Document number")]
    pub document_number: String,

    /// Nationality (ISO 3166-1 code)
    #[try_from(infallible)]
    #[serde(rename = "Nationality")]
    pub nationality: String,

    #[try_from(with_fn = "iso_8601_date_to_rfc3339_datetime")]
    #[serde(rename = "Date of Birth")]
    pub birth_date: String,

    #[try_from(infallible)]
    #[serde(rename = "Gender")]
    pub gender: Gender,

    #[serde(rename = "Date of Expiry")]
    #[try_from(with_fn = "iso_8601_date_to_rfc3339_datetime")]
    pub expiry_date: String,
}

fn iso_8601_date_to_rfc3339_datetime<T>(date: T) -> Result<String, FormatterError>
where
    T: ToString,
{
    time::Date::parse(&date.to_string(), &Iso8601::DEFAULT)
        .map_err(|e| {
            FormatterError::CouldNotExtractCredentials(format!("Failed to parse date: {}", e))
        })
        .and_then(|d| {
            OffsetDateTime::new_utc(d, time::Time::MIDNIGHT)
                .format(&Rfc3339)
                .map_err(|e| {
                    FormatterError::CouldNotExtractCredentials(format!(
                        "Failed to format date: {}",
                        e
                    ))
                })
        })
}

#[derive(Deserialize, Serialize, From)]
#[from(mrtd::Gender)]
pub enum Gender {
    Male,
    Female,
    Other,
}

pub struct TerseBitstringStatusListEntry {
    pub terse_status_list_index: usize,
    pub terse_status_list_base_url: String,
}

pub struct OptiocalBarcodeCredential {
    pub schema: CredentialSchema,
    pub credential: LdCredential,
    pub optical_data: ProtectedOpticalData,
}
