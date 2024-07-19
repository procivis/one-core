use dto_mapper::From;
use dto_mapper::TryFrom;
use one_providers::credential_formatter::error::FormatterError;
use one_providers::credential_formatter::imp::json_ld::model::LdCredential;
use one_providers::credential_formatter::model::CredentialSchema;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Iso8601;
use time::OffsetDateTime;

use super::mappers::ProtectedOpticalData;

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

    #[try_from(with_fn = "iso_8601_to_offset_datetime")]
    #[serde(rename = "Date of Birth")]
    pub birth_date: String,

    #[try_from(infallible)]
    #[serde(rename = "Gender")]
    pub gender: Gender,

    #[serde(rename = "Date of Expiry")]
    #[try_from(with_fn = "iso_8601_to_offset_datetime")]
    pub expiry_date: String,
}

fn iso_8601_to_offset_datetime<T>(date: T) -> Result<String, FormatterError>
where
    T: ToString,
{
    time::Date::parse(&date.to_string(), &Iso8601::DEFAULT)
        .map_err(|e| {
            FormatterError::CouldNotExtractCredentials(format!("Failed to parse date: {}", e))
        })
        .map(|d| OffsetDateTime::new_utc(d, time::Time::MIDNIGHT).to_string())
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