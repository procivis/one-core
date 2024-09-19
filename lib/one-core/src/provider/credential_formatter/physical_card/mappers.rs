use std::collections::HashMap;

use super::model::{
    IdentityCard, OptiocalBarcodeCredential, TerseBitstringStatusListEntry,
    MRZ_CREDENTIAL_SUBJECT_TYPE,
};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::model::{LdCredential, LdCredentialSubject};
use crate::provider::credential_formatter::model::{
    CredentialSchema, CredentialStatus, CredentialSubject, DetailCredential,
};
use crate::provider::exchange_protocol::scan_to_verify::dto::ScanToVerifyCredentialDTO;

impl OptiocalBarcodeCredential {
    pub fn from_token(token: &str) -> Result<Self, FormatterError> {
        let input: ScanToVerifyCredentialDTO = serde_json::from_str(token).map_err(|e| {
            FormatterError::Failed(format!("Failed to extract input data from token: {e}"))
        })?;

        let schema: Result<_, FormatterError> = match input.schema_id.as_str() {
            "IdentityCard" | "UtopiaEmploymentDocument" => Ok(CredentialSchema {
                id: input.schema_id,
                r#type: "OpticalBarcodeCredential".to_string(),
                metadata: None,
            }),
            _ => Err(FormatterError::Failed(format!(
                "Unsupported schema, {}",
                input.schema_id
            ))),
        };

        let credential: LdCredential = serde_json::from_str(&input.credential).map_err(|e| {
            FormatterError::Failed(format!("Failed to deserialize credential: {e}"))
        })?;

        if !credential
            .r#type
            .contains(&"OpticalBarcodeCredential".to_string())
        {
            return Err(FormatterError::Failed(
                "Invalid credential type, expected `OpticalBarcodeCredential`".to_string(),
            ));
        }

        Ok(Self {
            schema: schema?,
            optical_data: ProtectedOpticalData::new_from_credential_subject(
                &credential.credential_subject[0],
                input.barcode,
            )?,
            credential,
        })
    }

    pub fn extract_claims(&self) -> Result<CredentialSubject, FormatterError> {
        match &self.optical_data {
            ProtectedOpticalData::Mrz(mrz) => {
                if let mrtd::Document::IdentityCard(mrz_fields) = mrtd::parse(mrz)
                    .map_err(|err| FormatterError::Failed(format!("Failed to decode MRZ: {err}")))?
                {
                    let claim_values = IdentityCard::try_from(mrz_fields)?;

                    let map = serde_json::to_value(claim_values)
                        .map_err(|err| {
                            FormatterError::Failed(format!("Failed to decode MRZ: {err}"))
                        })?
                        .as_object()
                        .ok_or(FormatterError::Failed(
                            "Failed to decode MRZ fields".to_string(),
                        ))?
                        .into_iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect();

                    Ok(CredentialSubject { values: map })
                } else {
                    Err(FormatterError::Failed("Unknown Barcode format".to_string()))
                }
            }
        }
    }

    pub fn extra_information_bytes(&self) -> Result<Vec<u8>, FormatterError> {
        match &self.optical_data {
            ProtectedOpticalData::Mrz(mrz) => {
                // https://w3c-ccg.github.io/vc-barcodes/#machinereadablezone-credentials
                let mrz_lines = mrz
                    .chars()
                    .collect::<Vec<_>>()
                    .chunks(30)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect::<Vec<_>>()
                    .join("\n");

                Ok(format!("{mrz_lines}\n").into_bytes())
            }
        }
    }
}

impl TryInto<DetailCredential> for OptiocalBarcodeCredential {
    type Error = FormatterError;

    fn try_into(self) -> Result<DetailCredential, Self::Error> {
        let credential_subject = self.extract_claims()?;

        let status: Result<Vec<CredentialStatus>, FormatterError> = self
            .credential
            .credential_status
            .into_iter()
            .try_fold(Vec::new(), |mut acc, status| {
                let entry: TerseBitstringStatusListEntry = status.try_into()?;
                let expanded = terse_bitstring_status_list_to_bitstring_status(entry, None)?;
                acc.extend(expanded);
                Ok(acc)
            });

        Ok(DetailCredential {
            id: self.credential.id.map(|url| url.to_string()),
            valid_from: self.credential.valid_from.or(self.credential.issuance_date),
            valid_until: None,
            update_at: None,
            invalid_before: None,
            issuer_did: Some(self.credential.issuer.to_did_value()),
            subject: None,
            claims: credential_subject,
            status: status?,
            credential_schema: Some(self.schema),
        })
    }
}

pub enum ProtectedOpticalData {
    Mrz(String),
}

impl ProtectedOpticalData {
    pub fn new_from_credential_subject(
        subject: &LdCredentialSubject,
        code: String,
    ) -> Result<Self, FormatterError> {
        let subject_type = subject
            .subject
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or(FormatterError::Failed("Missing subject type".to_string()))?;

        match subject_type {
            MRZ_CREDENTIAL_SUBJECT_TYPE => {
                // Remove all whitespaces and newlines, otherwise the MRZ parser will fail
                Ok(Self::Mrz(code.replace([' ', '\n', '\r'], "")))
            }
            _ => Err(FormatterError::Failed(format!(
                "Unsupported subject type: {}",
                subject_type
            ))),
        }
    }
}

impl TryFrom<CredentialStatus> for TerseBitstringStatusListEntry {
    type Error = FormatterError;
    fn try_from(status: CredentialStatus) -> Result<Self, Self::Error> {
        if status.r#type != "TerseBitstringStatusListEntry" {
            return Err(FormatterError::Failed("Invalid status type".to_string()));
        }

        let terse_status_list_index: usize = status
            .additional_fields
            .get("terseStatusListIndex")
            .and_then(|v| v.as_u64())
            .ok_or(FormatterError::Failed(
                "Missing status list index".to_string(),
            ))?
            .try_into()
            .map_err(|_| FormatterError::Failed("Invalid status list index".to_string()))?;

        let terse_status_list_base_url = status
            .additional_fields
            .get("terseStatusListBaseUrl")
            .and_then(|v| v.as_str())
            .ok_or(FormatterError::Failed(
                "Missing status list base url".to_string(),
            ))?
            .to_owned();

        Ok(Self {
            terse_status_list_index,
            terse_status_list_base_url,
        })
    }
}

pub fn terse_bitstring_status_list_to_bitstring_status(
    terse_bitstring_list: TerseBitstringStatusListEntry,
    status_purpose: Option<&str>,
) -> Result<Vec<CredentialStatus>, FormatterError> {
    // https://w3c-ccg.github.io/vc-barcodes/#tersebitstringstatuslistentry
    // implementations MUST use listLength = 2^17
    let list_length: usize = usize::pow(2, 17);

    // Set listIndex to vc.credentialStatus.terseStatusListIndex / listLength rounded down to the next lowest integer.
    let list_index = terse_bitstring_list.terse_status_list_index / list_length;
    // Set statusListIndex to vc.credentialStatus.terseStatusListIndex % listLength.
    let status_list_index = terse_bitstring_list.terse_status_list_index % list_length;

    let status_purpose = status_purpose
        .map(|s| vec![s])
        .unwrap_or(vec!["revocation", "suspension"]);

    status_purpose
        .iter()
        .map(|purpose| {
            let credential_url = format!(
                "{}/{purpose}/{list_index}",
                terse_bitstring_list.terse_status_list_base_url
            );
            Ok(CredentialStatus {
                id: None,
                r#type: "BitstringStatusListEntry".to_string(),
                status_purpose: Some(purpose.to_string()),
                additional_fields: HashMap::from([
                    (
                        "statusListIndex".to_string(),
                        status_list_index.to_string().into(),
                    ),
                    ("statusListCredential".to_string(), credential_url.into()),
                ]),
            })
        })
        .collect()
}
