use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::hash::Hash;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use error::TransactionDataError;
use proc_macros::provider_mock;
use processed_transaction_data::ProcessedTransactionData;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json_path::JsonPath;
use shared_types::TransactionDataType;
use standardized_types::openid4vp::dcql::CredentialQueryId;
use standardized_types::{iana, openid4vp};

use crate::config::core_config::FormatType;
use crate::provider::Provider;
use crate::provider::presentation_formatter::model::PresentedTransactionData;

pub(crate) mod decorators;
pub mod error;
pub(crate) mod processed_transaction_data;
pub(crate) mod provider;
pub(crate) mod qes_approval;
pub(crate) mod sca;

pub(crate) fn decode_transaction_data<T: DeserializeOwned>(
    transaction_data: &str,
) -> Result<T, TransactionDataError> {
    let data = Base64UrlSafeNoPadding::decode_to_vec(transaction_data, None)?;
    Ok(serde_json::from_slice(&data)?)
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransactionDataMetadata {
    pub credential_ids: Vec<CredentialQueryId>,
}

/// Outcome of checking presented evidence against a `transaction_data` entry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionDataAuthorization {
    Authorized,
    NotAuthorized,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDataCapabilities {
    pub transaction_data_types: Vec<String>,
    /// Credential formats the transaction data can be bound to
    pub formats: Vec<FormatType>,
    pub features: Vec<Features>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Features {
    SupportsMultipleTxDataPerPresentation,
}

// Private params
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransactionDataParams {
    pub(crate) transaction_data_display_params: TransactionDataDisplayParams,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDataDisplayParams {
    /// Selects the displayed entries within the transaction data
    group_path: JsonPath,
    /// Selects an entry's title, relative to `group_path`, where entries have one
    title_path: Option<JsonPath>,
    /// An entry's attributes, relative to `group_path`
    attributes: Vec<TransactionDataDisplayParam>,
}

#[derive(Deserialize, Debug)]
pub struct TransactionDataDisplayParam {
    path: JsonPath,
    display: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TransactionDataDisplayValue {
    /// Absent where the entries carry no title of their own
    pub title: Option<String>,
    pub attributes: Vec<TransactionDataDisplayAttribute>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TransactionDataDisplayAttribute {
    pub key: String,
    pub value: String,
}

/// The hash algorithm for every entry a single credential authorizes. The entries share
/// one `transaction_data_hashes_alg` Key Binding JWT claim, so the chosen algorithm has
/// to be one they all offer.
pub(crate) fn agreed_hash_algorithm<'a>(
    transaction_data: impl IntoIterator<Item = &'a str>,
) -> Result<iana::HashAlgorithm, TransactionDataError> {
    let mut agreed: Option<Vec<iana::HashAlgorithm>> = None;
    for entry in transaction_data {
        let entry = decode_transaction_data::<openid4vp::TransactionData>(entry)?;
        let offered = entry
            .transaction_data_hashes_alg
            .as_deref()
            .unwrap_or(&[iana::HashAlgorithm::Sha256]);
        match &mut agreed {
            None => agreed = Some(offered.to_vec()),
            Some(agreed) => agreed.retain(|algorithm| offered.contains(algorithm)),
        }
    }
    let agreed = agreed.unwrap_or_default();

    // every implementation must support `sha-256`, so prefer it where the entries offer it
    if agreed.contains(&iana::HashAlgorithm::Sha256) {
        return Ok(iana::HashAlgorithm::Sha256);
    }

    agreed.into_iter().next().ok_or_else(|| {
        TransactionDataError::InvalidTransactionData(
            "transaction data entries of one credential offer no common hash algorithm".to_string(),
        )
    })
}

/// The `transaction_data` arguments are base64url-encoded OpenID4VP `transaction_data` entries.
#[provider_mock]
#[async_trait]
pub trait TransactionData: Provider + Send + Sync {
    /// Composes a `transaction_data` entry from verifier-provided type-specific content,
    /// validates it and returns it base64url-encoded for use in the authorization request.
    fn prepare_transaction_data(
        &self,
        credential_ids: Vec<CredentialQueryId>,
        data: Option<serde_json::Value>,
    ) -> Result<String, TransactionDataError>;
    fn validate_transaction_data(
        &self,
        transaction_data: &str,
    ) -> Result<TransactionDataMetadata, TransactionDataError>;
    /// Holder-side processing of an approved transaction; returns the fields to be
    /// merged into the presentation response of the credential authorizing it.
    /// May have side effects, e.g. calling out to external signing APIs.
    ///
    /// `hash_algorithm` comes from [`agreed_hash_algorithm`]. Types that do not hash
    /// their evidence per the OpenID4VP profile ignore it.
    async fn process_transaction_data(
        &self,
        transaction_data: &str,
        format: FormatType,
        hash_algorithm: iana::HashAlgorithm,
    ) -> Result<ProcessedTransactionData, TransactionDataError>;
    /// Verifier-side check whether the evidence presented by the holder authorizes this
    /// transaction data entry. Must not trigger the side effects of
    /// [`process_transaction_data`](Self::process_transaction_data).
    /// Evidence not matching the entry is [`TransactionDataAuthorization::NotAuthorized`],
    /// never an error; errors always denote a failure to perform the check.
    async fn verify_transaction_data(
        &self,
        transaction_data: &str,
        format: FormatType,
        presented: &PresentedTransactionData,
    ) -> Result<TransactionDataAuthorization, TransactionDataError>;
    fn get_capabilities(&self) -> TransactionDataCapabilities;
    fn config_name(&self) -> &TransactionDataType;
    fn display_params(&self) -> &TransactionDataDisplayParams;

    /// Grouped key-value data for displaying the transaction to the user
    fn get_display_data(
        &self,
        transaction_data: &str,
    ) -> Result<Vec<TransactionDataDisplayValue>, TransactionDataError> {
        let transaction_data: serde_json::Value = decode_transaction_data(transaction_data)?;
        let params = self.display_params();

        Ok(params
            .group_path
            .query(&transaction_data)
            .all()
            .into_iter()
            .map(|group| TransactionDataDisplayValue {
                title: params
                    .title_path
                    .as_ref()
                    .and_then(|title_path| title_path.query(group).first())
                    .and_then(|title| title.as_str())
                    .map(ToString::to_string),
                attributes: params
                    .attributes
                    .iter()
                    .flat_map(|param| {
                        let values = param
                            .path
                            .query(group)
                            .all()
                            .into_iter()
                            .filter_map(transaction_data_value_display);

                        values.map(|value| TransactionDataDisplayAttribute {
                            key: param.display.clone(),
                            value,
                        })
                    })
                    .collect(),
            })
            .collect())
    }
}

fn transaction_data_value_display(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.to_owned()),
        serde_json::Value::Null => Some("null".to_string()),
        serde_json::Value::Bool(value) => Some(format!("{value}")),
        serde_json::Value::Number(value) => Some(format!("{value}")),
        other => {
            tracing::warn!("Non-primitive display value: `{other}`");
            None
        }
    }
}

impl Display for dyn TransactionData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transaction data type `{}`", self.config_name())
    }
}

/// Gives each transaction data entry a credential of its own: a presentation
/// can only carry a single processed transaction data value of a conflicting type
/// (e.g. the `qesApproval` KB-JWT claim), so no credential may authorize two entries.
///
/// `applicable_credentials[i]` lists the credentials that may authorize entry `i`,
/// identified by anything the caller uses to distinguish them (a credential query id
/// or the index of a concrete presentation). Returns the chosen credential per entry,
/// or `None` if there is no way to give every entry its own credential.
pub(crate) fn assign_entries_to_distinct_credentials<Id: Clone + Eq + Hash>(
    applicable_credentials: &[Vec<Id>],
) -> Option<Vec<Id>> {
    // Tries to place `entry` on one of its applicable credentials: a free one
    // if available, otherwise a taken one whose current entry can itself be
    // moved to another credential, applying the same rule.
    // Returns true if successfully placed, false otherwise.
    fn place<Id: Clone + Eq + Hash>(
        entry: usize,
        applicable_credentials: &[Vec<Id>],
        authorized_entry: &mut HashMap<Id, usize>,
        considered: &mut HashSet<Id>,
    ) -> bool {
        let Some(candidates) = applicable_credentials.get(entry) else {
            return false;
        };
        for credential in candidates {
            if !considered.insert(credential.clone()) {
                continue;
            }
            let held_by = authorized_entry.get(credential).copied();
            if held_by.is_none_or(|holder| {
                place(holder, applicable_credentials, authorized_entry, considered)
            }) {
                authorized_entry.insert(credential.clone(), entry);
                return true;
            }
        }
        false
    }

    // per credential: the entry it ends up authorizing
    let mut authorized_entry = HashMap::new();
    for entry in 0..applicable_credentials.len() {
        if !place(
            entry,
            applicable_credentials,
            &mut authorized_entry,
            &mut HashSet::new(),
        ) {
            return None;
        }
    }

    let mut credential_per_entry: HashMap<usize, Id> = authorized_entry
        .into_iter()
        .map(|(credential, entry)| (entry, credential))
        .collect();
    (0..applicable_credentials.len())
        .map(|entry| credential_per_entry.remove(&entry))
        .collect()
}

#[cfg(test)]
mod test {
    use std::assert_matches;

    use ct_codecs::Encoder;
    use similar_asserts::assert_eq;

    use super::*;

    fn credentials(ids: &[&str]) -> Vec<CredentialQueryId> {
        ids.iter().map(|&id| CredentialQueryId::from(id)).collect()
    }

    // the entries share one Key Binding JWT claim, so the algorithm has to be one they all
    // offer even where that means passing over `sha-256`
    #[test]
    fn test_agreed_hash_algorithm_takes_the_one_every_entry_offers() {
        let agreed = |offers: &[&[&str]]| {
            let entries: Vec<String> = offers
                .iter()
                .map(|algorithms| {
                    let entry = serde_json::json!({
                        "type": "https://example.com/transaction",
                        "credential_ids": ["cred1"],
                        "transaction_data_hashes_alg": algorithms
                    });
                    Base64UrlSafeNoPadding::encode_to_string(serde_json::to_vec(&entry).unwrap())
                        .unwrap()
                })
                .collect();

            agreed_hash_algorithm(entries.iter().map(String::as_str))
        };

        assert_eq!(
            agreed(&[&["sha-256", "sha-512"], &["sha-512"]]).unwrap(),
            iana::HashAlgorithm::Sha512
        );
        assert_matches!(
            agreed(&[&["sha-256"], &["sha-512"]]),
            Err(TransactionDataError::InvalidTransactionData(_))
        );
    }

    #[test]
    fn test_assign_entries_disjoint_credentials() {
        assert_eq!(
            Some(credentials(&["a", "b"])),
            assign_entries_to_distinct_credentials(&[credentials(&["a"]), credentials(&["b"])])
        );
    }

    #[test]
    fn test_assign_entries_moves_earlier_entry_to_make_room() {
        // entry 0 initially takes credential `a`, but must move to credential
        // `b` so that entry 1 (which only credential `a` can authorize) fits
        assert_eq!(
            Some(credentials(&["b", "a"])),
            assign_entries_to_distinct_credentials(&[
                credentials(&["a", "b"]),
                credentials(&["a"])
            ])
        );
    }

    #[test]
    fn test_assign_entries_resolves_chained_moves() {
        assert_eq!(
            Some(credentials(&["a", "c", "d", "b"])),
            assign_entries_to_distinct_credentials(&[
                credentials(&["b", "a"]),
                credentials(&["b", "c"]),
                credentials(&["c", "d"]),
                credentials(&["b", "d"]),
            ])
        );
    }

    #[test]
    fn test_assign_entries_more_entries_than_credentials_fails() {
        assert_eq!(
            None,
            assign_entries_to_distinct_credentials(&[credentials(&["a"]), credentials(&["a"])])
        );
    }

    #[test]
    fn test_assign_entries_entry_without_applicable_credential_fails() {
        assert_eq!(
            None,
            assign_entries_to_distinct_credentials(&[credentials(&["a"]), credentials(&[])])
        );
    }
}
