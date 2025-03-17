//! `struct`s and `enum`s for DID method provider.

use one_dto_mapper::{convert_inner, From, Into};
use serde::Serialize;
use shared_types::DidValue;

use super::dto::{DidDocumentDTO, DidVerificationMethodDTO};
use crate::model::key::PublicKeyJwk;

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub enum Operation {
    RESOLVE,
    CREATE,
    DEACTIVATE,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidCapabilities {
    pub operations: Vec<Operation>,
    pub key_algorithms: Vec<String>,
    /// Did method names that this did method is able to handle
    pub method_names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, From, Into)]
#[from(DidDocumentDTO)]
#[into(DidDocumentDTO)]
pub struct DidDocument {
    pub context: serde_json::Value,
    pub id: DidValue,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub verification_method: Vec<DidVerificationMethod>,
    pub authentication: Option<Vec<String>>,
    pub assertion_method: Option<Vec<String>>,
    pub key_agreement: Option<Vec<String>>,
    pub capability_invocation: Option<Vec<String>>,
    pub capability_delegation: Option<Vec<String>>,

    pub rest: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, From, Into)]
#[from(DidVerificationMethodDTO)]
#[into(DidVerificationMethodDTO)]
pub struct DidVerificationMethod {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    pub public_key_jwk: PublicKeyJwk,
}

#[derive(Debug, Clone)]
pub struct AmountOfKeys {
    pub global: usize,
    pub authentication: usize,
    pub assertion_method: usize,
    pub key_agreement: usize,
    pub capability_invocation: usize,
    pub capability_delegation: usize,
}
