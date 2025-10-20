use std::collections::HashMap;

use maplit::hashmap;
use serde::{Deserialize, Serialize};

use crate::proto::jwt::WithMetadata;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialClaim, CredentialClaimValue};
use crate::provider::credential_formatter::vcdm::JwtVcdmCredential;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VcClaim {
    pub vc: JwtVcdmCredential,
}

impl WithMetadata for VcClaim {
    fn get_metadata_claims(&self) -> Result<HashMap<String, CredentialClaim>, FormatterError> {
        let value =
            serde_json::to_value(self).map_err(|e| FormatterError::JsonMapping(e.to_string()))?;

        let Some(obj) = value.as_object() else {
            return Err(FormatterError::Failed(
                "Expected serialized value to be an object".to_string(),
            ));
        };

        let Some(vc) = obj.get("vc").and_then(|vc| vc.as_object()) else {
            return Ok(HashMap::new());
        };

        let mut result = HashMap::new();
        for key in ["type", "id"] {
            let Some(claim) = vc.get(key) else { continue };
            let mut claim = CredentialClaim::try_from(claim.clone())?;
            claim.set_metadata(true);
            result.insert(key.to_string(), claim);
        }

        let vc_claim = CredentialClaim {
            selectively_disclosable: false,
            metadata: true,
            value: CredentialClaimValue::Object(result),
        };

        Ok(hashmap! {
            "vc".to_string() => vc_claim,
        })
    }
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TokenStatusListContent {
    pub status_list: TokenStatusListSubject,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TokenStatusListSubject {
    pub bits: usize,
    #[serde(rename = "lst")]
    pub value: String,
}
