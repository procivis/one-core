use one_dto_mapper::{From, Into};
use serde::de::Error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Into)]
#[into(one_core::provider::did_method::universal::Params)]
#[serde(rename_all = "camelCase")]
pub struct DidUniversalParams {
    pub resolver_url: String,
    pub supported_method_names: Vec<String>,
}

#[derive(Debug, Deserialize, Into)]
#[into(one_core::provider::did_method::web::Params)]
#[serde(rename_all = "camelCase")]
pub struct DidWebParams {
    #[serde(default)]
    pub keys: Keys,
    pub resolve_to_insecure_http: Option<bool>,
}

#[derive(Debug, Deserialize, Into)]
#[into(one_core::provider::did_method::webvh::Params)]
#[serde(rename_all = "camelCase")]
pub struct DidWebVhParams {
    #[serde(default)]
    pub keys: Keys,
    #[serde(default)]
    pub max_did_log_entry_check: Option<u32>,
    #[serde(default)]
    pub resolve_to_insecure_http: bool,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, From, Into)]
#[from(one_core::provider::did_method::keys::Keys)]
#[into(one_core::provider::did_method::keys::Keys)]
#[serde(rename_all = "camelCase")]
pub struct Keys {
    #[serde(default, flatten)]
    pub global: MinMax<1>,
    #[serde(default)]
    pub authentication: MinMax<0>,
    #[serde(default)]
    pub assertion_method: MinMax<0>,
    #[serde(default)]
    pub key_agreement: MinMax<0>,
    #[serde(default)]
    pub capability_invocation: MinMax<0>,
    #[serde(default)]
    pub capability_delegation: MinMax<0>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MinMax<const N: usize> {
    pub min: usize,
    pub max: usize,
}

impl<const N: usize> Default for MinMax<N> {
    fn default() -> Self {
        Self { min: 1, max: 1 }
    }
}

impl<const N: usize> From<one_core::provider::did_method::keys::MinMax<N>> for MinMax<N> {
    fn from(value: one_core::provider::did_method::keys::MinMax<N>) -> Self {
        MinMax {
            min: value.min,
            max: value.max,
        }
    }
}

impl<const N: usize> From<MinMax<N>> for one_core::provider::did_method::keys::MinMax<N> {
    fn from(value: MinMax<N>) -> Self {
        one_core::provider::did_method::keys::MinMax {
            min: value.min,
            max: value.max,
        }
    }
}

impl<'a, const N: usize> Deserialize<'a> for MinMax<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        struct Proxy {
            min: usize,
            max: usize,
        }

        let val = Proxy::deserialize(deserializer)?;

        if val.min < N {
            return Err(Error::custom(format!("`min` cannot be smaller then {N}")));
        }

        if val.max < val.min {
            return Err(Error::custom("`max` cannot be smaller then `min`"));
        }

        Ok(MinMax {
            min: val.min,
            max: val.max,
        })
    }
}
