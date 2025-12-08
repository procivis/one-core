//! Implementation of keys validation of DIDs.

use serde::{Deserialize, Serialize};

use crate::provider::did_method::model::AmountOfKeys;

#[derive(Debug, Serialize, Clone)]
pub struct MinMax<const N: usize> {
    pub min: usize,
    pub max: usize,
}

impl<const N: usize> MinMax<N> {
    fn contains(&self, number: usize) -> bool {
        (&self.min..=&self.max).contains(&&number)
    }
}

impl<const N: usize> Default for MinMax<N> {
    fn default() -> Self {
        Self { min: 1, max: 1 }
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
            return Err(serde::de::Error::custom(format!(
                "`min` cannot be smaller then {N}"
            )));
        }

        if val.max < val.min {
            return Err(serde::de::Error::custom(
                "`max` cannot be smaller then `min`",
            ));
        }

        Ok(MinMax {
            min: val.min,
            max: val.max,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
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

impl Keys {
    pub fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        self.global.contains(keys.global)
            && self.authentication.contains(keys.authentication)
            && self.assertion_method.contains(keys.assertion_method)
            && self.key_agreement.contains(keys.key_agreement)
            && self
                .capability_invocation
                .contains(keys.capability_invocation)
            && self
                .capability_delegation
                .contains(keys.capability_delegation)
    }
}
