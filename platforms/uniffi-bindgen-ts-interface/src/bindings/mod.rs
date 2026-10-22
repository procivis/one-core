// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

use std::collections::HashMap;

use anyhow::Result;
use heck::ToKebabCase;
use serde::Deserialize;
use uniffi_bindgen::{BindingGenerator, GenerationSettings};

mod filters;
mod generator;

use crate::bindings::generator::{Bindings, generate_ts_bindings};
use crate::utils::write_with_dirs;

pub struct IntfBindingGenerator {}

impl IntfBindingGenerator {
    pub fn new() -> Self {
        Self {}
    }
}

/// Configuration read from the `[bindings.ts-interface]` section of `uniffi.toml`
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TsInterfaceBindingGeneratorConfig {
    /// Records, enums or objects left out from the TS interface, declared as type names
    pub hidden_types: Vec<String>,
    /// Workaround types that need to be replaced in the TS interface with a custom declaration, declared as type name -> typescript type
    pub type_overrides: HashMap<String, String>,
    /// Enum variants not exposed in the TS interface, declared as enum name -> variant names
    pub hidden_enum_variants: HashMap<String, Vec<String>>,
}

impl BindingGenerator for IntfBindingGenerator {
    type Config = TsInterfaceBindingGeneratorConfig;

    fn new_config(&self, root_toml: &toml::Value) -> Result<Self::Config> {
        Ok(
            match root_toml
                .get("bindings")
                .and_then(|b| b.get("ts-interface"))
            {
                Some(v) => v.clone().try_into()?,
                None => Default::default(),
            },
        )
    }

    fn update_component_configs(
        &self,
        _settings: &GenerationSettings,
        _components: &mut Vec<uniffi_bindgen::Component<Self::Config>>,
    ) -> Result<()> {
        Ok(())
    }

    fn write_bindings(
        &self,
        settings: &GenerationSettings,
        components: &[uniffi_bindgen::Component<Self::Config>],
    ) -> Result<()> {
        for uniffi_bindgen::Component { ci, config } in components {
            let ts_file_name = format!("{}-intf.ts", ci.namespace().to_kebab_case());
            let ts_file_path = settings.out_dir.join(ts_file_name);

            let Bindings { ts_file_contents } = generate_ts_bindings(ci, config)?;

            write_with_dirs(&ts_file_path, ts_file_contents)?;
        }

        Ok(())
    }
}
