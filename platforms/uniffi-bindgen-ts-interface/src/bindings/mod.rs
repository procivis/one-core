// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

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

#[derive(Default, Deserialize)]
pub struct IntfBindingGeneratorConfig {
    // TODO: Add specific configuration options.
}

impl BindingGenerator for IntfBindingGenerator {
    type Config = IntfBindingGeneratorConfig;

    fn new_config(&self, root_toml: &toml::Value) -> Result<Self::Config> {
        Ok(
            match root_toml.get("bindings").and_then(|b| b.get("ts-intf")) {
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
        for uniffi_bindgen::Component { ci, config: _, .. } in components {
            let ts_file_name = format!("{}-intf.ts", ci.namespace().to_kebab_case());
            let ts_file_path = settings.out_dir.join(ts_file_name);

            let Bindings { ts_file_contents } = generate_ts_bindings(ci)?;

            write_with_dirs(&ts_file_path, ts_file_contents)?;
        }

        Ok(())
    }
}
