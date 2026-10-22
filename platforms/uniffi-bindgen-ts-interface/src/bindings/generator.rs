// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

use std::any::Any;

use anyhow::{Context, Result};
use askama::Template;
use uniffi_bindgen::ComponentInterface;
use uniffi_bindgen::interface::{AsType, Type};

use crate::bindings::{TsInterfaceBindingGeneratorConfig, filters};

pub struct Bindings {
    pub ts_file_contents: String,
}

#[derive(Template)]
#[template(escape = "none", path = "intf.ts")]
struct IntfTsTemplate<'ci> {
    ci: &'ci ComponentInterface,
}

pub fn generate_ts_bindings(
    ci: &ComponentInterface,
    config: &TsInterfaceBindingGeneratorConfig,
) -> Result<Bindings> {
    // the config is passed as a runtime value, so that filters can access it
    let ts_file_contents = IntfTsTemplate { ci }
        .render_with_values(&("config", config as &dyn Any))
        .context("failed to render intf.ts template")?;

    Ok(Bindings { ts_file_contents })
}
