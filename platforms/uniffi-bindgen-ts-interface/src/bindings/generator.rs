// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

use anyhow::{Context, Result};
use askama::Template;
use uniffi_bindgen::ComponentInterface;
use uniffi_bindgen::interface::{AsType, Type};

use crate::bindings::filters;

pub struct Bindings {
    pub ts_file_contents: String,
}

#[derive(Template)]
#[template(escape = "none", path = "intf.ts")]
struct IntfTsTemplate<'ci> {
    ci: &'ci ComponentInterface,
}

impl<'ci> IntfTsTemplate<'ci> {
    pub fn new(ci: &'ci ComponentInterface) -> Self {
        Self { ci }
    }
}

pub fn generate_ts_bindings(ci: &ComponentInterface) -> Result<Bindings> {
    let ts_file_contents = IntfTsTemplate::new(ci)
        .render()
        .context("failed to render intf.ts template")?;

    Ok(Bindings { ts_file_contents })
}
