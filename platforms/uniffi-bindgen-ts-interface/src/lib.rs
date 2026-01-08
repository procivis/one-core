// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use clap::Parser;

mod bindings;
mod utils;

/// UniFFI binding generator for Typescript
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Path to the compiled library (.so, .dylib, or .dll).
    #[arg(short, long)]
    library: Utf8PathBuf,

    /// Output directory.
    #[arg(short, long, default_value = "./output")]
    out_dir: Utf8PathBuf,

    /// Name of the crate.
    #[arg(long)]
    crate_name: Option<String>,

    /// Config file override.
    #[arg(short, long)]
    config: Option<Utf8PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    let config_supplier = {
        use uniffi_bindgen::cargo_metadata::CrateConfigSupplier;
        let cmd = ::cargo_metadata::MetadataCommand::new();
        let metadata = cmd.exec().context("error running cargo metadata")?;
        CrateConfigSupplier::from(metadata)
    };
    let binding_generator = bindings::IntfBindingGenerator::new();

    uniffi_bindgen::library_mode::generate_bindings(
        &args.library,
        args.crate_name,
        &binding_generator,
        &config_supplier,
        args.config.as_deref(),
        &args.out_dir,
        false,
    )
    .context("Failed to generate typescript bindings in library mode")?;

    Ok(())
}
