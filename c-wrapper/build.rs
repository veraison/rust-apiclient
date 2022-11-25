// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("veraison_client_wrapper.h");
}
