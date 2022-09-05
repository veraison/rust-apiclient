// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

extern crate reqwest;
extern crate veraison_apiclient;

use veraison_apiclient::*;

fn my_evidence_builder(nonce: &Vec<u8>, accept: &Vec<String>) -> Result<(Vec<u8>, String), Error> {
    println!("server challenge: {:?}", nonce);
    println!("acceptable media types: {:#?}", accept);

    Ok((
        // some very fake evidence
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        // the first acceptable evidence type
        accept[0].to_string(),
    ))
}

fn main() {
    let api_endpoint = "http://127.0.0.1:8080/challenge-response/v1/".to_string();
    let http_client = reqwest::blocking::Client::builder().build().unwrap();

    // create a ChallengeResponse object
    let cr = ChallengeResponseBuilder::new()
        .with_base_url(api_endpoint.to_string())
        .with_http_client(http_client)
        .with_evidence_creation_cb(my_evidence_builder)
        .build()
        .unwrap();

    let nonce = Nonce::Value(vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef]);
    // alternatively, to let Veraison pick the challenge: "let nonce = Nonce::Size(32);"

    match cr.run(nonce) {
        Err(e) => println!("Error: {}", e),
        Ok(attestation_result) => println!("Attestation Result: {}", attestation_result),
    }
}
