// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

extern crate veraison_apiclient;

use veraison_apiclient::*;

fn my_evidence_builder(nonce: &[u8], accept: &[String], token: Vec<u8>) -> Result<(Vec<u8>, String), Error> {
    println!("server challenge: {:?}", nonce);
    println!("acceptable media types: {:#?}", accept);
    let mut token = token;
    if token.is_empty() {
        // some very fake evidence
        token = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    }
    Ok((
        token,
        // the first acceptable evidence type
        accept[0].to_string(),
    ))
}

fn main() {
    let base_url = "http://127.0.0.1:8080";

    let discovery = Discovery::from_base_url(String::from(base_url))
        .expect("Failed to start API discovery with the service.");

    let verification_api = discovery
        .get_verification_api()
        .expect("Failed to discover the verification endpoint details.");

    let relative_endpoint = verification_api
        .get_api_endpoint("newChallengeResponseSession")
        .expect("Could not locate a newChallengeResponseSession endpoint.");

    let api_endpoint = format!("{}{}", base_url, relative_endpoint);

    // create a ChallengeResponse object
    let cr = ChallengeResponseBuilder::new()
        .with_new_session_url(api_endpoint)
        .build()
        .unwrap();

    let nonce = Nonce::Value(vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef]);
    // alternatively, to let Veraison pick the challenge: "let nonce = Nonce::Size(32);"

    match cr.run(nonce, my_evidence_builder, Vec::new()) {
        Err(e) => println!("Error: {}", e),
        Ok(attestation_result) => println!("Attestation Result: {}", attestation_result),
    }
}
