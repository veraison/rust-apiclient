extern crate reqwest;
extern crate veraison_apiclient;

fn my_evidence_builder(
    nonce: &Vec<u8>,
    accept: &Vec<String>,
) -> Result<(Vec<u8>, String), veraison_apiclient::Error> {
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
    let nonce = vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef];
    let http_client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();

    let mut c = veraison_apiclient::ChallengeResponseConfig::new();

    c.set_base_url(api_endpoint).unwrap();
    c.set_nonce(nonce).unwrap();
    c.set_http_client(http_client);
    c.set_evidence_builder(my_evidence_builder);

    match c.run() {
        Err(e) => println!("Error: {}", e),
        Ok(attestation_result) => println!("Attestation Result: {}", attestation_result),
    }
}
