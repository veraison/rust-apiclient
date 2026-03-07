// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::multiple_crate_versions)]

use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use http_cache_reqwest::{CacheMode, HttpCacheOptions};

#[cfg(feature = "disk-caching")]
use http_cache_reqwest::CACacheManager;

#[cfg(feature = "memory-caching")]
use http_cache_reqwest::MokaManager;

use coserv_rs::discovery::{DiscoveryDocument, DISCOVERY_DOCUMENT_CBOR, DISCOVERY_DOCUMENT_JSON};
use reqwest_middleware::ClientWithMiddleware;

use crate::http::{ConfigureHttp, HttpClientBuilder};

pub mod coserv;
pub mod http;

#[derive(thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("configuration error: {0}")]
    ConfigError(String),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("callback error: {0}")]
    CallbackError(String),
    #[error("feature not implemented: {0}")]
    NotImplementedError(String),
    #[error("data conversion error: {0}")]
    DataConversionError(String),
    #[error("signature verification error: {0}")]
    SignatureVerificationError(String),
}

// While for other error sources the mapping may be more subtle, all reqwest
// errors are bottled as ApiErrors.
impl From<reqwest::Error> for Error {
    fn from(re: reqwest::Error) -> Self {
        Error::ApiError(re.to_string())
    }
}

impl From<reqwest_middleware::Error> for Error {
    fn from(re: reqwest_middleware::Error) -> Self {
        Error::ApiError(re.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(re: std::io::Error) -> Self {
        Error::ConfigError(re.to_string())
    }
}

impl From<jsonwebkey::ConversionError> for Error {
    fn from(e: jsonwebkey::ConversionError) -> Self {
        Error::DataConversionError(e.to_string())
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotImplementedError(e)
            | Error::ConfigError(e)
            | Error::ApiError(e)
            | Error::CallbackError(e)
            | Error::DataConversionError(e)
            | Error::SignatureVerificationError(e) => {
                write!(f, "{e}")
            }
        }
    }
}

/// EvidenceCreationCb is the function signature of the application callback.
/// The application is passed the session nonce and the list of supported
/// evidence media types and shall return the computed evidence together with
/// the selected media type.
type EvidenceCreationCb =
    fn(nonce: &[u8], accepted: &[String], token: Vec<u8>) -> Result<(Vec<u8>, String), Error>;

/// A builder for ChallengeResponse objects
pub struct ChallengeResponseBuilder {
    http_client_builder: HttpClientBuilder,
    new_session_url: Option<String>,
}

impl ChallengeResponseBuilder {
    /// default constructor
    pub fn new() -> Self {
        Self {
            http_client_builder: HttpClientBuilder::new(),
            new_session_url: None,
        }
    }

    /// Use this method to supply the URL of the verification endpoint that will create
    /// new challenge-response sessions, e.g.:
    /// "https://veraison.example/challenge-response/v1/newSession".
    pub fn with_new_session_url(mut self, v: String) -> ChallengeResponseBuilder {
        self.new_session_url = Some(v);
        self
    }

    /// Instantiate a valid ChallengeResponse object, or fail with an error.
    pub fn build(self) -> Result<ChallengeResponse, Error> {
        let new_session_url_str = self
            .new_session_url
            .ok_or_else(|| Error::ConfigError("missing API endpoint".to_string()))?;

        let http_client = self.http_client_builder.build()?;

        Ok(ChallengeResponse {
            new_session_url: url::Url::parse(&new_session_url_str)
                .map_err(|e| Error::ConfigError(e.to_string()))?,
            http_client,
        })
    }
}

impl ConfigureHttp for ChallengeResponseBuilder {
    fn with_root_certificate(mut self, v: PathBuf) -> ChallengeResponseBuilder {
        self.http_client_builder = self.http_client_builder.with_root_certificate(v);
        self
    }

    #[cfg(feature = "disk-caching")]
    fn with_disk_cache(mut self, v: CACacheManager) -> ChallengeResponseBuilder {
        self.http_client_builder = self.http_client_builder.with_disk_cache(v);
        self
    }

    #[cfg(feature = "memory-caching")]
    fn with_memory_cache(mut self, v: MokaManager) -> ChallengeResponseBuilder {
        self.http_client_builder = self.http_client_builder.with_memory_cache(v);
        self
    }

    fn with_cache_mode(mut self, v: CacheMode) -> ChallengeResponseBuilder {
        self.http_client_builder = self.http_client_builder.with_cache_mode(v);
        self
    }

    fn with_http_cache_options(mut self, v: HttpCacheOptions) -> ChallengeResponseBuilder {
        self.http_client_builder = self.http_client_builder.with_http_cache_options(v);
        self
    }
}

impl Default for ChallengeResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The object on which one or more challenge-response verification sessions can
/// be run.  Always use the [ChallengeResponseBuilder] to instantiate it.
pub struct ChallengeResponse {
    new_session_url: url::Url,
    http_client: ClientWithMiddleware,
}

/// Nonce configuration: either the size (Size) of the nonce generated by the
/// server (use 0 to let the server also pick the size of the challenge), or an
/// explicit nonce (Value) supplied as a byte array.
pub enum Nonce {
    Size(usize),
    Value(Vec<u8>),
}

impl ChallengeResponse {
    /// Run a challenge-response verification session using the supplied nonce
    /// configuration and evidence creation callback. Returns the raw attestation results, or an
    /// error on failure.
    pub async fn run(
        &self,
        nonce: Nonce,
        evidence_creation_cb: EvidenceCreationCb,
        token: Vec<u8>,
    ) -> Result<String, Error> {
        // create new c/r verification session on the veraison side
        let (session_url, session) = self.new_session(&nonce).await?;

        // invoke the user-provided evidence builder callback with per-session parameters
        let (evidence, media_type) =
            (evidence_creation_cb)(session.nonce(), session.accept(), token)?;

        // send evidence for verification to the session endpoint
        let attestation_result = self
            .challenge_response(&evidence, &media_type, &session_url)
            .await?;

        // return veraison's attestation results
        Ok(attestation_result)
    }

    /// Ask Veraison to create a new challenge/response session using the supplied nonce
    /// configuration. On success, the return value is a tuple of the session URL for subsequent
    /// operations, plus the session data including the nonce and the list of accept types.
    pub async fn new_session(
        &self,
        nonce: &Nonce,
    ) -> Result<(String, ChallengeResponseSession), Error> {
        // ask veraison for a new session object
        let resp = self.new_session_request(nonce).await?;

        // expect 201 and a Location header containing the URI of the newly
        // allocated session
        match resp.status() {
            reqwest::StatusCode::CREATED => (),
            status => {
                // on error the body is a RFC7807 problem detail
                //
                // NOTE(tho) -- this assumption does not hold in general because
                // the request may be intercepted (and dealt with) by HTTP
                // middleware that is unaware of the API.  We need something
                // more robust here that dispatches based on the Content-Type
                // header.
                let pd: ProblemDetails = resp.json().await?;

                return Err(Error::ApiError(format!(
                    "newSession response has unexpected status: {}.  Details: {}",
                    status, pd.detail
                )));
            }
        };

        // extract location header
        let loc = resp
            .headers()
            .get("location")
            .ok_or_else(|| {
                Error::ApiError("cannot determine URI of the session resource".to_string())
            })?
            .to_str()
            .map_err(|e| Error::ApiError(e.to_string()))?;

        // join relative location with base URI
        let session_url = resp
            .url()
            .join(loc)
            .map_err(|e| Error::ApiError(e.to_string()))?;

        // decode returned session object
        let crs: ChallengeResponseSession = resp.json().await?;

        Ok((session_url.to_string(), crs))
    }

    /// Execute a challenge/response operation with the given evidence.
    pub async fn challenge_response(
        &self,
        evidence: &[u8],
        media_type: &str,
        session_url: &str,
    ) -> Result<String, Error> {
        let c = &self.http_client;

        let resp = c
            .post(session_url)
            .header(reqwest::header::ACCEPT, CRS_MEDIA_TYPE)
            .header(reqwest::header::CONTENT_TYPE, media_type)
            .body(evidence.to_owned())
            .send()
            .await?;

        let status = resp.status();

        if status.is_success() {
            match status {
                reqwest::StatusCode::OK => {
                    let crs: ChallengeResponseSession = resp.json().await?;

                    if crs.status != "complete" {
                        return Err(Error::ApiError(format!(
                            "unexpected session state: {}",
                            crs.status
                        )));
                    }

                    let result = crs.result.ok_or_else(|| {
                        Error::ApiError(
                            "no attestation results found in completed session".to_string(),
                        )
                    })?;

                    Ok(result)
                }
                reqwest::StatusCode::ACCEPTED => {
                    // TODO(tho)
                    Err(Error::NotImplementedError("asynchronous model".to_string()))
                }
                status => Err(Error::ApiError(format!(
                    "session response has unexpected success status: {status}",
                ))),
            }
        } else {
            let pd: ProblemDetails = resp.json().await?;

            Err(Error::ApiError(format!(
                "session response has error status: {}.  Details: {}",
                status, pd.detail,
            )))
        }
    }

    async fn new_session_request(&self, nonce: &Nonce) -> Result<reqwest::Response, Error> {
        let u = self.new_session_request_url(nonce)?;

        let r = self
            .http_client
            .post(u.as_str())
            .header(reqwest::header::ACCEPT, CRS_MEDIA_TYPE)
            .send()
            .await?;

        Ok(r)
    }

    fn new_session_request_url(&self, nonce: &Nonce) -> Result<url::Url, Error> {
        let mut new_session_url = self.new_session_url.clone();

        let mut q_params = String::new();

        match nonce {
            Nonce::Value(val) if !val.is_empty() => {
                q_params.push_str("nonce=");
                q_params.push_str(&URL_SAFE_NO_PAD.encode(val));
            }
            Nonce::Size(val) if *val > 0 => {
                q_params.push_str("nonceSize=");
                q_params.push_str(&val.to_string());
            }
            _ => {}
        }

        new_session_url.set_query(Some(&q_params));

        Ok(new_session_url)
    }
}

const CRS_MEDIA_TYPE: &str = "application/vnd.veraison.challenge-response-session+json";
const DISCOVERY_MEDIA_TYPE: &str = "application/vnd.veraison.discovery+json";

#[serde_with::serde_as]
#[serde_with::skip_serializing_none]
#[derive(serde::Deserialize, serde::Serialize)]
pub struct ChallengeResponseSession {
    #[serde_as(as = "serde_with::base64::Base64")]
    nonce: Vec<u8>,
    #[serde_as(as = "chrono::DateTime<chrono::Utc>")]
    expiry: chrono::NaiveDateTime,
    accept: Vec<String>,
    status: String,
    evidence: Option<EvidenceBlob>,
    result: Option<String>,
}

impl ChallengeResponseSession {
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn accept(&self) -> &[String] {
        &self.accept
    }
}

#[serde_with::serde_as]
#[derive(serde::Deserialize, serde::Serialize)]
pub struct EvidenceBlob {
    r#type: String,
    #[serde_as(as = "serde_with::base64::Base64")]
    value: Vec<u8>,
}

/// Enumerates the four possible states that the service can be in.
#[derive(Debug, PartialEq, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ServiceState {
    Down,
    Initializing,
    Ready,
    Terminating,
}

/// This object models the state and capabilities of the verification API in the Veraison service.
///
/// An instance of this struct is returned from [`Discovery::get_verification_api()`].
#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VerificationApi {
    ear_verification_key: jsonwebkey::JsonWebKey,
    media_types: Vec<String>,
    version: String,
    service_state: ServiceState,
    api_endpoints: std::collections::HashMap<String, String>,
}

/// A builder for Discovery objects
pub struct DiscoveryBuilder {
    http_client_builder: HttpClientBuilder,
    verification_url: Option<String>,
    coserv_url: Option<String>,
}

impl DiscoveryBuilder {
    /// default constructor
    pub fn new() -> Self {
        Self {
            http_client_builder: HttpClientBuilder::new(),
            verification_url: None,
            coserv_url: None,
        }
    }

    /// Use this method to supply the base URL of the discovery endpoint, e.g.
    /// "https://veraison.example" in the full
    /// "https://veraison.example/.well-known/veraison/verification".
    /// This hides / encapsulate the details of what the actual URL looks like.
    pub fn with_base_url(mut self, base_url: String) -> DiscoveryBuilder {
        self.verification_url = Some(format!(
            "{}{}",
            base_url, "/.well-known/veraison/verification"
        ));
        self.coserv_url = Some(format!(
            "{}{}",
            base_url, "/.well-known/coserv-configuration"
        ));
        self
    }

    /// Instantiate a valid Discovery object, or fail with an error.
    pub fn build(self) -> Result<Discovery, Error> {
        let verification_url = self
            .verification_url
            .ok_or_else(|| Error::ConfigError("missing API endpoint".to_string()))?;

        let coserv_url = self
            .coserv_url
            .ok_or_else(|| Error::ConfigError("missing API endpoint".to_string()))?;

        let http_client = self.http_client_builder.build()?;

        Ok(Discovery {
            verification_url: url::Url::parse(&verification_url)
                .map_err(|e| Error::ConfigError(e.to_string()))?,
            coserv_url: url::Url::parse(&coserv_url)
                .map_err(|e| Error::ConfigError(e.to_string()))?,
            http_client,
        })
    }
}

impl ConfigureHttp for DiscoveryBuilder {
    fn with_root_certificate(mut self, v: PathBuf) -> DiscoveryBuilder {
        self.http_client_builder = self.http_client_builder.with_root_certificate(v);
        self
    }

    #[cfg(feature = "disk-caching")]
    fn with_disk_cache(mut self, v: CACacheManager) -> DiscoveryBuilder {
        self.http_client_builder = self.http_client_builder.with_disk_cache(v);
        self
    }

    #[cfg(feature = "memory-caching")]
    fn with_memory_cache(mut self, v: MokaManager) -> DiscoveryBuilder {
        self.http_client_builder = self.http_client_builder.with_memory_cache(v);
        self
    }

    fn with_cache_mode(mut self, v: CacheMode) -> DiscoveryBuilder {
        self.http_client_builder = self.http_client_builder.with_cache_mode(v);
        self
    }

    fn with_http_cache_options(mut self, v: HttpCacheOptions) -> DiscoveryBuilder {
        self.http_client_builder = self.http_client_builder.with_http_cache_options(v);
        self
    }
}

impl Default for DiscoveryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VerificationApi {
    /// Obtains the EAR verification public key encoded in ASN.1 DER format.
    pub fn ear_verification_key_as_der(&self) -> Result<Vec<u8>, Error> {
        let key = &self.ear_verification_key.key;
        (*key)
            .try_to_der()
            .map_err(|e| Error::DataConversionError(e.to_string()))
    }

    /// Obtains the EAR verification public key encoded in PEM format.
    pub fn ear_verification_key_as_pem(&self) -> Result<String, Error> {
        let key = &self.ear_verification_key.key;
        (*key)
            .try_to_pem()
            .map_err(|e| Error::DataConversionError(e.to_string()))
    }

    /// Obtains the EAR verification public key as a JSON string.
    pub fn ear_verification_key_as_string(&self) -> String {
        self.ear_verification_key.to_string()
    }

    /// Obtains the signature algorithm scheme used with the EAR.
    pub fn ear_verification_algorithm(&self) -> String {
        match &self.ear_verification_key.algorithm {
            Some(alg) => match alg {
                jsonwebkey::Algorithm::ES256 => String::from("ES256"),
                jsonwebkey::Algorithm::HS256 => String::from("HS256"),
                jsonwebkey::Algorithm::RS256 => String::from("RS256"),
            },
            None => String::from(""),
        }
    }

    /// Obtains the strings for the set of media types that are supported for evidence
    /// verification. Each member of the array will be a media type string such as
    /// `"application/eat-cwt; profile=http://arm.com/psa/2.0.0"`.
    pub fn media_types(&self) -> &[String] {
        self.media_types.as_ref()
    }

    /// Obtains the version of the service.
    pub fn version(&self) -> &str {
        self.version.as_ref()
    }

    /// Indicates whether the service is starting, ready, terminating or down.
    pub fn service_state(&self) -> &ServiceState {
        &self.service_state
    }

    /// Gets the API endpoint associated with a specific endpoint name.
    ///
    /// Returns `None` if there is no API endpoint with the given name, otherwise returns
    /// a relative URL such as `"/challenge-response/v1/newSession"`.
    pub fn get_api_endpoint(&self, endpoint_name: &str) -> Option<String> {
        self.api_endpoints.get(endpoint_name).cloned()
    }

    /// Gets all of the API endpoints published by this verification service as a vector of
    /// string pairs.
    ///
    /// For each endpoint entry, the first member of the pair is the endpoint name, such
    /// as `"newChallengeResponseSession"`, and the second member is the corresponding
    /// relative URL, such as `"/challenge-response/v1/newSession"`.
    pub fn get_all_api_endpoints(&self) -> Vec<(String, String)> {
        self.api_endpoints
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// This structure allows Veraison endpoints and service capabilities to be discovered
/// dynamically.
///
/// Use [`DiscoveryBuilder`] to create an instance of this structure for the
/// Veraison service instance that you are communicating with.
pub struct Discovery {
    verification_url: url::Url,
    coserv_url: url::Url,
    http_client: ClientWithMiddleware,
}

impl Discovery {
    #[deprecated(since = "0.0.2", note = "please use the `DiscoveryBuilder` instead")]
    /// Establishes client API discovery for the Veraison service instance running at the
    /// given base URL.
    pub fn from_base_url(base_url_str: String) -> Result<Discovery, Error> {
        DiscoveryBuilder::new().with_base_url(base_url_str).build()
    }

    /// Obtains the capabilities and endpoints of the Veraison verification service.
    pub async fn get_verification_api(&self) -> Result<VerificationApi, Error> {
        let response = self
            .http_client
            .get(self.verification_url.as_str())
            .header(reqwest::header::ACCEPT, DISCOVERY_MEDIA_TYPE)
            .send()
            .await?;

        match response.status() {
            reqwest::StatusCode::OK => Ok(response.json::<VerificationApi>().await?),
            _ => Err(Error::ApiError(String::from(
                "Failed to discover verification endpoint information.",
            ))),
        }
    }

    /// Obtains the capabilities and endpoints of the CoSERV service using JSON format.
    pub async fn get_coserv_discovery_document_json(&self) -> Result<DiscoveryDocument, Error> {
        let response = self
            .http_client
            .get(self.coserv_url.as_str())
            .header(reqwest::header::ACCEPT, DISCOVERY_DOCUMENT_JSON)
            .send()
            .await?;

        match response.status() {
            reqwest::StatusCode::OK => Ok(response.json::<DiscoveryDocument>().await?),
            _ => Err(Error::ApiError(String::from(
                "Failed to discover CoSERV endpoint information (JSON format).",
            ))),
        }
    }

    /// Obtains the capabilities and endpoints of the CoSERV service using JSON format.
    pub async fn get_coserv_discovery_document_cbor(&self) -> Result<DiscoveryDocument, Error> {
        let response = self
            .http_client
            .get(self.coserv_url.as_str())
            .header(reqwest::header::ACCEPT, DISCOVERY_DOCUMENT_CBOR)
            .send()
            .await?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let dd: Result<DiscoveryDocument, ciborium::de::Error<std::io::Error>> =
                    ciborium::from_reader(response.bytes().await?.to_vec().as_slice());
                dd.map_err(|e| Error::ApiError(format!("Failed to parse CBOR data into CoSERV discovery document. Underlying error: {0}", e)))
            }
            _ => Err(Error::ApiError(String::from(
                "Failed to discover CoSERV endpoint information (CBOR format).",
            ))),
        }
    }
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct ProblemDetails {
    r#type: String,
    title: String,
    status: u16,
    detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_NEW_SESSION_URL_OK: &str =
        "https://veraison.example/challenge-response/v1/newSession";
    const TEST_NEW_SESSION_URL_NOT_ABSOLUTE: &str = "/challenge-response/v1/newSession";

    // Sample response crafted from CoSERV draft
    const SAMPLE_COSERV_DISCOVERY_DOCUMENT_CBOR_BYTES: [u8; 209] = [
        0xbf, 0x01, 0x6a, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2d, 0x62, 0x65, 0x74, 0x61, 0x02, 0x81,
        0xbf, 0x01, 0x78, 0x48, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
        0x2f, 0x63, 0x6f, 0x73, 0x65, 0x72, 0x76, 0x2b, 0x63, 0x6f, 0x73, 0x65, 0x3b, 0x20, 0x70,
        0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x3d, 0x22, 0x74, 0x61, 0x67, 0x3a, 0x76, 0x65, 0x6e,
        0x64, 0x6f, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x2c, 0x32, 0x30, 0x32, 0x35, 0x3a, 0x63, 0x63,
        0x5f, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x23, 0x31, 0x2e, 0x30, 0x2e, 0x30,
        0x22, 0x02, 0x82, 0x69, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x65, 0x64, 0x66, 0x73,
        0x6f, 0x75, 0x72, 0x63, 0x65, 0xff, 0x03, 0xa1, 0x75, 0x43, 0x6f, 0x53, 0x45, 0x52, 0x56,
        0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
        0x78, 0x2b, 0x2f, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x2d,
        0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31,
        0x2f, 0x63, 0x6f, 0x73, 0x65, 0x72, 0x76, 0x2f, 0x7b, 0x71, 0x75, 0x65, 0x72, 0x79, 0x7d,
        0x04, 0x81, 0xa6, 0x01, 0x02, 0x02, 0x45, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x03, 0x26, 0x20,
        0x01, 0x21, 0x44, 0x1a, 0x2b, 0x3c, 0x4d, 0x22, 0x44, 0x5e, 0x6f, 0x7a, 0x8b, 0xff,
    ];

    #[test]
    fn default_constructor() {
        let b: ChallengeResponseBuilder = Default::default();

        // expected initial state
        assert!(b.new_session_url.is_none());
    }

    #[test]
    fn build_ok() {
        let b = ChallengeResponseBuilder::new()
            .with_new_session_url(TEST_NEW_SESSION_URL_OK.to_string());

        assert!(b.build().is_ok());
    }

    #[test]
    fn build_fail_base_url_not_absolute() {
        let b = ChallengeResponseBuilder::new()
            .with_new_session_url(TEST_NEW_SESSION_URL_NOT_ABSOLUTE.to_string());

        assert!(b.build().is_err());
    }

    #[test]
    fn build_fail_missing_base_url() {
        let b = ChallengeResponseBuilder::new();

        assert!(b.build().is_err());
    }

    #[test]
    fn build_fail_missing_evidence_creation_cb() {
        let b = ChallengeResponseBuilder::new()
            .with_new_session_url(TEST_NEW_SESSION_URL_NOT_ABSOLUTE.to_string());

        assert!(b.build().is_err());
    }

    #[async_std::test]
    async fn new_session_request_ok() {
        let mock_server = MockServer::start().await;
        let nonce_value = vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef];
        let nonce = Nonce::Value(nonce_value.clone());

        let response = ResponseTemplate::new(201)
            .insert_header("location", "1234")
            .set_body_json(ChallengeResponseSession {
                nonce: nonce_value,
                status: "waiting".to_string(),
                accept: vec!["application/vnd.1".to_string()],
                evidence: None,
                result: None,
                expiry: chrono::Utc::now().naive_utc(),
            });

        Mock::given(method("POST"))
            .and(path("/newSession"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let cr = ChallengeResponseBuilder::new()
            .with_new_session_url(mock_server.uri() + "/newSession")
            .build()
            .unwrap();

        let rv = cr.new_session(&nonce).await.expect("unexpected failure");

        // Expect we are given the expected location URL
        assert_eq!(rv.0, format!("{}/1234", mock_server.uri()));
    }

    #[async_std::test]
    async fn challenge_response_ok() {
        let mock_server = MockServer::start().await;
        let nonce_value = vec![0xbe, 0xef];
        let evidence_value: Vec<u8> = vec![0, 1];
        let evidence = EvidenceBlob {
            r#type: "application/vnd.1".to_string(),
            value: evidence_value.clone(),
        };
        let attestation_result = "a.b.c".to_string();

        let response = ResponseTemplate::new(200).set_body_json(ChallengeResponseSession {
            nonce: nonce_value,
            status: "complete".to_string(),
            accept: vec!["application/vnd.1".to_string()],
            evidence: Some(evidence),
            result: Some(attestation_result.clone()),
            expiry: chrono::Utc::now().naive_utc(),
        });

        Mock::given(method("POST"))
            .and(path("/session/5678"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let cr = ChallengeResponseBuilder::new()
            .with_new_session_url(mock_server.uri() + "/newSession")
            .build()
            .unwrap();

        let session_url = mock_server.uri() + "/session/5678";
        let media_type = "application/vnd.1";

        let rv = cr
            .challenge_response(&evidence_value, media_type, &session_url)
            .await
            .expect("unexpected failure");

        // Expect we are given the expected attestation result
        assert_eq!(rv, attestation_result)
    }

    #[async_std::test]
    async fn discover_verification_ok() {
        let mock_server = MockServer::start().await;

        // Sample response crafted from Veraison docs.
        let raw_response = r#"
        {
            "ear-verification-key": {
                "crv": "P-256",
                "kty": "EC",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "alg": "ES256"
            },
            "media-types": [
                "application/eat-cwt; profile=http://arm.com/psa/2.0.0",
                "application/pem-certificate-chain",
                "application/vnd.enacttrust.tpm-evidence",
                "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0",
                "application/psa-attestation-token"
            ],
            "version": "commit-cb11fa0",
            "service-state": "READY",
            "api-endpoints": {
                "newChallengeResponseSession": "/challenge-response/v1/newSession"
            }
        }"#;

        let response = ResponseTemplate::new(200)
            .set_body_raw(raw_response, "application/vnd.veraison.discovery+json");

        Mock::given(method("GET"))
            .and(path("/.well-known/veraison/verification"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let discovery = DiscoveryBuilder::new()
            .with_base_url(mock_server.uri())
            .build()
            .expect("Failed to create Discovery client.");

        let verification_api = discovery
            .get_verification_api()
            .await
            .expect("Failed to get verification endpoint details.");

        // Check that we've pulled and deserialized everything that we expect
        assert_eq!(verification_api.service_state, ServiceState::Ready);
        assert_eq!(verification_api.version, String::from("commit-cb11fa0"));
        assert_eq!(verification_api.media_types.len(), 5);
        assert_eq!(
            verification_api.media_types[0],
            String::from("application/eat-cwt; profile=http://arm.com/psa/2.0.0")
        );
        assert_eq!(
            verification_api.media_types[1],
            String::from("application/pem-certificate-chain")
        );
        assert_eq!(
            verification_api.media_types[2],
            String::from("application/vnd.enacttrust.tpm-evidence")
        );
        assert_eq!(
            verification_api.media_types[3],
            String::from("application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0")
        );
        assert_eq!(
            verification_api.media_types[4],
            String::from("application/psa-attestation-token")
        );
        assert_eq!(verification_api.api_endpoints.len(), 1);
        assert_eq!(
            verification_api
                .api_endpoints
                .get("newChallengeResponseSession"),
            Some(&String::from("/challenge-response/v1/newSession"))
        );
    }

    #[async_std::test]
    async fn discover_coserv_json_ok() {
        let mock_server = MockServer::start().await;

        // Sample response crafted from CoSERV draft
        let raw_response = r#"
            {
              "version": "1.2.3-beta",
              "capabilities": [
                {
                  "media-type": "application/coserv+cose; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\"",
                  "artifact-support": [
                    "source",
                    "collected"
                  ]
                }
              ],
              "api-endpoints": {
                "CoSERVRequestResponse": "/endorsement-distribution/v1/coserv/{query}"
              },
              "result-verification-key": [
                {
                  "alg": "ES256",
                  "crv": "P-256",
                  "kty": "EC",
                  "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                  "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                  "kid": "key1"
                }
              ]
            }
        "#;

        let response =
            ResponseTemplate::new(200).set_body_raw(raw_response, DISCOVERY_DOCUMENT_JSON);

        Mock::given(method("GET"))
            .and(path("/.well-known/coserv-configuration"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let discovery = DiscoveryBuilder::new()
            .with_base_url(mock_server.uri())
            .build()
            .expect("Failed to create Discovery client.");

        let coserv_dd = discovery
            .get_coserv_discovery_document_json()
            .await
            .expect("Failed to get verification endpoint details.");

        // Light testing here - just check the version field
        // (The CoSERV DiscoveryDocument is not implemented in this crate, so we aren't testing that.)
        assert_eq!(coserv_dd.version.to_string(), String::from("1.2.3-beta"));
    }

    #[async_std::test]
    async fn discover_coserv_cbor_ok() {
        let mock_server = MockServer::start().await;

        let response = ResponseTemplate::new(200).set_body_raw(
            SAMPLE_COSERV_DISCOVERY_DOCUMENT_CBOR_BYTES,
            DISCOVERY_DOCUMENT_CBOR,
        );

        Mock::given(method("GET"))
            .and(path("/.well-known/coserv-configuration"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let discovery = DiscoveryBuilder::new()
            .with_base_url(mock_server.uri())
            .build()
            .expect("Failed to create Discovery client.");

        let coserv_dd = discovery
            .get_coserv_discovery_document_cbor()
            .await
            .expect("Failed to get verification endpoint details.");

        // Light testing here - just check the version field
        // (The CoSERV DiscoveryDocument is not implemented in this crate, so we aren't testing that.)
        assert_eq!(coserv_dd.version.to_string(), String::from("1.2.3-beta"));
    }

    #[async_std::test]
    #[cfg(feature = "disk-caching")]
    async fn discover_coserv_cbor_disk_cached_ok() {
        // Make a temporary directory to use as the cache (will be deleted when dropped)
        let cache_root = tempfile::tempdir().unwrap();
        let cache_path: PathBuf = cache_root.path().into();

        let mock_server = MockServer::start().await;

        let response = ResponseTemplate::new(200)
            .insert_header("Cache-Control", "max-age=3600")
            .set_body_raw(
                SAMPLE_COSERV_DISCOVERY_DOCUMENT_CBOR_BYTES,
                DISCOVERY_DOCUMENT_CBOR,
            );

        Mock::given(method("GET"))
            .and(path("/.well-known/coserv-configuration"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let discovery = DiscoveryBuilder::new()
            .with_base_url(mock_server.uri())
            .with_default_disk_cache(cache_path.clone())
            .build()
            .expect("Failed to create Discovery client.");

        // We should have an empty cache before we run the first query
        assert!(cache_path.read_dir().unwrap().next().is_none());

        let coserv_dd = discovery
            .get_coserv_discovery_document_cbor()
            .await
            .expect("Failed to get verification endpoint details.");

        // Light testing here - just check the version field
        // (The CoSERV DiscoveryDocument is not implemented in this crate, so we aren't testing that.)
        assert_eq!(coserv_dd.version.to_string(), String::from("1.2.3-beta"));

        // Cache should now be non-empty
        // (The structure of the cache is an implementation detail, but there must be SOMETHING in there.)
        assert!(cache_path.read_dir().unwrap().next().is_some());

        // Run a flurry of identical queries and assert a valid CoSERV result - these will be served from the cache
        for _i in 1..1000 {
            let coserv_dd = discovery
                .get_coserv_discovery_document_cbor()
                .await
                .expect("Failed to get verification endpoint details.");

            // Light testing here - just check the version field
            // (The CoSERV DiscoveryDocument is not implemented in this crate, so we aren't testing that.)
            assert_eq!(coserv_dd.version.to_string(), String::from("1.2.3-beta"));
        }

        // Only the original request should have been received by the server, so
        // assert that exactly one request was received.
        assert_eq!(
            mock_server
                .received_requests()
                .await
                .unwrap_or(vec![])
                .len(),
            1
        );
    }

    #[async_std::test]
    #[cfg(feature = "memory-caching")]
    async fn discover_coserv_cbor_memory_cached_ok() {
        use http_cache_reqwest::MokaCache;

        // Make the in-memory cache
        let cache = MokaCache::new(10);
        let cache_manager = MokaManager::new(cache);

        let mock_server = MockServer::start().await;

        let response = ResponseTemplate::new(200)
            .insert_header("Cache-Control", "max-age=3600")
            .set_body_raw(
                SAMPLE_COSERV_DISCOVERY_DOCUMENT_CBOR_BYTES,
                DISCOVERY_DOCUMENT_CBOR,
            );

        Mock::given(method("GET"))
            .and(path("/.well-known/coserv-configuration"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let discovery = DiscoveryBuilder::new()
            .with_base_url(mock_server.uri())
            .with_memory_cache(cache_manager)
            .build()
            .expect("Failed to create Discovery client.");

        let coserv_dd = discovery
            .get_coserv_discovery_document_cbor()
            .await
            .expect("Failed to get verification endpoint details.");

        // Light testing here - just check the version field
        // (The CoSERV DiscoveryDocument is not implemented in this crate, so we aren't testing that.)
        assert_eq!(coserv_dd.version.to_string(), String::from("1.2.3-beta"));

        // Run a flurry of identical queries and assert a valid CoSERV result - these will be served from the cache
        for _i in 1..1000 {
            let coserv_dd = discovery
                .get_coserv_discovery_document_cbor()
                .await
                .expect("Failed to get verification endpoint details.");

            // Light testing here - just check the version field
            // (The CoSERV DiscoveryDocument is not implemented in this crate, so we aren't testing that.)
            assert_eq!(coserv_dd.version.to_string(), String::from("1.2.3-beta"));
        }

        // Only the original request should have been received by the server, so
        // assert that exactly one request was received.
        assert_eq!(
            mock_server
                .received_requests()
                .await
                .unwrap_or(vec![])
                .len(),
            1
        );
    }
}
