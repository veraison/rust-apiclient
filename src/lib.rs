// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#[derive(thiserror::Error, PartialEq)]
pub enum Error {
    #[error("configuration error: {0}")]
    ConfigError(String),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("callback error: {0}")]
    CallbackError(String),
    #[error("feature not implemented: {0}")]
    NotImplementedError(String),
}

// While for other error sources the mapping may be more subtle, all reqwest
// errors are bottled as ApiErrors.
impl From<reqwest::Error> for Error {
    fn from(re: reqwest::Error) -> Self {
        Error::ApiError(re.to_string())
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotImplementedError(e)
            | Error::ConfigError(e)
            | Error::ApiError(e)
            | Error::CallbackError(e) => {
                write!(f, "{}", e)
            }
        }
    }
}

/// EvidenceCreationCb is the function signature of the application callback.
/// The application is passed the session nonce and the list of supported
/// evidence media types and shall return the computed evidence together with
/// the selected media type.
type EvidenceCreationCb = fn(nonce: &[u8], accepted: &[String]) -> Result<(Vec<u8>, String), Error>;

/// A builder for ChallengeResponse objects
pub struct ChallengeResponseBuilder {
    base_url: Option<String>,
    http_client: Option<reqwest::blocking::Client>,
    evidence_creation_cb: Option<EvidenceCreationCb>,
}

impl ChallengeResponseBuilder {
    /// default constructor
    pub fn new() -> Self {
        Self {
            base_url: None,
            http_client: None,
            evidence_creation_cb: None,
        }
    }

    /// Use this method to supply the base URL of the service implementing the
    /// challenge-response API.  E.g.,
    /// "https://veraison.example/challenge-response/v1/".
    pub fn with_base_url(mut self, v: String) -> ChallengeResponseBuilder {
        self.base_url = Some(v);
        self
    }

    /// Use this method to supply a fully configured reqwest::blocking::Client
    /// used for communicating with the Veraison service.
    pub fn with_http_client(mut self, v: reqwest::blocking::Client) -> ChallengeResponseBuilder {
        self.http_client = Some(v);
        self
    }

    /// Use this method to provide the application callback that is used to
    /// build the attestation evidence for this verification session.  See
    /// EvidenceCreationCb.
    pub fn with_evidence_creation_cb(mut self, v: EvidenceCreationCb) -> ChallengeResponseBuilder {
        self.evidence_creation_cb = Some(v);
        self
    }

    /// Instantiate a valid ChallengeResponse object, or fail with an error.
    pub fn build(self) -> Result<ChallengeResponse, Error> {
        let base_url_str = self
            .base_url
            .ok_or(Error::ConfigError("missing API endpoint".to_string()))?;

        Ok(ChallengeResponse {
            base_url: url::Url::parse(&base_url_str)
                .map_err(|e| Error::ConfigError(e.to_string()))?,
            http_client: self
                .http_client
                .ok_or(Error::ConfigError("missing HTTP client".to_string()))?,
            evidence_creation_cb: self.evidence_creation_cb.ok_or(Error::ConfigError(
                "missing evidence creation callback".to_string(),
            ))?,
        })
    }
}

/// The object on which one or more challenge-response verification sessions can
/// be run.  Always use the [ChallengeResponseBuilder] to instantiate it.
pub struct ChallengeResponse {
    base_url: url::Url,
    http_client: reqwest::blocking::Client,
    evidence_creation_cb: EvidenceCreationCb,
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
    /// configuration.  Returns the raw attestation results, or an error on
    /// failure.
    pub fn run(&self, nonce: Nonce) -> Result<String, Error> {
        // create new c/r verification session on the veraison side
        let (session_url, session) = self.new_session(&nonce)?;

        // invoke the user-provided evidence builder callback with per-session parameters
        let (evidence, media_type) =
            (self.evidence_creation_cb)(session.nonce(), session.accept())?;

        // send evidence for verification to the session endpoint
        let attestation_result = self.challenge_response(&evidence, &media_type, &session_url)?;

        // return veraison's attestation results
        Ok(attestation_result)
    }

    fn new_session(&self, nonce: &Nonce) -> Result<(String, ChallengeResponseSession), Error> {
        // ask veraison for a new session object
        let resp = self.new_session_request(nonce)?;

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
                let pd: ProblemDetails = resp.json()?;

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
            .ok_or(Error::ApiError(
                "cannot determine URI of the session resource".to_string(),
            ))?
            .to_str()
            .map_err(|e| Error::ApiError(e.to_string()))?;

        // join relative location with base URI
        let session_url = resp
            .url()
            .join(loc)
            .map_err(|e| Error::ApiError(e.to_string()))?;

        // decode returned session object
        let crs: ChallengeResponseSession = resp.json()?;

        Ok((session_url.to_string(), crs))
    }

    fn new_session_request(&self, nonce: &Nonce) -> Result<reqwest::blocking::Response, Error> {
        let u = self.new_session_request_url(nonce)?;

        let r = self
            .http_client
            .post(u.as_str())
            .header(reqwest::header::ACCEPT, CRS_MEDIA_TYPE)
            .send()?;

        return Ok(r);
    }

    fn new_session_request_url(&self, nonce: &Nonce) -> Result<url::Url, Error> {
        let base = &self.base_url;

        let mut new_session_url = base
            .join("newSession")
            .map_err(|e| Error::ConfigError(e.to_string()))?;

        let mut q_params = String::new();

        match nonce {
            Nonce::Value(val) if val.len() > 0 => {
                q_params.push_str("nonce=");
                q_params.push_str(&base64::encode_config(val, base64::URL_SAFE));
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

    fn challenge_response(
        &self,
        evidence: &Vec<u8>,
        media_type: &str,
        session_url: &str,
    ) -> Result<String, Error> {
        let c = &self.http_client;

        let resp = c
            .post(session_url)
            .header(reqwest::header::ACCEPT, CRS_MEDIA_TYPE)
            .header(reqwest::header::CONTENT_TYPE, media_type)
            .body(evidence.clone())
            .send()?;

        match resp.status() {
            reqwest::StatusCode::OK => {
                let crs: ChallengeResponseSession = resp.json()?;

                if crs.status != "complete" {
                    return Err(Error::ApiError(format!(
                        "unexpected session state: {}",
                        crs.status
                    )));
                }

                let result = crs.result.ok_or(Error::ApiError(
                    "no attestation results found in completed session".to_string(),
                ))?;

                return Ok(result);
            }
            reqwest::StatusCode::ACCEPTED => {
                // TODO(tho)
                return Err(Error::NotImplementedError("asynchronous model".to_string()));
            }
            status => {
                let pd: ProblemDetails = resp.json()?;

                return Err(Error::ApiError(format!(
                    "session response has unexpected status: {}.  Details: {}",
                    status, pd.detail,
                )));
            }
        }
    }
}

const CRS_MEDIA_TYPE: &'static str = "application/vnd.veraison.challenge-response-session+json";

#[serde_with::serde_as]
#[serde_with::skip_serializing_none]
#[derive(serde::Deserialize)]
struct ChallengeResponseSession {
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
        return &self.nonce;
    }

    pub fn accept(&self) -> &[String] {
        return &self.accept;
    }
}

#[serde_with::serde_as]
#[derive(serde::Deserialize)]
struct EvidenceBlob {
    r#type: String,
    #[serde_as(as = "serde_with::base64::Base64")]
    value: Vec<u8>,
}

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

    const TEST_BASE_URL: &str = "https://veraison.example/challenge-response/v1/";

    fn test_evidence_builder(_: &[u8], _: &[String]) -> Result<(Vec<u8>, String), Error> {
        Ok((vec![0xff], "application/my".to_string()))
    }

    #[test]
    fn default_constructor() {
        let b = ChallengeResponseBuilder::new();

        // expected initial state
        assert!(b.base_url.is_none());
        assert!(b.http_client.is_none());
        assert!(b.evidence_creation_cb.is_none());
    }

    #[test]
    fn build_ok() {
        /*
        let good_base_url = TEST_BASE_URL.to_string();
        */
    }

    #[test]
    fn build_fail_base_url_not_absolute() {
        /*
        let bad_base_url = "/challenge-response/v1/".to_string();
        */
    }

    #[test]
    fn run_fail_nonce_too_short() {
        /*
        let nonce_too_short = Vector<u8>::new();
        */
    }

    #[test]
    fn run_fail_nonce_sz_too_short() {
        /*
        let nonce_sz_too_short = 0;
        */
    }
}
