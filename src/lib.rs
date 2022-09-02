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

/// EvidenceBuilder is the function signature of the application callback.
/// The application is passed the nonce and the list of supported evidence media
/// types and shall returns the computed evidence together with the selected
/// media type.
type EvidenceBuilder =
    fn(nonce: &Vec<u8>, accepted: &Vec<String>) -> Result<(Vec<u8>, String), Error>;

pub struct ChallengeResponseConfig {
    nonce: Option<Vec<u8>>,
    nonce_sz: usize,
    base_url: Option<url::Url>,
    http_client: Option<reqwest::blocking::Client>,
    delete_session: bool,
    evidence_builder: Option<EvidenceBuilder>,
}

const CRS_MEDIA_TYPE: &'static str = "application/vnd.veraison.challenge-response-session+json";

impl ChallengeResponseConfig {
    pub fn new() -> Self {
        Self {
            nonce: None,
            nonce_sz: 0,
            base_url: None,
            delete_session: true,
            http_client: None,
            evidence_builder: None,
        }
    }

    pub fn set_base_url(&mut self, v: String) -> Result<(), Error> {
        let url = url::Url::parse(&v).map_err(|e| Error::ConfigError(e.to_string()))?;

        self.base_url = Some(url);

        Ok(())
    }

    pub fn set_nonce(&mut self, v: Vec<u8>) -> Result<(), Error> {
        if v.len() == 0 {
            return Err(Error::ConfigError("zero length nonce supplied".to_string()));
        }

        self.nonce = Some(v);
        self.nonce_sz = 0;

        Ok(())
    }

    pub fn set_nonce_sz(&mut self, v: usize) -> Result<(), Error> {
        if v == 0 {
            return Err(Error::ConfigError("zero bytes nonce requested".to_string()));
        }

        self.nonce_sz = v;
        self.nonce = None;

        Ok(())
    }

    pub fn set_delete_session(&mut self, v: bool) {
        self.delete_session = v;
    }

    pub fn set_http_client(&mut self, v: reqwest::blocking::Client) {
        self.http_client = Some(v);
    }

    pub fn set_evidence_builder(&mut self, v: EvidenceBuilder) {
        self.evidence_builder = Some(v);
    }

    // on success return the attestation result
    pub fn run(&self) -> Result<String, Error> {
        // check that the configuration is in order
        self.check()?;

        // create new c/r verification session on the veraison side
        let (session_url, session) = self.new_session()?;

        // invoke the user-provided evidence builder callback with per-session parameters
        let cb = self.evidence_builder.ok_or(Error::ConfigError(
            "missing evidence builder callback".to_string(),
        ))?;
        let (evidence, media_type) = cb(session.nonce(), session.accept())?;

        // send evidence for verification to the session endpoint
        let attestation_result = self.challenge_response(&evidence, &media_type, &session_url)?;

        // return veraison's attestation results
        Ok(attestation_result)
    }

    fn challenge_response(
        &self,
        evidence: &Vec<u8>,
        media_type: &str,
        session_url: &str,
    ) -> Result<String, Error> {
        let c = self
            .http_client
            .as_ref()
            .ok_or(Error::ConfigError("missing HTTP client".to_string()))?;

        let resp = c
            .post(session_url)
            .header(reqwest::header::ACCEPT, CRS_MEDIA_TYPE)
            .header(reqwest::header::CONTENT_TYPE, media_type)
            .body(evidence.clone())
            .send()
            .map_err(|e| Error::ApiError(e.to_string()))?;

        match resp.status() {
            reqwest::StatusCode::OK => {
                let crs: ChallengeResponseSession =
                    resp.json().map_err(|e| Error::ApiError(e.to_string()))?;

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
                let pd: ProblemDetails = resp.json().map_err(|e| Error::ApiError(e.to_string()))?;

                return Err(Error::ApiError(format!(
                    "session response has unexpected status: {}.  Details: {}",
                    status, pd.detail,
                )));
            }
        }
    }

    fn new_session_request_url(&self) -> Result<url::Url, Error> {
        let base = self
            .base_url
            .clone()
            .ok_or(Error::ConfigError("missing API endpoint".to_string()))?;

        let mut new_session_url = base
            .join("newSession")
            .map_err(|e| Error::ConfigError(e.to_string()))?;

        let mut q_params = String::new();

        if self.nonce.is_some() {
            let nonce = self.nonce.as_ref().unwrap();
            q_params.push_str("nonce=");
            q_params.push_str(&base64::encode_config(nonce, base64::URL_SAFE));
        } else {
            let nonce_sz = self.nonce_sz;
            q_params.push_str("nonceSize=");
            q_params.push_str(&nonce_sz.to_string());
        }

        new_session_url.set_query(Some(&q_params));

        Ok(new_session_url)
    }

    fn new_session_request(&self) -> Result<reqwest::blocking::Response, Error> {
        let c = self
            .http_client
            .as_ref()
            .ok_or(Error::ConfigError("missing HTTP client".to_string()))?;

        let u = self.new_session_request_url()?;

        return c
            .post(u.as_str())
            .header(reqwest::header::ACCEPT, CRS_MEDIA_TYPE)
            .send()
            .map_err(|e| Error::ApiError(e.to_string()));
    }

    fn new_session(&self) -> Result<(String, ChallengeResponseSession), Error> {
        // ask veraison for a new session object
        let resp = self
            .new_session_request()
            .map_err(|e| Error::ApiError(e.to_string()))?;

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
                let pd: ProblemDetails = resp.json().map_err(|e| Error::ApiError(e.to_string()))?;

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
        let crs: ChallengeResponseSession =
            resp.json().map_err(|e| Error::ApiError(e.to_string()))?;

        Ok((session_url.to_string(), crs))
    }

    fn check(&self) -> Result<(), Error> {
        if self.nonce_sz == 0 && self.nonce.is_none() {
            return Err(Error::ConfigError("missing nonce info".to_string()));
        }

        // given the setters' logics, this is treated as an object invariant
        if self.nonce_sz > 0 && self.nonce.is_some() {
            panic!("only one of nonce or nonce size must be specified")
        }

        if self.base_url.is_none() {
            return Err(Error::ConfigError("missing API endpoint".to_string()));
        }

        if self.http_client.is_none() {
            return Err(Error::ConfigError("missing HTTP client".to_string()));
        }

        if self.evidence_builder.is_none() {
            return Err(Error::ConfigError(
                "missing evidence builder callback".to_string(),
            ));
        }

        Ok(())
    }
}

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
    pub fn nonce(&self) -> &Vec<u8> {
        return &self.nonce;
    }

    pub fn accept(&self) -> &Vec<String> {
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

    fn test_evidence_builder(_: &Vec<u8>, _: &Vec<String>) -> Result<(Vec<u8>, String), Error> {
        Ok((vec![0xff], "application/my".to_string()))
    }

    #[test]
    fn default_constructor() {
        let c = ChallengeResponseConfig::new();

        // expected initial state
        assert!(c.nonce.is_none());
        assert_eq!(c.nonce_sz, 0);
        assert!(c.base_url.is_none());
        assert_eq!(c.delete_session, true);
        assert!(c.http_client.is_none());
    }

    #[test]
    fn check_ok() {
        let mut c = ChallengeResponseConfig::new();

        c.set_nonce_sz(32).unwrap();
        c.set_base_url(TEST_BASE_URL.to_string()).unwrap();
        c.set_http_client(reqwest::blocking::Client::new());
        c.set_evidence_builder(test_evidence_builder);

        assert!(!c.check().is_err())
    }

    #[test]
    fn check_fail_missing_nonce_info() {
        let c = ChallengeResponseConfig::new();

        let expected_err = "missing nonce info".to_string();

        assert_eq!(c.check(), Err(Error::ConfigError(expected_err)));
    }

    #[test]
    #[should_panic]
    fn check_fail_broken_nonce_invariant() {
        let mut c = ChallengeResponseConfig::new();

        c.set_nonce(vec![1, 2, 3, 4]).unwrap();
        c.nonce_sz = 1; // not possible to an outside caller

        let _unused_result = c.check();
    }

    #[test]
    fn check_fail_no_base_url() {
        let mut c = ChallengeResponseConfig::new();

        c.set_nonce_sz(32).unwrap();

        let expected_err = "missing API endpoint".to_string();

        assert_eq!(c.check(), Err(Error::ConfigError(expected_err)));
    }

    #[test]
    fn check_fail_no_http_client() {
        let mut c = ChallengeResponseConfig::new();

        let expected_err = "missing HTTP client".to_string();

        c.set_nonce_sz(32).unwrap();
        c.set_base_url(TEST_BASE_URL.to_string()).unwrap();

        assert_eq!(c.check(), Err(Error::ConfigError(expected_err)));
    }

    #[test]
    fn set_base_url_ok() {
        let mut c = ChallengeResponseConfig::new();
        assert!(c.base_url.is_none());

        let good_base_url = TEST_BASE_URL.to_string();
        assert!(!c.set_base_url(good_base_url).is_err());
        assert!(c.base_url.is_some());
    }

    #[test]
    fn set_base_url_fail_not_absolute() {
        let mut c = ChallengeResponseConfig::new();
        assert!(c.base_url.is_none());

        let bad_base_url = "/challenge-response/v1/".to_string();

        let expected_err = "relative URL without a base".to_string();

        assert_eq!(
            c.set_base_url(bad_base_url),
            Err(Error::ConfigError(expected_err))
        );
    }

    #[test]
    fn set_nonce_ok() {
        let mut c = ChallengeResponseConfig::new();
        assert!(c.nonce.is_none());

        let good_nonce = vec![1, 2, 3, 4];
        assert!(!c.set_nonce(good_nonce).is_err());
        assert!(c.nonce.is_some());
        assert_eq!(c.nonce_sz, 0);
    }

    #[test]
    fn set_nonce_fail_too_short() {
        let mut c = ChallengeResponseConfig::new();
        assert!(c.nonce.is_none());

        let zero_length_nonce = Vec::<u8>::new();

        let expected_err = "zero length nonce supplied".to_string();

        assert_eq!(
            c.set_nonce(zero_length_nonce),
            Err(Error::ConfigError(expected_err))
        );
    }

    #[test]
    fn set_nonce_sz_ok() {
        let mut c = ChallengeResponseConfig::new();
        assert_eq!(c.nonce_sz, 0);

        let good_nonce_sz = 1;
        assert!(!c.set_nonce_sz(good_nonce_sz).is_err());
        assert_eq!(c.nonce_sz, good_nonce_sz);
        assert!(c.nonce.is_none());
    }

    #[test]
    fn set_nonce_sz_fail_too_short() {
        let mut c = ChallengeResponseConfig::new();
        assert_eq!(c.nonce_sz, 0);

        let expected_err = "zero bytes nonce requested".to_string();

        assert_eq!(c.set_nonce_sz(0), Err(Error::ConfigError(expected_err)));
    }

    #[test]
    fn set_nonce_sz_resets_nonce() {
        let mut c = ChallengeResponseConfig::new();
        assert!(c.nonce.is_none());

        assert!(!c.set_nonce(vec![1, 2, 3, 4]).is_err());
        assert!(c.nonce.is_some());

        assert!(!c.set_nonce_sz(1).is_err());
        assert!(c.nonce.is_none());
    }

    #[test]
    fn set_nonce_resets_nonce_sz() {
        let mut c = ChallengeResponseConfig::new();
        assert_eq!(c.nonce_sz, 0);

        assert!(!c.set_nonce_sz(1).is_err());
        assert_eq!(c.nonce_sz, 1);

        assert!(!c.set_nonce(vec![1, 2, 3, 4]).is_err());
        assert_eq!(c.nonce_sz, 0);
    }

    #[test]
    fn set_delete_session() {
        let mut c = ChallengeResponseConfig::new();
        assert!(c.delete_session);

        c.set_delete_session(false);
        assert!(!c.delete_session);
    }
}
