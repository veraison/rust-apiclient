// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use base64::{engine::general_purpose::STANDARD, Engine};
use oauth2::basic::BasicTokenType;
use reqwest_middleware::ClientWithMiddleware;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    http::{ConfigureHttp, HttpClientBuilder},
    Error,
};

/// Upper bound on the whole OAuth2 token request (connect, TLS handshake, request and response).
/// Token requests are serialised behind the authenticator lock, so an unresponsive identity
/// provider must not be allowed to block every outgoing request indefinitely.
const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Refresh cached tokens this long before their advertised expiry to account for network latency
/// and clock skew between the identity provider and resource server.
const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(30);

/// Scope requested from the identity provider when none is configured.
const DEFAULT_SCOPE: &str = "openid";

/// Authentication methods supported by the Veraison service.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub enum Method {
    #[default]
    Passthrough,
    Basic,
    Oauth2,
}

impl std::str::FromStr for Method {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "none" | "passthrough" => Ok(Self::Passthrough),
            "basic" => Ok(Self::Basic),
            "oauth2" => Ok(Self::Oauth2),
            _ => Err(Error::ConfigError(format!("unexpected Method {value:?}"))),
        }
    }
}

/// Supplies the value of the HTTP Authorization header.
#[async_trait::async_trait]
pub trait Authenticator {
    /// Configure the authenticator with a JSON value.
    fn configure(&mut self, config: &serde_json::Value) -> Result<(), Error>;
    /// Encode the Authorization header.
    async fn encode_header(&mut self) -> Result<String, Error>;
}

/// A Null authenticator that does not add any Authorization header.
#[derive(Default)]
pub struct NullAuthenticator;

#[async_trait::async_trait]
impl Authenticator for NullAuthenticator {
    /// Configure the authenticator with a JSON value. This implementation ignores the configuration.
    fn configure(&mut self, _config: &serde_json::Value) -> Result<(), Error> {
        Ok(())
    }

    /// Encode the Authorization header. This implementation always returns an empty string.
    async fn encode_header(&mut self) -> Result<String, Error> {
        Ok(String::new())
    }
}

/// A Basic authenticator that uses a username and password to generate a Basic Authorization header.
#[derive(Default, Deserialize)]
pub struct BasicAuthenticator {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

impl BasicAuthenticator {
    /// Validate the authenticator's configuration.
    fn validate(&self) -> Result<(), Error> {
        if self.username.is_empty() {
            return Err(Error::ConfigError("missing username".into()));
        }
        if self.username.contains(':') {
            return Err(Error::ConfigError("username cannot contain ':'".into()));
        }
        if self.password.is_empty() {
            return Err(Error::ConfigError("missing password".into()));
        }
        Ok(())
    }
}

impl Drop for BasicAuthenticator {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[async_trait::async_trait]
impl Authenticator for BasicAuthenticator {
    /// Configure the authenticator with a JSON value. This implementation expects a JSON object with "username" and "password" fields.
    fn configure(&mut self, config: &serde_json::Value) -> Result<(), Error> {
        *self = serde_json::from_value(config.clone())
            .map_err(|error| Error::ConfigError(error.to_string()))?;
        self.validate()
    }

    /// Encode the Authorization header. This implementation generates a Basic Authorization header.
    async fn encode_header(&mut self) -> Result<String, Error> {
        self.validate()?;
        let credentials = Zeroizing::new(format!("{}:{}", self.username, self.password));
        let encoded_credentials = Zeroizing::new(STANDARD.encode(credentials.as_bytes()));
        Ok(format!("Basic {}", encoded_credentials.as_str()))
    }
}

/// An OAuth2 authenticator that uses the Resource Owner Password Credentials grant to obtain an access token and generate a Bearer Authorization header.
#[derive(Default, Deserialize)]
pub struct Oauth2Authenticator {
    #[serde(default)]
    token_url: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    ca_certs: Vec<String>,
    /// Space-delimited list of scopes to request (RFC 6749, section 3.3). Defaults to
    /// [DEFAULT_SCOPE] when not set; an empty string omits the scope parameter, leaving the scope
    /// up to the identity provider.
    #[serde(default)]
    scope: Option<String>,
    #[serde(skip)]
    token: Option<CachedTokenResponse>,
}

#[derive(Deserialize)]
struct Oauth2TokenResponse {
    access_token: Zeroizing<String>,
    #[serde(deserialize_with = "deserialize_basic_token_type")]
    token_type: BasicTokenType,
    expires_in: Option<u64>,
}

fn deserialize_basic_token_type<'de, D>(deserializer: D) -> Result<BasicTokenType, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(match value.to_ascii_lowercase().as_str() {
        "bearer" => BasicTokenType::Bearer,
        "mac" => BasicTokenType::Mac,
        _ => BasicTokenType::Extension(value),
    })
}

/// A cached OAuth2 token response with the time its request started.
struct CachedTokenResponse {
    response: Oauth2TokenResponse,
    requested_at: std::time::Instant,
}

impl CachedTokenResponse {
    // If expiry is not given then do not cache the token, and always obtain a new one.
    fn is_expired(&self) -> bool {
        self.response.expires_in.is_none_or(|expiry| {
            let usable_for = Duration::from_secs(expiry).saturating_sub(TOKEN_EXPIRY_MARGIN);
            self.requested_at.elapsed() >= usable_for
        })
    }
}

impl Drop for Oauth2Authenticator {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        self.password.zeroize();
    }
}

impl Oauth2Authenticator {
    /// Validate the authenticator's configuration.
    fn validate(&self) -> Result<(), Error> {
        for (value, name) in [
            (&self.client_id, "client_id"),
            (&self.client_secret, "client_secret"),
            (&self.token_url, "token_url"),
            (&self.username, "username"),
            (&self.password, "password"),
        ] {
            if value.is_empty() {
                return Err(Error::ConfigError(format!("missing {name}")));
            }
        }
        Url::parse(&self.token_url)
            .map_err(|error| Error::ConfigError(format!("invalid token_url: {error}")))?;
        Ok(())
    }

    /// Obtain an OAuth2 token response using the Resource Owner Password Credentials grant.
    async fn obtain_token(&self) -> Result<Oauth2TokenResponse, Error> {
        self.request_token(TOKEN_REQUEST_TIMEOUT).await
    }

    /// Send a token request, failing if the request and response take longer than `timeout`.
    async fn request_token(&self, timeout: Duration) -> Result<Oauth2TokenResponse, Error> {
        self.validate()?;
        let client = new_tls_client(&self.ca_certs)?;
        // Build the body in its own scope: the serializer is not Send, so it must not be held
        // across the await points below.
        let body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "password")
                .append_pair("username", &self.username)
                .append_pair("password", &self.password);
            match self.scope.as_deref().unwrap_or(DEFAULT_SCOPE) {
                "" => {}
                scope => {
                    form.append_pair("scope", scope);
                }
            }
            form.finish()
        };
        let timed_out = || {
            Error::ApiError(format!(
                "OAuth2 token request to {} timed out after {timeout:?}",
                self.token_url
            ))
        };
        // RFC 6749, section 2.3.1: the client credentials are form-urlencoded before being used
        // as the HTTP Basic username and password
        let client_id: String =
            url::form_urlencoded::byte_serialize(self.client_id.as_bytes()).collect();
        let client_secret: Zeroizing<String> = Zeroizing::new(
            url::form_urlencoded::byte_serialize(self.client_secret.as_bytes()).collect(),
        );
        let response = client
            .post(&self.token_url)
            .basic_auth(client_id, Some(client_secret.as_str()))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .timeout(timeout)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    timed_out()
                } else {
                    error.into()
                }
            })?
            .error_for_status()?;
        let token: Oauth2TokenResponse = response.json().await.map_err(|error| {
            if error.is_timeout() {
                timed_out()
            } else {
                error.into()
            }
        })?;
        if token.token_type != BasicTokenType::Bearer {
            return Err(Error::ConfigError(format!(
                "unsupported OAuth2 token type: {}",
                token.token_type.as_ref()
            )));
        }
        Ok(token)
    }

    /// Obtain a valid access token, transparently refreshing the cached token when needed.
    async fn get_access_token(&mut self) -> Result<Zeroizing<String>, Error> {
        let expired = self
            .token
            .as_ref()
            .is_none_or(CachedTokenResponse::is_expired);
        if expired {
            let requested_at = std::time::Instant::now();
            self.token = Some(CachedTokenResponse {
                response: self.obtain_token().await?,
                requested_at,
            });
        }
        Ok(Zeroizing::new(
            self.token
                .as_ref()
                .expect("token was just obtained")
                .response
                .access_token
                .to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl Authenticator for Oauth2Authenticator {
    /// Configure the authenticator with a JSON value. This implementation expects
    /// a JSON object with "token_url", "client_id", "client_secret", "username",
    /// and "password" fields, and optional "ca_certs" and "scope" fields.
    fn configure(&mut self, config: &serde_json::Value) -> Result<(), Error> {
        *self = serde_json::from_value(config.clone())
            .map_err(|error| Error::ConfigError(error.to_string()))?;
        self.validate()
    }

    /// Encode the Authorization header. This implementation obtains an access token
    /// if necessary and generates a Bearer Authorization header.
    async fn encode_header(&mut self) -> Result<String, Error> {
        let access_token = self.get_access_token().await?;
        Ok(format!("Bearer {}", access_token.as_str()))
    }
}

/// Build a reqwest client with system roots and additional PEM CA certificates.
pub fn new_tls_client<I, P>(cert_paths: I) -> Result<ClientWithMiddleware, Error>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut builder = HttpClientBuilder::new();
    for path in cert_paths {
        builder = builder.with_root_certificate(PathBuf::from(path.as_ref()));
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::str::FromStr;
    use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

    #[async_std::test]
    async fn null_authenticator_has_no_header() {
        let mut authenticator = NullAuthenticator;
        assert!(authenticator.configure(&json!({"ignored": true})).is_ok());
        assert_eq!(authenticator.encode_header().await.unwrap(), "");
    }

    #[test]
    fn method_parsing_matches_upstream_values() {
        assert!(matches!(
            Method::from_str("none").unwrap(),
            Method::Passthrough
        ));
        assert!(matches!(
            Method::from_str("passthrough").unwrap(),
            Method::Passthrough
        ));
        assert!(matches!(Method::from_str("basic").unwrap(), Method::Basic));
        assert!(matches!(
            Method::from_str("oauth2").unwrap(),
            Method::Oauth2
        ));
        assert!(Method::from_str("unknown").is_err());
    }

    #[async_std::test]
    async fn basic_authenticator_configures_and_encodes_header() {
        let mut authenticator = BasicAuthenticator::default();
        authenticator
            .configure(&json!({"username": "user1", "password": "Passw0rd!"}))
            .unwrap();
        assert_eq!(
            authenticator.encode_header().await.unwrap(),
            "Basic dXNlcjE6UGFzc3cwcmQh"
        );
    }

    #[async_std::test]
    async fn basic_authenticator_rejects_missing_credentials() {
        let mut authenticator = BasicAuthenticator::default();
        let error = authenticator
            .configure(&json!({"username": "user1"}))
            .unwrap_err();
        assert_eq!(error.to_string(), "configuration error: missing password");

        // println!(""reached here");
        let error = BasicAuthenticator::default()
            .encode_header()
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "configuration error: missing username");
    }

    #[async_std::test]
    async fn oauth2_authenticator_obtains_and_reuses_token() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .and(matchers::header(
                "authorization",
                "Basic bXljbGllbnQ6c2VjcmV0",
            ))
            .and(matchers::body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-1",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut authenticator = Oauth2Authenticator::default();
        authenticator
            .configure(&json!({
                "token_url": format!("{}/token", server.uri()),
                "client_id": "myclient",
                "client_secret": "secret",
                "username": "user1",
                "password": "Passw0rd!"
            }))
            .unwrap();

        assert_eq!(
            authenticator.encode_header().await.unwrap(),
            "Bearer token-1"
        );
        assert_eq!(
            authenticator.encode_header().await.unwrap(),
            "Bearer token-1"
        );
    }

    #[async_std::test]
    async fn oauth2_authenticator_refreshes_expired_token() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token-expired",
                "token_type": "Bearer",
                "expires_in": 0
            })))
            .expect(2)
            .mount(&server)
            .await;

        let mut authenticator = Oauth2Authenticator::default();
        authenticator
            .configure(&json!({
                "token_url": format!("{}/token", server.uri()),
                "client_id": "client",
                "client_secret": "secret",
                "username": "user",
                "password": "password"
            }))
            .unwrap();

        assert_eq!(
            authenticator.encode_header().await.unwrap(),
            "Bearer token-expired"
        );
        assert_eq!(
            authenticator.encode_header().await.unwrap(),
            "Bearer token-expired"
        );
    }

    fn cached_token(expires_in: Option<u64>, age: Duration) -> CachedTokenResponse {
        CachedTokenResponse {
            response: Oauth2TokenResponse {
                access_token: Zeroizing::new("token".into()),
                token_type: BasicTokenType::Bearer,
                expires_in,
            },
            requested_at: std::time::Instant::now()
                .checked_sub(age)
                .expect("monotonic clock is past the test age"),
        }
    }

    #[test]
    fn cached_token_expires_before_advertised_expiry_by_margin() {
        assert!(!cached_token(Some(100), Duration::from_secs(60)).is_expired());
        assert!(cached_token(Some(100), Duration::from_secs(70)).is_expired());
    }

    #[test]
    fn cached_token_lifetime_must_exceed_expiry_margin() {
        assert!(cached_token(Some(0), Duration::ZERO).is_expired());
        assert!(cached_token(Some(30), Duration::ZERO).is_expired());
        assert!(!cached_token(Some(31), Duration::ZERO).is_expired());
        assert!(cached_token(Some(31), Duration::from_secs(1)).is_expired());
    }

    #[test]
    fn cached_token_without_expiry_is_not_reused() {
        assert!(cached_token(None, Duration::ZERO).is_expired());
    }

    #[async_std::test]
    async fn oauth2_token_request_times_out() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(200))
                    .set_body_json(json!({
                        "access_token": "token",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let mut authenticator = Oauth2Authenticator::default();
        authenticator
            .configure(&json!({
                "token_url": format!("{}/token", server.uri()),
                "client_id": "client",
                "client_secret": "secret",
                "username": "user",
                "password": "password"
            }))
            .unwrap();

        let error = authenticator
            .request_token(Duration::from_millis(20))
            .await
            .err()
            .expect("token request should time out");
        let error = error.to_string();
        assert!(error.contains("OAuth2 token request to"), "{error}");
        assert!(error.contains("timed out after 20ms"), "{error}");
    }

    #[test]
    fn oauth2_authenticator_validates_configuration() {
        let mut authenticator = Oauth2Authenticator::default();
        let error = authenticator
            .configure(&json!({"token_url": "https://example.com/token", "client_id": "client"}))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "configuration error: missing client_secret"
        );
    }

    #[test]
    fn tls_client_reports_missing_ca_file() {
        let error = new_tls_client(["/does/not/exist.pem"]).unwrap_err();
        assert!(error.to_string().contains("No such file or directory"));
    }

    #[test]
    fn tls_client_accepts_multiple_ca_files() {
        let root_cert = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/veraison-root.crt");
        new_tls_client([&root_cert, &root_cert]).unwrap();
    }

    #[test]
    fn oauth2_token_response_deserializes_and_preserves_optional_expiry() {
        let token: Oauth2TokenResponse = serde_json::from_value(json!({
            "access_token": "token",
            "token_type": "Bearer"
        }))
        .unwrap();
        assert_eq!(token.access_token.as_str(), "token");
        assert_eq!(token.token_type, BasicTokenType::Bearer);
        assert!(token.expires_in.is_none());
    }

    #[async_std::test]
    async fn oauth2_authenticator_rejects_non_bearer_token_type() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "token",
                "token_type": "mac",
                "expires_in": 3600
            })))
            .mount(&server)
            .await;

        let mut authenticator = Oauth2Authenticator::default();
        authenticator
            .configure(&json!({
                "token_url": format!("{}/token", server.uri()),
                "client_id": "client",
                "client_secret": "secret",
                "username": "user",
                "password": "password"
            }))
            .unwrap();

        let error = authenticator.encode_header().await.unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported OAuth2 token type: mac"));
    }
}
