// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    auth::Authenticator,
    http::{ConfigureHttp, HttpClientBuilder},
    Error,
};
use chrono::{DateTime, Utc};
use http_cache_reqwest::{CacheMode, HttpCacheOptions};
use reqwest::{header, StatusCode};
use std::{path::PathBuf, str::FromStr, time::Duration};
use url::Url;
use uuid::Uuid;

#[cfg(feature = "disk-caching")]
use http_cache_reqwest::CACacheManager;

#[cfg(feature = "memory-caching")]
use http_cache_reqwest::MokaManager;

const OPA_RULES_MEDIA_TYPE: &str = "application/vnd.veraison.policy.opa";
const POLICY_MEDIA_TYPE: &str = "application/vnd.veraison.policy+json";
const POLICIES_MEDIA_TYPE: &str = "application/vnd.veraison.policies+json";

/// Policy allows enforcing additional constraints on top of the regular
/// attestation schemes.
#[derive(Clone, Debug, serde::Deserialize, PartialEq)]
pub struct Policy {
    /// uuid is the unique identifier associated with the specific instance
    /// of a policy.
    pub uuid: Uuid,
    /// ctime is the creation time of the policy.
    pub ctime: DateTime<Utc>,
    /// name is the name of the policy. It's a short descriptor for the
    /// rules in the policy.
    pub name: String,
    /// type identifies the policy engine used to evaluate the policy, and
    /// therefore dictates how the Rules should be interpreted.
    #[serde(rename = "type")]
    pub policy_type: String,
    /// rules of the policy to be interpreted and executed by the policy
    /// agent.
    pub rules: String,
    /// active indicates whether the policy instance is currently active
    /// for the associated key.
    pub active: bool,
}

/// A builder for [PolicyManager] objects.
pub struct PolicyManagerBuilder {
    http_client_builder: HttpClientBuilder,
    base_url: Option<String>,
}

impl PolicyManagerBuilder {
    /// default constructor
    pub fn new() -> Self {
        Self {
            http_client_builder: HttpClientBuilder::new(),
            base_url: None,
        }
    }

    /// Set the management API base URL, for example `https://veraison.example/`.
    pub fn with_base_url(mut self, value: String) -> Self {
        self.base_url = Some(value);
        self
    }

    /// Configure the authenticator used for management API requests.
    pub fn with_authenticator<A>(mut self, authenticator: A) -> Self
    where
        A: Authenticator + Send + 'static,
    {
        self.http_client_builder = self.http_client_builder.with_authenticator(authenticator);
        self
    }

    /// Instantiate a valid [PolicyManager] object, or fail with an error.
    pub fn build(self) -> Result<PolicyManager, Error> {
        let Some(base_url) = &self.base_url else {
            return Err(Error::ConfigError(
                "missing management API endpoint".to_string(),
            ));
        };
        let base_url = url::Url::parse(base_url)
            .map_err(|e| Error::ConfigError(format!("could not parse URL: {e}")))?;

        if base_url.cannot_be_a_base()
            || !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
        {
            return Err(Error::ConfigError(format!(
                "invalid management API URL \"{base_url}\": expected an HTTP(S) URL with a host"
            )));
        }

        Ok(PolicyManager {
            base_url,
            http_client: self.http_client_builder.build()?,
        })
    }
}

impl ConfigureHttp for PolicyManagerBuilder {
    fn with_root_certificate(mut self, value: PathBuf) -> Self {
        self.http_client_builder = self.http_client_builder.with_root_certificate(value);
        self
    }

    fn no_check_certificate(mut self) -> Self {
        self.http_client_builder = self.http_client_builder.no_check_certificate();
        self
    }

    #[cfg(feature = "disk-caching")]
    fn with_disk_cache(mut self, value: CACacheManager) -> Self {
        self.http_client_builder = self.http_client_builder.with_disk_cache(value);
        self
    }

    #[cfg(feature = "memory-caching")]
    fn with_memory_cache(mut self, value: MokaManager) -> Self {
        self.http_client_builder = self.http_client_builder.with_memory_cache(value);
        self
    }

    fn with_cache_mode(mut self, value: CacheMode) -> Self {
        self.http_client_builder = self.http_client_builder.with_cache_mode(value);
        self
    }

    fn with_http_cache_options(mut self, value: HttpCacheOptions) -> Self {
        self.http_client_builder = self.http_client_builder.with_http_cache_options(value);
        self
    }

    fn with_timeout(mut self, value: Duration) -> Self {
        self.http_client_builder = self.http_client_builder.with_timeout(value);
        self
    }
}

impl Default for PolicyManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Client for Veraison management policy operations.
pub struct PolicyManager {
    base_url: Url,
    http_client: reqwest_middleware::ClientWithMiddleware,
}

impl PolicyManager {
    /// Check if the response has the expected content type.
    fn content_type_is(response: &reqwest::Response, expected: &str) -> bool {
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<mime::Mime>().ok())
            .map(|value| value.essence_str().to_owned())
            == Some(expected.to_owned())
    }

    /// Build a discovered management endpoint below the configured base URL, preserving any base path.
    fn build_endpoint(
        &self,
        endpoint_template: &str,
        scheme: &str,
        policy_id: Option<Uuid>,
    ) -> Result<Url, Error> {
        if scheme.is_empty()
            || matches!(scheme, "." | "..")
            || scheme.contains('/')
            || scheme.contains('\\')
        {
            return Err(Error::ConfigError(format!(
                "invalid attestation scheme: {scheme:?}"
            )));
        }
        if !endpoint_template.starts_with('/')
            || endpoint_template.contains('?')
            || endpoint_template.contains('#')
            || endpoint_template.contains('\\')
            || endpoint_template
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
        {
            return Err(Error::ConfigError(format!(
                "invalid management API endpoint template: {endpoint_template:?}"
            )));
        }

        let mut url = self.base_url.clone();
        let policy_id = policy_id.map_or_else(String::new, |id| id.to_string());
        url.set_query(None);
        url.set_fragment(None);
        {
            let mut path_segments = url.path_segments_mut().map_err(|_| {
                Error::ConfigError("management API URL cannot be used as a base".into())
            })?;
            path_segments.pop_if_empty().extend(
                endpoint_template
                    .split('/')
                    .filter(|segment| !segment.is_empty())
                    .map(|segment| match segment {
                        ":scheme" => scheme,
                        ":uuid" => policy_id.as_str(),
                        segment => segment,
                    }),
            );
        }
        Ok(url)
    }

    /// Expect a specific HTTP status code from a response.
    async fn expect_status(
        response: reqwest::Response,
        expected: StatusCode,
    ) -> Result<reqwest::Response, Error> {
        let status = response.status();
        if status != expected {
            let body = response.text().await.unwrap_or_default();
            let detail = if body.is_empty() {
                String::new()
            } else {
                format!(": {body}")
            };
            return Err(Error::ApiError(format!(
                "unexpected HTTP response code {status} (expected {expected}){detail}"
            )));
        }
        Ok(response)
    }

    /// Get a [Policy] from a response.
    async fn policy_from_response(response: reqwest::Response) -> Result<Policy, Error> {
        if !Self::content_type_is(&response, POLICY_MEDIA_TYPE) {
            return Err(Error::ApiError(
                "policy response with unexpected content type".into(),
            ));
        }
        response
            .json()
            .await
            .map_err(|error| Error::ApiError(format!("failure decoding policy: {error}")))
    }

    /// Get a list of [Policy] objects from a response.
    async fn policies_from_response(response: reqwest::Response) -> Result<Vec<Policy>, Error> {
        if !Self::content_type_is(&response, POLICIES_MEDIA_TYPE) {
            return Err(Error::ApiError(
                "policies response with unexpected content type".into(),
            ));
        }
        response
            .json()
            .await
            .map_err(|error| Error::ApiError(format!("failure decoding policies: {error}")))
    }

    /// Create an OPA policy using the discovered `createPolicy` endpoint.
    ///
    /// Obtain `endpoint_template` from `ManagementApi::get_api_endpoint("createPolicy")`, which is like `/management/v1/policy/:scheme`.
    pub async fn create_opa_policy(
        &self,
        scheme: &str,
        endpoint_template: &str,
        rules: Vec<u8>,
        name: Option<&str>,
    ) -> Result<Policy, Error> {
        self.create_policy(scheme, endpoint_template, OPA_RULES_MEDIA_TYPE, rules, name)
            .await
    }

    /// Create a policy using the discovered `createPolicy` endpoint and supplied content type.
    ///
    /// Obtain `endpoint_template` from `ManagementApi::get_api_endpoint("createPolicy")`, which is like `/management/v1/policy/:scheme`.
    pub async fn create_policy(
        &self,
        scheme: &str,
        endpoint_template: &str,
        content_type: &str,
        rules: Vec<u8>,
        name: Option<&str>,
    ) -> Result<Policy, Error> {
        let mut url = self.build_endpoint(endpoint_template, scheme, None)?;
        if let Some(name) = name {
            url.query_pairs_mut().append_pair("name", name);
        }
        let response = self
            .http_client
            .post(url)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::ACCEPT, POLICY_MEDIA_TYPE)
            .body(rules)
            .send()
            .await?;
        Self::policy_from_response(Self::expect_status(response, StatusCode::CREATED).await?).await
    }

    /// Activate a policy, deactivating the previously active policy for the scheme.
    ///
    /// Obtain `endpoint_template` from `ManagementApi::get_api_endpoint("activatePolicy")`, which is like `/management/v1/policy/:scheme/:uuid/activate`.
    pub async fn activate_policy(
        &self,
        scheme: &str,
        endpoint_template: &str,
        policy_id: Uuid,
    ) -> Result<(), Error> {
        let response = self
            .http_client
            .post(self.build_endpoint(endpoint_template, scheme, Some(policy_id))?)
            .header(header::ACCEPT, POLICY_MEDIA_TYPE)
            .send()
            .await?;
        Self::expect_status(response, StatusCode::OK).await?;
        Ok(())
    }

    /// Deactivate all policies for a scheme.
    ///
    /// Obtain `endpoint_template` from `ManagementApi::get_api_endpoint("deactivatePolicies")`, which is like `/management/v1/policy/:scheme/deactivate`.
    pub async fn deactivate_all_policies(
        &self,
        scheme: &str,
        endpoint_template: &str,
    ) -> Result<(), Error> {
        let response = self
            .http_client
            .post(self.build_endpoint(endpoint_template, scheme, None)?)
            .header(header::ACCEPT, POLICY_MEDIA_TYPE)
            .send()
            .await?;
        Self::expect_status(response, StatusCode::OK).await?;
        Ok(())
    }

    /// Get the currently active policy for a scheme.
    ///
    /// Obtain `endpoint_template` from `ManagementApi::get_api_endpoint("getActivePolicy")`, which is like `/management/v1/policy/:scheme/active`.
    pub async fn get_active_policy(
        &self,
        scheme: &str,
        endpoint_template: &str,
    ) -> Result<Policy, Error> {
        let response = self
            .http_client
            .get(self.build_endpoint(endpoint_template, scheme, None)?)
            .header(header::ACCEPT, POLICY_MEDIA_TYPE)
            .send()
            .await?;
        Self::policy_from_response(Self::expect_status(response, StatusCode::OK).await?).await
    }

    /// Get a policy by scheme and ID.
    ///
    /// Obtain `endpoint_template` from `ManagementApi::get_api_endpoint("getPolicy")`, which is like `/management/v1/policy/:scheme/:uuid`.
    pub async fn get_policy(
        &self,
        scheme: &str,
        endpoint_template: &str,
        policy_id: Uuid,
    ) -> Result<Policy, Error> {
        let response = self
            .http_client
            .get(self.build_endpoint(endpoint_template, scheme, Some(policy_id))?)
            .header(header::ACCEPT, POLICY_MEDIA_TYPE)
            .send()
            .await?;
        Self::policy_from_response(Self::expect_status(response, StatusCode::OK).await?).await
    }

    /// Get policies for a scheme, optionally filtered by name.
    ///
    /// Obtain `endpoint_template` from `ManagementApi::get_api_endpoint("getPolicies")`, which is like `/management/v1/policies/:scheme`.
    pub async fn get_policies(
        &self,
        scheme: &str,
        endpoint_template: &str,
        name: Option<&str>,
    ) -> Result<Vec<Policy>, Error> {
        let mut url = self.build_endpoint(endpoint_template, scheme, None)?;
        if let Some(name) = name {
            url.query_pairs_mut().append_pair("name", name);
        }
        let response = self
            .http_client
            .get(url)
            .header(header::ACCEPT, POLICIES_MEDIA_TYPE)
            .send()
            .await?;
        Self::policies_from_response(Self::expect_status(response, StatusCode::OK).await?).await
    }
}

impl FromStr for Policy {
    type Err = serde_json::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{Authenticator, Oauth2Authenticator},
        DiscoveryBuilder, ServiceState,
    };
    use serde_json::json;
    use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

    const CREATE_POLICY_ENDPOINT: &str = "/management/v1/policy/:scheme";
    const GET_POLICY_ENDPOINT: &str = "/management/v1/policy/:scheme/:uuid";
    const DEACTIVATE_POLICIES_ENDPOINT: &str = "/management/v1/policies/:scheme/deactivate";
    const GET_ACTIVE_POLICY_ENDPOINT: &str = "/management/v1/policy/:scheme";
    const ACTIVATE_POLICY_ENDPOINT: &str = "/management/v1/policy/:scheme/:uuid/activate";
    const GET_POLICIES_ENDPOINT: &str = "/management/v1/policies/:scheme";

    fn policy_json(id: Uuid) -> serde_json::Value {
        json!({
            "uuid": id,
            "ctime": "2026-08-20T12:00:00Z",
            "name": "test_name",
            "type": "opa",
            "rules": "test rule",
            "active": true
        })
    }

    async fn runner(server: &MockServer) -> PolicyManager {
        PolicyManagerBuilder::new()
            .with_base_url(server.uri().to_string())
            .build()
            .unwrap()
    }

    fn assert_management_endpoint(
        management_api: &crate::ManagementApi,
        name: &str,
        expected: &str,
    ) {
        assert_eq!(
            management_api.get_api_endpoint(name),
            Some(expected.to_owned()),
            "missing or unexpected management endpoint: {name}"
        );
    }

    fn endpoint_path(template: &str, scheme: &str, policy_id: Option<Uuid>) -> String {
        template.replace(":scheme", scheme).replace(
            ":uuid",
            &policy_id.map_or_else(String::new, |id| id.to_string()),
        )
    }

    #[test]
    fn endpoint_preserves_base_path_with_attestation_scheme() {
        let manager = PolicyManagerBuilder::new()
            .with_base_url("https://example.test/proxy-needed/?old=query#fragment".into())
            .build()
            .unwrap();

        let endpoint = manager
            .build_endpoint(GET_ACTIVE_POLICY_ENDPOINT, "ARM_CCA", None)
            .unwrap();

        assert_eq!(
            endpoint.as_str(),
            "https://example.test/proxy-needed/management/v1/policy/ARM_CCA"
        );
    }

    #[test]
    fn endpoint_rejects_empty_or_path_traversal_scheme() {
        let manager = PolicyManagerBuilder::new()
            .with_base_url("https://example.test/proxy-needed/".into())
            .build()
            .unwrap();

        for scheme in ["", ".", "..", "ARM/CCA", "ARM\\CCA"] {
            assert!(
                manager
                    .build_endpoint(GET_ACTIVE_POLICY_ENDPOINT, scheme, None)
                    .is_err(),
                "scheme should be rejected: {scheme:?}"
            );
        }
    }

    #[test]
    fn endpoint_encodes_scheme_as_single_segment() {
        let manager = PolicyManagerBuilder::new()
            .with_base_url("https://example.test/".into())
            .build()
            .unwrap();
        for (scheme, expected) in [
            (
                "%2e%2e",
                "https://example.test/management/v1/policy/%252e%252e",
            ),
            (
                "a?b#c",
                "https://example.test/management/v1/policy/a%3Fb%23c",
            ),
        ] {
            let url = manager
                .build_endpoint(GET_ACTIVE_POLICY_ENDPOINT, scheme, None)
                .unwrap();
            assert_eq!(url.as_str(), expected, "scheme: {scheme}");
        }
    }

    #[test]
    fn builder_rejects_non_base_url() {
        // "localhost:8088" (missing "https://") parses with "localhost" as the URL scheme.
        for base_url in [
            "localhost:8088",
            "mailto:admin@example.com",
            "ftp://example.com/",
            "file:///tmp",
        ] {
            let Err(error) = PolicyManagerBuilder::new()
                .with_base_url(base_url.to_string())
                .build()
            else {
                panic!("a non-base URL should be rejected: {base_url}");
            };
            assert_eq!(
                error.to_string(),
                format!(
                    "configuration error: invalid management API URL \"{base_url}\": expected an HTTP(S) URL with a host"
                )
            );
        }
    }

    #[async_std::test]
    async fn get_policies_without_name_sends_no_filter() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path(endpoint_path(
                GET_POLICIES_ENDPOINT,
                "test_scheme",
                None,
            )))
            .respond_with(ResponseTemplate::new(200).set_body_raw("[]", POLICIES_MEDIA_TYPE))
            .expect(1)
            .mount(&server)
            .await;

        let policies = runner(&server)
            .await
            .get_policies("test_scheme", GET_POLICIES_ENDPOINT, None)
            .await
            .unwrap();
        assert!(policies.is_empty());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests[0].url.query(), None);
    }

    #[async_std::test]
    async fn policy_request_times_out() {
        let server = MockServer::start().await;
        Mock::given(matchers::any())
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let manager = PolicyManagerBuilder::new()
            .with_base_url(server.uri())
            .with_timeout(Duration::from_millis(200))
            .build()
            .unwrap();

        let error = manager
            .get_active_policy("ARM_CCA", GET_ACTIVE_POLICY_ENDPOINT)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("API error: request timed out"),
            "{error}"
        );
    }

    #[async_std::test]
    async fn create_opa_policy_using_management_endpoint() {
        let server = MockServer::start().await;
        let id = Uuid::new_v4();
        Mock::given(matchers::method("POST"))
            .and(matchers::path(endpoint_path(
                CREATE_POLICY_ENDPOINT,
                "test_scheme",
                None,
            )))
            .and(matchers::query_param("name", "test_name"))
            .and(matchers::header("content-type", OPA_RULES_MEDIA_TYPE))
            .and(matchers::header("accept", POLICY_MEDIA_TYPE))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("content-type", POLICY_MEDIA_TYPE)
                    .set_body_raw(policy_json(id).to_string(), POLICY_MEDIA_TYPE),
            )
            .mount(&server)
            .await;

        let policy = runner(&server)
            .await
            .create_opa_policy(
                "test_scheme",
                CREATE_POLICY_ENDPOINT,
                b"rule".to_vec(),
                Some("test_name"),
            )
            .await
            .unwrap();
        assert_eq!(policy.uuid, id);
        assert_eq!(policy.name, "test_name");
    }

    #[async_std::test]
    async fn policy_reads_and_state_operations_using_expected_paths() {
        let server = MockServer::start().await;
        let id = Uuid::new_v4();
        Mock::given(matchers::method("GET"))
            .and(matchers::path(endpoint_path(
                GET_POLICY_ENDPOINT,
                "test_scheme",
                Some(id),
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", POLICY_MEDIA_TYPE)
                    .set_body_raw(policy_json(id).to_string(), POLICY_MEDIA_TYPE),
            )
            .mount(&server)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path(endpoint_path(
                GET_ACTIVE_POLICY_ENDPOINT,
                "test_scheme",
                None,
            )))
            .and(matchers::header("accept", POLICY_MEDIA_TYPE))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", POLICY_MEDIA_TYPE)
                    .set_body_raw(policy_json(id).to_string(), POLICY_MEDIA_TYPE),
            )
            .mount(&server)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path(endpoint_path(
                GET_POLICIES_ENDPOINT,
                "test_scheme",
                None,
            )))
            .and(matchers::query_param("name", "test_name"))
            .and(matchers::header("accept", POLICIES_MEDIA_TYPE))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", POLICIES_MEDIA_TYPE)
                    .set_body_raw(
                        format!("[{}]", policy_json(id)).as_bytes(),
                        POLICIES_MEDIA_TYPE,
                    ),
            )
            .mount(&server)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path(endpoint_path(
                ACTIVATE_POLICY_ENDPOINT,
                "test_scheme",
                Some(id),
            )))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path(endpoint_path(
                DEACTIVATE_POLICIES_ENDPOINT,
                "test_scheme",
                None,
            )))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let runner = runner(&server).await;
        assert_eq!(
            runner
                .get_policy("test_scheme", GET_POLICY_ENDPOINT, id)
                .await
                .unwrap()
                .uuid,
            id
        );
        assert_eq!(
            runner
                .get_active_policy("test_scheme", GET_ACTIVE_POLICY_ENDPOINT)
                .await
                .unwrap()
                .uuid,
            id
        );
        assert_eq!(
            runner
                .get_policies("test_scheme", GET_POLICIES_ENDPOINT, Some("test_name"))
                .await
                .unwrap(),
            vec![Policy::from_str(&policy_json(id).to_string()).unwrap()]
        );
        runner
            .activate_policy("test_scheme", ACTIVATE_POLICY_ENDPOINT, id)
            .await
            .unwrap();
        runner
            .deactivate_all_policies("test_scheme", DEACTIVATE_POLICIES_ENDPOINT)
            .await
            .unwrap();
    }

    #[async_std::test]
    async fn submits_and_manages_cca_policy_using_mock_server() {
        let server = MockServer::start().await;
        let policy_id = Uuid::new_v4();
        let create_policy_endpoint = "/custom-management/policy/:scheme";
        let activate_policy_endpoint = "/custom-management/policy/:scheme/:uuid/activate";
        let get_active_policy_endpoint = "/custom-management/policy/:scheme";
        let deactivate_policies_endpoint = "/custom-management/policies/:scheme/deactivate";
        let policy_rules = r#"package policy

executables = APPROVED_RT {
  evidence["realm"]["cca-realm-initial-measurement"] == "MRMUq3NiA1DPdYg0rlxl2ejC3H/r5ufZZUu+hk4wDUk="
} else = CONTRAINDICATED_RT
"#;
        let policy_response = json!({
            "uuid": policy_id,
            "ctime": "2026-09-08T16:08:59.660798394Z",
            "name": "default",
            "type": "opa",
            "rules": policy_rules,
            "active": false
        });

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/.well-known/veraison/management"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/vnd.veraison.discovery+json")
                    .set_body_json(json!({
                        "attestation-schemes": ["ARM_CCA"],
                        "version": "0.0.2608+f7d0bd7",
                        "service-state": "READY",
                        "api-endpoints": {
                            "createPolicy": create_policy_endpoint,
                            "activatePolicy": activate_policy_endpoint,
                            "getActivePolicy": get_active_policy_endpoint,
                            "deactivatePolicies": deactivate_policies_endpoint
                        }
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "mock-management-token",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path(endpoint_path(
                create_policy_endpoint,
                "ARM_CCA",
                None,
            )))
            .and(matchers::header("content-type", OPA_RULES_MEDIA_TYPE))
            .and(matchers::header("accept", POLICY_MEDIA_TYPE))
            .and(matchers::body_string(policy_rules))
            .respond_with(
                ResponseTemplate::new(201)
                    .insert_header("content-type", POLICY_MEDIA_TYPE)
                    .set_body_raw(policy_response.to_string(), POLICY_MEDIA_TYPE),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path(endpoint_path(
                activate_policy_endpoint,
                "ARM_CCA",
                Some(policy_id),
            )))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path(endpoint_path(
                get_active_policy_endpoint,
                "ARM_CCA",
                None,
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", POLICY_MEDIA_TYPE)
                    .set_body_raw(policy_response.to_string(), POLICY_MEDIA_TYPE),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path(endpoint_path(
                deactivate_policies_endpoint,
                "ARM_CCA",
                None,
            )))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let discovery = DiscoveryBuilder::new()
            .with_base_url(server.uri())
            .build()
            .expect("failed to create Discovery client");
        let management_api = discovery
            .get_management_api()
            .await
            .expect("failed to get management endpoint details");

        assert_eq!(management_api.service_state(), &ServiceState::Ready);
        assert!(management_api
            .attestation_schemes()
            .contains(&"ARM_CCA".to_string()));

        let mut authenticator = Oauth2Authenticator::default();
        authenticator
            .configure(&json!({
                "token_url": format!("{}/token", server.uri()),
                "client_id": "veraison-client",
                "client_secret": "YifmabB4cVSPPtFLAmHfq7wKaEHQn10Z",
                "username": "veraison-manager",
                "password": "veraison"
            }))
            .expect("invalid OAuth2 configuration");

        let runner = PolicyManagerBuilder::new()
            .with_base_url(server.uri().to_string())
            .with_authenticator(authenticator)
            .build()
            .expect("failed to build management client");

        assert_management_endpoint(&management_api, "createPolicy", create_policy_endpoint);
        let policy = runner
            .create_opa_policy(
                "ARM_CCA",
                &management_api
                    .get_api_endpoint("createPolicy")
                    .expect("missing createPolicy endpoint"),
                policy_rules.as_bytes().to_vec(),
                None,
            )
            .await
            .expect("failed to submit policy");

        assert_eq!(policy.uuid, policy_id);
        assert_eq!(policy.name, "default");
        assert_eq!(policy.policy_type, "opa");
        assert_eq!(policy.rules, policy_rules);
        assert!(!policy.active);

        assert_management_endpoint(&management_api, "activatePolicy", activate_policy_endpoint);
        runner
            .activate_policy(
                "ARM_CCA",
                &management_api
                    .get_api_endpoint("activatePolicy")
                    .expect("missing activatePolicy endpoint"),
                policy.uuid,
            )
            .await
            .expect("failed to activate policy");
        assert_management_endpoint(
            &management_api,
            "getActivePolicy",
            get_active_policy_endpoint,
        );
        assert_eq!(
            runner
                .get_active_policy(
                    "ARM_CCA",
                    &management_api
                        .get_api_endpoint("getActivePolicy")
                        .expect("missing getActivePolicy endpoint"),
                )
                .await
                .unwrap()
                .uuid,
            policy_id
        );
        assert_management_endpoint(
            &management_api,
            "deactivatePolicies",
            deactivate_policies_endpoint,
        );
        runner
            .deactivate_all_policies(
                "ARM_CCA",
                &management_api
                    .get_api_endpoint("deactivatePolicies")
                    .expect("missing deactivatePolicies endpoint"),
            )
            .await
            .expect("failed to deactivate policies");
    }
}
