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
use std::{path::PathBuf, str::FromStr};
use url::Url;
use uuid::Uuid;

#[cfg(feature = "disk-caching")]
use http_cache_reqwest::CACacheManager;

#[cfg(feature = "memory-caching")]
use http_cache_reqwest::{MokaCache, MokaManager};

const OPA_RULES_MEDIA_TYPE: &str = "application/vnd.veraison.policy.opa";
const POLICY_MEDIA_TYPE: &str = "application/vnd.veraison.policy+json";
const POLICIES_MEDIA_TYPE: &str = "application/vnd.veraison.policies+json";
const CREATE_POLICY_ENDPOINT: &str = "/management/v1/policy/:scheme";
const GET_POLICY_ENDPOINT: &str = "/management/v1/policy/:scheme/:uuid";
const DEACTIVATE_POLICIES_ENDPOINT: &str = "/management/v1/policies/:scheme/deactivate";
const GET_ACTIVE_POLICY_ENDPOINT: &str = "/management/v1/policy/:scheme";
const ACTIVATE_POLICY_ENDPOINT: &str = "/management/v1/policy/:scheme/:uuid/activate";
const GET_POLICIES_ENDPOINT: &str = "/management/v1/policies/:scheme";

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

    /// Construct a URL from a management API endpoint template.
    fn endpoint(&self, template: &str, scheme: &str, policy_id: Option<Uuid>) -> Url {
        let mut url = self.base_url.clone();
        let path = template.replace(":scheme", scheme).replace(
            ":uuid",
            &policy_id.map_or_else(String::new, |id| id.to_string()),
        );
        url.set_path(&path);
        url.set_query(None);
        url
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

    /// Create an OPA policy.
    pub async fn create_opa_policy(
        &self,
        scheme: &str,
        rules: Vec<u8>,
        name: &str,
    ) -> Result<Policy, Error> {
        self.create_policy(scheme, OPA_RULES_MEDIA_TYPE, rules, name)
            .await
    }

    /// Create a policy using the supplied policy engine content type.
    pub async fn create_policy(
        &self,
        scheme: &str,
        content_type: &str,
        rules: Vec<u8>,
        name: &str,
    ) -> Result<Policy, Error> {
        let mut url = self.endpoint(CREATE_POLICY_ENDPOINT, scheme, None);
        if !name.is_empty() {
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
    pub async fn activate_policy(&self, scheme: &str, policy_id: Uuid) -> Result<(), Error> {
        let response = self
            .http_client
            .post(self.endpoint(ACTIVATE_POLICY_ENDPOINT, scheme, Some(policy_id)))
            .header(header::ACCEPT, POLICY_MEDIA_TYPE)
            .send()
            .await?;
        Self::expect_status(response, StatusCode::OK).await?;
        Ok(())
    }

    /// Deactivate all policies for a scheme.
    pub async fn deactivate_all_policies(&self, scheme: &str) -> Result<(), Error> {
        let response = self
            .http_client
            .post(self.endpoint(DEACTIVATE_POLICIES_ENDPOINT, scheme, None))
            .header(header::ACCEPT, POLICY_MEDIA_TYPE)
            .send()
            .await?;
        Self::expect_status(response, StatusCode::OK).await?;
        Ok(())
    }

    /// Get the currently active policy for a scheme.
    pub async fn get_active_policy(&self, scheme: &str) -> Result<Policy, Error> {
        let response = self
            .http_client
            .get(self.endpoint(GET_ACTIVE_POLICY_ENDPOINT, scheme, None))
            .header(header::ACCEPT, POLICY_MEDIA_TYPE)
            .send()
            .await?;
        Self::policy_from_response(Self::expect_status(response, StatusCode::OK).await?).await
    }

    /// Get a specific policy by its scheme and ID.
    pub async fn get_policy(&self, scheme: &str, policy_id: Uuid) -> Result<Policy, Error> {
        let response = self
            .http_client
            .get(self.endpoint(GET_POLICY_ENDPOINT, scheme, Some(policy_id)))
            .header(header::ACCEPT, POLICY_MEDIA_TYPE)
            .send()
            .await?;
        Self::policy_from_response(Self::expect_status(response, StatusCode::OK).await?).await
    }

    /// Get all policies for a scheme. (optially filtered by name)
    pub async fn get_policies(&self, scheme: &str, name: &str) -> Result<Vec<Policy>, Error> {
        let mut url = self.endpoint(GET_POLICIES_ENDPOINT, scheme, None);
        if !name.is_empty() {
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
            management_api.get_api_endpoint(name).map(String::as_str),
            Some(expected),
            "missing or unexpected management endpoint: {name}"
        );
    }

    fn endpoint_path(template: &str, scheme: &str, policy_id: Option<Uuid>) -> String {
        template.replace(":scheme", scheme).replace(
            ":uuid",
            &policy_id.map_or_else(String::new, |id| id.to_string()),
        )
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
            .create_opa_policy("test_scheme", b"rule".to_vec(), "test_name")
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
        assert_eq!(runner.get_policy("test_scheme", id).await.unwrap().uuid, id);
        assert_eq!(
            runner.get_active_policy("test_scheme").await.unwrap().uuid,
            id
        );
        assert_eq!(
            runner
                .get_policies("test_scheme", "test_name")
                .await
                .unwrap(),
            vec![Policy::from_str(&policy_json(id).to_string()).unwrap()]
        );
        runner.activate_policy("test_scheme", id).await.unwrap();
        runner.deactivate_all_policies("test_scheme").await.unwrap();
    }

    #[async_std::test]
    async fn submits_and_manages_cca_policy_using_mock_server() {
        let server = MockServer::start().await;
        let policy_id = Uuid::new_v4();
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
                            "createPolicy": CREATE_POLICY_ENDPOINT,
                            "getPolicy": GET_POLICY_ENDPOINT,
                            "deactivatePolicies": DEACTIVATE_POLICIES_ENDPOINT,
                            "getActivePolicy": GET_ACTIVE_POLICY_ENDPOINT,
                            "activatePolicy": ACTIVATE_POLICY_ENDPOINT,
                            "getPolicies": GET_POLICIES_ENDPOINT
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
                CREATE_POLICY_ENDPOINT,
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
                ACTIVATE_POLICY_ENDPOINT,
                "ARM_CCA",
                Some(policy_id),
            )))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path(endpoint_path(
                GET_ACTIVE_POLICY_ENDPOINT,
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
                DEACTIVATE_POLICIES_ENDPOINT,
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

        assert_management_endpoint(&management_api, "createPolicy", CREATE_POLICY_ENDPOINT);
        let policy = runner
            .create_opa_policy("ARM_CCA", policy_rules.as_bytes().to_vec(), "")
            .await
            .expect("failed to submit policy");

        assert_eq!(policy.uuid, policy_id);
        assert_eq!(policy.name, "default");
        assert_eq!(policy.policy_type, "opa");
        assert_eq!(policy.rules, policy_rules);
        assert!(!policy.active);

        assert_management_endpoint(&management_api, "activatePolicy", ACTIVATE_POLICY_ENDPOINT);
        runner
            .activate_policy("ARM_CCA", policy.uuid)
            .await
            .expect("failed to activate policy");
        assert_management_endpoint(
            &management_api,
            "getActivePolicy",
            GET_ACTIVE_POLICY_ENDPOINT,
        );
        assert_eq!(
            runner.get_active_policy("ARM_CCA").await.unwrap().uuid,
            policy_id
        );
        assert_management_endpoint(
            &management_api,
            "deactivatePolicies",
            DEACTIVATE_POLICIES_ENDPOINT,
        );
        runner
            .deactivate_all_policies("ARM_CCA")
            .await
            .expect("failed to deactivate policies");
    }
}
