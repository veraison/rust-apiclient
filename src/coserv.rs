// Copyright 2022-2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::multiple_crate_versions)]

use std::{fs::File, io::Read, path::PathBuf};

use ciborium::Value as CborValue;
use http_cache_reqwest::{Cache, CacheMode, HttpCache, HttpCacheOptions};

#[cfg(feature = "coserv-disk-caching")]
use http_cache_reqwest::CACacheManager;

#[cfg(feature = "coserv-memory-caching")]
use http_cache_reqwest::{MokaCache, MokaManager};

use mediatype::{MediaType, Name, Value, WriteParams};
use reqwest::{Certificate, ClientBuilder};

use coserv_rs::coserv::{corim_rs::CoseVerifier, Coserv, CoservProfile};
use uritemplate::UriTemplate;
use url::Url;

use crate::Error;

const UNSIGNED_COSERV_MEDIA_SUBTYPE: &str = "coserv+cbor";
const SIGNED_COSERV_MEDIA_SUBTYPE: &str = "coserv+cose";

struct ConciseProblemDetails {
    pub title: String,
    pub detail: String,
}

impl ConciseProblemDetails {
    fn from_cbor(bytes: &[u8]) -> Self {
        // Start with degenerate strings for the error title and detail.
        // Hopefully, we decode something better from the CBOR data.
        let mut title = String::from("UNKNOWN ERROR");
        let mut detail = String::from("The problem details could not be obtained from the server");
        let d: Result<CborValue, ciborium::de::Error<std::io::Error>> =
            ciborium::from_reader(bytes);
        if let Ok(CborValue::Map(map)) = d {
            for (k, v) in map {
                if let CborValue::Integer(intkey) = k {
                    match intkey.into() {
                        -1 => title = v.as_text().unwrap_or(&title).to_string(),
                        -2 => detail = v.as_text().unwrap_or(&detail).to_string(),
                        _ => {}
                    }
                }
            }
        }

        ConciseProblemDetails { title, detail }
    }
}

/// A builder for [QueryRunner] objects
pub struct QueryRunnerBuilder {
    request_response_url: Option<String>,
    root_certificate: Option<PathBuf>,
    #[cfg(feature = "coserv-disk-caching")]
    disk_cache: Option<CACacheManager>,
    #[cfg(feature = "coserv-memory-caching")]
    memory_cache: Option<MokaManager>,
    cache_mode: Option<CacheMode>,
    http_cache_options: Option<HttpCacheOptions>,
}

impl QueryRunnerBuilder {
    /// default constructor
    pub fn new() -> Self {
        Self {
            request_response_url: None,
            root_certificate: None,
            #[cfg(feature = "coserv-disk-caching")]
            disk_cache: None,
            #[cfg(feature = "coserv-memory-caching")]
            memory_cache: None,
            cache_mode: None,
            http_cache_options: None,
        }
    }

    /// Use this method to supply the URL of the CoSERV request-response endpoint, e.g.:
    /// "https://veraison.example/endorsement-distribution/v1/coserv/{query}".
    pub fn with_request_response_url(mut self, v: String) -> QueryRunnerBuilder {
        self.request_response_url = Some(v);
        self
    }

    /// Use this method to add a custom root certificate.  For example, this can be used to connect
    /// to a server whose certificate is signed by a CA which is not present in (and does not need to be added to)
    /// the system's trust anchor store.
    pub fn with_root_certificate(mut self, v: PathBuf) -> QueryRunnerBuilder {
        self.root_certificate = Some(v);
        self
    }

    /// Use this method to build a [QueryRunner] with client-side caching enabled using local disk storage.
    /// Pass in the path to the folder on the local system that should be used for the cache.
    /// Default caching mode and options will also be applied.
    /// You may override these by calling [QueryRunnerBuilder::with_cache_mode] and/or
    /// [QueryRunnerBuilder::with_http_cache_options] during the build.
    /// NOTE: This is a convenience method. It is functionally equivalent to [QueryRunnerBuilder::with_disk_cache],
    /// but avoids the need for the caller to construct the full cache manager object. The caller only supplies the file path.
    #[cfg(feature = "coserv-disk-caching")]
    pub fn with_default_disk_cache(self, v: PathBuf) -> QueryRunnerBuilder {
        self.with_disk_cache(CACacheManager::new(v, true))
    }

    /// Use this method to build a [QueryRunner] with client-side caching enabled using local disk storage.
    /// Pass in the path to the folder on the local system that should be used for the cache.
    /// Default caching mode and options will also be applied.
    /// You may override these by calling [QueryRunnerBuilder::with_cache_mode] and/or
    /// [QueryRunnerBuilder::with_http_cache_options] during the build.
    #[cfg(feature = "coserv-disk-caching")]
    pub fn with_disk_cache(mut self, v: CACacheManager) -> QueryRunnerBuilder {
        self.disk_cache = Some(v);
        self
    }

    /// Use this method to build a [QueryRunner] with client-side caching enabled using local memory.
    /// In-memory caching is implemented using [http_cache_reqwest::MokaManager].
    /// This default option will create the cache manager automatically, with capacity for the given number of entries.
    /// For finer control of the cache behaviour, the caller can construct a custom cache manager and configure it
    /// with [QueryRunnerBuilder::with_memory_cache].
    /// Default caching mode and options will also be applied.
    /// You may override these by calling [QueryRunnerBuilder::with_cache_mode] and/or
    /// [QueryRunnerBuilder::with_http_cache_options] during the build.
    /// NOTE: This is a convenience method. It is functionally equivalent to [QueryRunnerBuilder::with_memory_cache],
    /// but avoids the need for the caller to construct the full cache manager object.
    #[cfg(feature = "coserv-memory-caching")]
    pub fn with_default_memory_cache(self, v: u64) -> QueryRunnerBuilder {
        self.with_memory_cache(MokaManager::new(MokaCache::new(v)))
    }

    /// Use this method to build a [QueryRunner] with client-side caching enabled using local memory.
    /// In-memory caching is implemented using [http_cache_reqwest::MokaManager], which the caller must configure.
    /// Default caching mode and options will also be applied.
    /// You may override these by calling [QueryRunnerBuilder::with_cache_mode] and/or
    /// [QueryRunnerBuilder::with_http_cache_options] during the build.
    #[cfg(feature = "coserv-memory-caching")]
    pub fn with_memory_cache(mut self, v: MokaManager) -> QueryRunnerBuilder {
        self.memory_cache = Some(v);
        self
    }

    /// Use this method to override the default cache mode.
    /// NOTE: This method is only effective in combination with [QueryRunnerBuilder::with_disk_cache] or
    /// [QueryRunnerBuilder::with_memory_cache].
    pub fn with_cache_mode(mut self, v: CacheMode) -> QueryRunnerBuilder {
        self.cache_mode = Some(v);
        self
    }

    /// Use this method to override the default HTTP caching options.
    /// NOTE: This method is only effective in combination with [QueryRunnerBuilder::with_disk_cache] or
    /// [QueryRunnerBuilder::with_memory_cache].
    pub fn with_http_cache_options(mut self, v: HttpCacheOptions) -> QueryRunnerBuilder {
        self.http_cache_options = Some(v);
        self
    }

    /// Instantiate a valid [QueryRunner] object, or fail with an error.
    pub fn build(self) -> Result<QueryRunner, Error> {
        let request_response_url_str = self.request_response_url.ok_or_else(|| {
            Error::ConfigError("missing CoSERV request-response API endpoint".to_string())
        })?;

        // Make sure the URL can be parsed
        let _url =
            Url::parse(&request_response_url_str).map_err(|e| Error::ConfigError(e.to_string()))?;

        // Make sure the URL ends with the "/{query}" template parameter as required by the spec
        if !request_response_url_str.ends_with("/{query}") {
            return Err(Error::ConfigError(format!(
                "The given CoSERV query endpoint '{0}' does not end with '/{{query}}'",
                request_response_url_str
            )));
        }

        let mut http_client_builder: ClientBuilder = reqwest::ClientBuilder::new();

        if let Some(root_cert) = self.root_certificate {
            let mut buf = Vec::new();
            File::open(root_cert)?.read_to_end(&mut buf)?;
            let cert = Certificate::from_pem(&buf)?;
            http_client_builder = http_client_builder.add_root_certificate(cert);
        }

        let http_client = http_client_builder.use_rustls_tls().build()?;

        // Now add any required middleware to the client
        let mut middleware_builder = reqwest_middleware::ClientBuilder::new(http_client);

        // Add memory caching middleware if configured
        #[cfg(feature = "coserv-memory-caching")]
        if let Some(moka_mgr) = self.memory_cache {
            let options = self.http_cache_options.clone().unwrap_or_default();
            middleware_builder = middleware_builder.with(Cache(HttpCache {
                mode: self.cache_mode.unwrap_or(CacheMode::Default),
                manager: moka_mgr,
                options,
            }))
        }

        // Add disk caching middleware if configured (via a root path for the cache)
        #[cfg(feature = "coserv-disk-caching")]
        if let Some(ca_mgr) = self.disk_cache {
            let options = self.http_cache_options.clone().unwrap_or_default();
            middleware_builder = middleware_builder.with(Cache(HttpCache {
                mode: self.cache_mode.unwrap_or(CacheMode::Default),
                manager: ca_mgr,
                options,
            }))
        }

        // Use the middleware client as the client in the QueryRunner
        let client_with_middleware = middleware_builder.build();

        Ok(QueryRunner {
            request_response_url_template: request_response_url_str.to_string(),
            http_client: client_with_middleware,
        })
    }
}

impl Default for QueryRunnerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// This object can be used to execute one or more CoSERV queries using the
/// transactional request-response API.  Always use the [QueryRunnerBuilder] to instantiate it.
pub struct QueryRunner {
    request_response_url_template: String,
    http_client: reqwest_middleware::ClientWithMiddleware,
}

impl<'a> QueryRunner {
    async fn execute_query(&self, query: &Coserv<'a>, signed: bool) -> Result<Vec<u8>, Error> {
        let coserv_b64 = query
            .to_b64_url()
            .map_err(|e| Error::DataConversionError(e.to_string()))?;

        // Instantiate the query by substituting the URL template variable
        let coserv_url = UriTemplate::new(&self.request_response_url_template)
            .set("query", coserv_b64)
            .build();

        let media_subtype = if signed {
            Name::new_unchecked(SIGNED_COSERV_MEDIA_SUBTYPE)
        } else {
            Name::new_unchecked(UNSIGNED_COSERV_MEDIA_SUBTYPE)
        };

        // Construct the base media type, which is "application/coserv+cbor" for
        // unsigned results, or "application/coserv+cose" for signed results.
        let mut media_type = MediaType::new(mediatype::names::APPLICATION, media_subtype);

        // Parameterise the base media type with the profile string (quoted, for the case of URI-based profiles).
        let mut profile = String::new();

        match &query.profile {
            CoservProfile::Oid(oid) => profile.push_str(&oid.to_string()),
            CoservProfile::Uri(uri) => {
                profile.push('"');
                profile.push_str(uri);
                profile.push('"');
            }
        }

        let value = Value::new(&profile);

        if let Some(v) = value {
            media_type.set_param(Name::new_unchecked("profile"), v)
        } else {
            return Err(Error::DataConversionError(format!(
                "could not parse profile {} to CoSERV media type parameter",
                profile
            )));
        }

        // Now run the actual HTTP GET operation
        let response = self
            .http_client
            .get(coserv_url.as_str())
            .header(reqwest::header::ACCEPT, media_type.to_string())
            .send()
            .await?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let response_body_bytes = response.bytes().await?;
                Ok(response_body_bytes.to_vec())
            }
            // These two are in-protocol errors. If we receive them, they should be accompanied by Concise Problem Details (RFC9290)
            // in the response body.
            reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::NOT_ACCEPTABLE => {
                let response_body_bytes = response.bytes().await?;
                let concise_problem_details =
                    ConciseProblemDetails::from_cbor(response_body_bytes.as_ref());
                Err(Error::ApiError(format!(
                    "{0}: {1}",
                    concise_problem_details.title, concise_problem_details.detail
                )))
            }
            // Some other HTTP status code that's out-of-protocol (e.g. Internal Server Error)
            // Don't expect any CBOR error details here, just report the code as an ApiError.
            n => Err(Error::ApiError(format!("http error status {0}", n))),
        }
    }

    /// Execute a single CoSERV query and return an unsigned result.
    ///
    /// On success, the returned [Coserv] object will contain the same query as the input,
    /// but the results will also be populated based on the data provided by the server.
    ///
    /// The semantics of this operation are as defined in the
    /// [CoSERV IETF Draft](https://www.ietf.org/archive/id/draft-ietf-rats-coserv-02.html#name-execute-query).
    ///
    /// It is the caller's responsibility to check that the server supports unsigned CoSERV output.
    /// To do this, consult the [crate::DiscoveryDocument].
    pub async fn execute_query_unsigned(&self, query: &Coserv<'a>) -> Result<Coserv<'a>, Error> {
        let response_bytes = self.execute_query(query, false).await?;
        let coserv_out = Coserv::from_cbor(response_bytes.as_slice())
            .map_err(|e| Error::DataConversionError(e.to_string()))?;
        Ok(coserv_out)
    }

    /// Execute a single CoSERV query and return a signed result as a vector of bytes.
    ///
    /// Verification of the signature, and extraction of the underlying [Coserv] object, are
    /// the responsibility of the caller. The [Coserv::verify_and_extract] function should be
    /// used for this purpose, and given an appropriate implementation of the signature
    /// verifier.
    ///
    /// As an alternative to this method, use [QueryRunner::execute_query_signed_extracted] to
    /// perform the signature verification and extraction in a single operation.
    ///
    /// The semantics of this operation are as defined in the
    /// [CoSERV IETF Draft](https://www.ietf.org/archive/id/draft-ietf-rats-coserv-02.html#name-execute-query).
    ///
    /// It is the caller's responsibility to check that the server supports signed CoSERV output.
    /// To do this, consult the [crate::DiscoveryDocument].
    pub async fn execute_query_signed(&self, query: &Coserv<'a>) -> Result<Vec<u8>, Error> {
        let response_bytes = self.execute_query(query, true).await?;
        Ok(response_bytes)
    }

    /// Execute a single CoSERV query with a signing and verification.
    ///
    /// On success, the returned [Coserv] object will contain the same query as the input,
    /// but the results will also be populated based on the data provided by the server.
    /// The signature will have been verified by the supplied implementation of the verifier.
    ///
    /// The semantics of this operation are as defined in the
    /// [CoSERV IETF Draft](https://www.ietf.org/archive/id/draft-ietf-rats-coserv-02.html#name-execute-query).
    ///
    /// It is the caller's responsibility to check that the server supports signed CoSERV output.
    /// To do this, consult the [crate::DiscoveryDocument].
    pub async fn execute_query_signed_extracted(
        &self,
        query: &Coserv<'a>,
        verifier: &impl CoseVerifier,
    ) -> Result<Coserv<'a>, Error> {
        let response_bytes = self.execute_query(query, true).await?;
        let coserv_out = Coserv::verify_and_extract(verifier, response_bytes.as_slice())
            .map_err(|e| Error::SignatureVerificationError(e.to_string()))?;
        Ok(coserv_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coserv_rs::coserv::corim_rs::CorimError;
    use coserv_rs::coserv::{
        ArtifactTypeChoice, CoseAlgorithm, CoseKey, CoseKeyOwner, CoseSigner, ResultSetTypeChoice,
        ResultTypeChoice,
    };
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn deserialize_concise_problem_details() {
        let problem_details_bytes =
            include_bytes!("../test/coserv/problem_details_bad_request.cbor");
        let problem_details = ConciseProblemDetails::from_cbor(problem_details_bytes);
        assert_eq!("Query validation failed", &problem_details.title);
        assert_eq!(
            "The query payload is not in CBOR format",
            &problem_details.detail
        );
    }

    #[async_std::test]
    async fn execute_query_unsigned_okay() {
        let query_bytes = include_bytes!("../test/coserv/example_query.cbor");
        let query = Coserv::from_cbor(query_bytes.as_slice()).unwrap();
        let query_string = query.to_b64_url().unwrap();

        let result_bytes = include_bytes!("../test/coserv/example_result.cbor");

        let mock_server = MockServer::start().await;

        let response = ResponseTemplate::new(200).set_body_bytes(result_bytes);

        Mock::given(method("GET"))
            .and(path("/".to_string() + &query_string))
            .and(header_exists("Accept")) // Ideally we would fully match the header, but WireMock barfs on complex parameterised media types
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let cr = QueryRunnerBuilder::new()
            .with_request_response_url(mock_server.uri() + "/{query}")
            .build()
            .unwrap();

        let coserv_out = cr.execute_query_unsigned(&query).await.unwrap();

        // Test some characteristics of the result
        // (This is deliberately not exhaustive, because this crate doesn't implement CoSERV deserialisation)
        assert_eq!(
            CoservProfile::Uri("tag:example.com,2025:cc-platform#1.0.0".to_string()),
            coserv_out.profile
        );
        assert_eq!(
            ArtifactTypeChoice::ReferenceValues,
            coserv_out.query.artifact_type
        );
        assert_eq!(
            ResultTypeChoice::CollectedArtifacts,
            coserv_out.query.result_type
        );

        let results = coserv_out.results.unwrap();
        assert_eq!(None, results.source_artifacts);

        let result_set = results.result_set.unwrap();
        if let ResultSetTypeChoice::ReferenceValues(rv) = result_set {
            assert_eq!(1, rv.rv_quads.len());

            let quad = &rv.rv_quads[0];
            assert_eq!(1, quad.authorities.len());
        } else {
            panic!("Wrong type of result set (not reference values).");
        }
    }

    #[async_std::test]
    async fn execute_query_signed_extracted_okay() {
        // Dummy COSE verifier
        struct TestVerifier {}

        impl CoseKeyOwner for TestVerifier {
            fn to_cose_key(&self) -> CoseKey {
                CoseKey::default()
            }
        }

        impl CoseVerifier for TestVerifier {
            fn verify_signature(
                &self,
                _alg: CoseAlgorithm,
                sig: &[u8],
                _data: &[u8],
            ) -> Result<(), CorimError> {
                assert_eq!(sig, [0xde, 0xad, 0xbe, 0xef]);
                Ok(())
            }
        }

        impl CoseSigner for TestVerifier {
            fn sign(&self, _alg: CoseAlgorithm, _data: &[u8]) -> Result<Vec<u8>, CorimError> {
                Ok(vec![0xde, 0xad, 0xbe, 0xef])
            }
        }

        let verifier = TestVerifier {};
        let query_bytes = include_bytes!("../test/coserv/example_query.cbor");
        let query = Coserv::from_cbor(query_bytes.as_slice()).unwrap();
        let query_string = query.to_b64_url().unwrap();

        let unsigned_result = include_bytes!("../test/coserv/example_result.cbor");
        let unsigned_coserv = Coserv::from_cbor(unsigned_result.as_slice()).unwrap();
        let signed_coserv = unsigned_coserv
            .sign(&verifier, CoseAlgorithm::ES384)
            .unwrap();

        let mock_server = MockServer::start().await;

        let response = ResponseTemplate::new(200).set_body_bytes(signed_coserv);

        Mock::given(method("GET"))
            .and(path("/".to_string() + &query_string))
            .and(header_exists("Accept")) // Ideally we would fully match the header, but WireMock barfs on complex parameterised media types
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let cr = QueryRunnerBuilder::new()
            .with_request_response_url(mock_server.uri() + "/{query}")
            .build()
            .unwrap();

        let coserv_out = cr
            .execute_query_signed_extracted(&query, &verifier)
            .await
            .unwrap();

        // Minimal test that we have a correctly-profiled CoSERV object.
        // No value in examining its contents here, because that's covered by other tests.
        assert_eq!(
            CoservProfile::Uri("tag:example.com,2025:cc-platform#1.0.0".to_string()),
            coserv_out.profile
        );
    }

    #[async_std::test]
    #[cfg(feature = "coserv-disk-caching")]
    async fn execute_query_disk_cached_okay() {
        // Make a temporary directory to use as the cache (will be deleted when dropped)
        let cache_root = tempfile::tempdir().unwrap();
        let cache_path: PathBuf = cache_root.path().into();

        let query_bytes = include_bytes!("../test/coserv/example_query.cbor");
        let query = Coserv::from_cbor(query_bytes.as_slice()).unwrap();
        let query_string = query.to_b64_url().unwrap();

        let result_bytes = include_bytes!("../test/coserv/example_result.cbor");

        let mock_server = MockServer::start().await;

        // Respond with a cache control header, allowing the client to cache the response
        let response = ResponseTemplate::new(200)
            .insert_header("Cache-Control", "max-age=3600")
            .set_body_bytes(result_bytes);

        Mock::given(method("GET"))
            .and(path("/".to_string() + &query_string))
            .and(header_exists("Accept")) // Ideally we would fully match the header, but WireMock barfs on complex parameterised media types
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let cr = QueryRunnerBuilder::new()
            .with_request_response_url(mock_server.uri() + "/{query}")
            .with_default_disk_cache(cache_path.clone())
            .build()
            .unwrap();

        // We should have an empty cache before we run the first query
        assert!(cache_path.read_dir().unwrap().next().is_none());

        // Run a query and assert a valid CoSERV result - this will be served from the MockServer
        let coserv_out = cr.execute_query_unsigned(&query).await.unwrap();
        assert_eq!(
            CoservProfile::Uri("tag:example.com,2025:cc-platform#1.0.0".to_string()),
            coserv_out.profile
        );

        // Cache should now be non-empty
        // (The structure of the cache is an implementation detail, but there must be SOMETHING in there.)
        assert!(cache_path.read_dir().unwrap().next().is_some());

        // Run a flurry of identical queries and assert a valid CoSERV result - these will be served from the cache
        for _i in 1..1000 {
            let coserv_out = cr.execute_query_unsigned(&query).await.unwrap();
            assert_eq!(
                CoservProfile::Uri("tag:example.com,2025:cc-platform#1.0.0".to_string()),
                coserv_out.profile
            );
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
    #[cfg(feature = "coserv-memory-caching")]
    async fn execute_query_memory_cached_okay() {
        // Make the in-memory cache
        let cache = MokaCache::new(10);
        let cache_manager = MokaManager::new(cache);

        let query_bytes = include_bytes!("../test/coserv/example_query.cbor");
        let query = Coserv::from_cbor(query_bytes.as_slice()).unwrap();
        let query_string = query.to_b64_url().unwrap();

        let result_bytes = include_bytes!("../test/coserv/example_result.cbor");

        let mock_server = MockServer::start().await;

        // Respond with a cache control header, allowing the client to cache the response
        let response = ResponseTemplate::new(200)
            .insert_header("Cache-Control", "max-age=3600")
            .set_body_bytes(result_bytes);

        Mock::given(method("GET"))
            .and(path("/".to_string() + &query_string))
            .and(header_exists("Accept")) // Ideally we would fully match the header, but WireMock barfs on complex parameterised media types
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let cr = QueryRunnerBuilder::new()
            .with_request_response_url(mock_server.uri() + "/{query}")
            .with_memory_cache(cache_manager)
            .build()
            .unwrap();

        // Run a query and assert a valid CoSERV result - this will be served from the MockServer
        let coserv_out = cr.execute_query_unsigned(&query).await.unwrap();
        assert_eq!(
            CoservProfile::Uri("tag:example.com,2025:cc-platform#1.0.0".to_string()),
            coserv_out.profile
        );

        // Run a flurry of identical queries and assert a valid CoSERV result - these will be served from the cache
        for _i in 1..1000 {
            let coserv_out = cr.execute_query_unsigned(&query).await.unwrap();
            assert_eq!(
                CoservProfile::Uri("tag:example.com,2025:cc-platform#1.0.0".to_string()),
                coserv_out.profile
            );
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
    async fn execute_query_not_acceptable() {
        let query_bytes = include_bytes!("../test/coserv/example_query.cbor");
        let query = Coserv::from_cbor(query_bytes.as_slice()).unwrap();
        let query_string = query.to_b64_url().unwrap();

        let result_bytes = include_bytes!("../test/coserv/problem_details_not_acceptable.cbor");

        let mock_server = MockServer::start().await;

        let response = ResponseTemplate::new(406).set_body_bytes(result_bytes);

        Mock::given(method("GET"))
            .and(path("/".to_string() + &query_string))
            .and(header_exists("Accept")) // Ideally we would fully match the header, but WireMock barfs on complex parameterised media types
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let cr = QueryRunnerBuilder::new()
            .with_request_response_url(mock_server.uri() + "/{query}")
            .build()
            .unwrap();

        let e = cr
            .execute_query_unsigned(&query)
            .await
            .expect_err("Should have resulted in an error.");
        assert_eq!("API error: Content negotiation failed: The given CoSERV profile is not supported by this server", e.to_string());
    }
}
