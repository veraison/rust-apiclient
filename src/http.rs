// Copyright 2022-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::multiple_crate_versions)]

use std::{fs::File, io::Read, path::PathBuf};

use http_cache_reqwest::{Cache, CacheMode, HttpCache, HttpCacheOptions};

#[cfg(feature = "disk-caching")]
use http_cache_reqwest::CACacheManager;

#[cfg(feature = "memory-caching")]
use http_cache_reqwest::{MokaCache, MokaManager};

use reqwest::{Certificate, ClientBuilder};

use reqwest_middleware::ClientWithMiddleware;

use crate::Error;

/// This trait is shared and implemented by all "Builder" objects that include an HTTP client.
pub trait ConfigureHttp: Sized {
    /// Use this method to add a custom root certificate.  For example, this can be used to connect
    /// to a server whose certificate is signed by a CA which is not present in (and does not need to be added to)
    /// the system's trust anchor store.
    fn with_root_certificate(self, v: PathBuf) -> Self;

    /// Use this method to build a client with client-side caching enabled using local disk storage.
    /// Pass in the path to the folder on the local system that should be used for the cache.
    /// Default caching mode and options will also be applied.
    /// You may override these by calling [ConfigureHttp::with_cache_mode] and/or
    /// [ConfigureHttp::with_http_cache_options] during the build.
    /// NOTE: This is a convenience method. It is functionally equivalent to [ConfigureHttp::with_disk_cache],
    /// but avoids the need for the caller to construct the full cache manager object. The caller only supplies the file path.
    #[cfg(feature = "disk-caching")]
    fn with_default_disk_cache(self, v: PathBuf) -> Self {
        self.with_disk_cache(CACacheManager::new(v, true))
    }

    /// Use this method to build a client with client-side caching enabled using local disk storage.
    /// Pass in the path to the folder on the local system that should be used for the cache.
    /// Default caching mode and options will also be applied.
    /// You may override these by calling [ConfigureHttp::with_cache_mode] and/or
    /// [ConfigureHttp::with_http_cache_options] during the build.
    #[cfg(feature = "disk-caching")]
    fn with_disk_cache(self, v: CACacheManager) -> Self;

    /// Use this method to build a client with client-side caching enabled using local memory.
    /// In-memory caching is implemented using [http_cache_reqwest::MokaManager].
    /// This default option will create the cache manager automatically, with capacity for the given number of entries.
    /// For finer control of the cache behaviour, the caller can construct a custom cache manager and configure it
    /// with [ConfigureHttp::with_memory_cache].
    /// Default caching mode and options will also be applied.
    /// You may override these by calling [ConfigureHttp::with_cache_mode] and/or
    /// [ConfigureHttp::with_http_cache_options] during the build.
    /// NOTE: This is a convenience method. It is functionally equivalent to [ConfigureHttp::with_memory_cache],
    /// but avoids the need for the caller to construct the full cache manager object.
    #[cfg(feature = "memory-caching")]
    fn with_default_memory_cache(self, v: u64) -> Self {
        self.with_memory_cache(MokaManager::new(MokaCache::new(v)))
    }

    /// Use this method to build a client with client-side caching enabled using local memory.
    /// In-memory caching is implemented using [http_cache_reqwest::MokaManager], which the caller must configure.
    /// Default caching mode and options will also be applied.
    /// You may override these by calling [ConfigureHttp::with_cache_mode] and/or
    /// [ConfigureHttp::with_http_cache_options] during the build.
    #[cfg(feature = "memory-caching")]
    fn with_memory_cache(self, v: MokaManager) -> Self;

    /// Use this method to override the default cache mode.
    /// NOTE: This method is only effective in combination with [ConfigureHttp::with_disk_cache] or
    /// [ConfigureHttp::with_memory_cache].
    fn with_cache_mode(self, v: CacheMode) -> Self;

    /// Use this method to override the default HTTP caching options.
    /// NOTE: This method is only effective in combination with [ConfigureHttp::with_disk_cache] or
    /// [ConfigureHttp::with_memory_cache].
    fn with_http_cache_options(self, v: HttpCacheOptions) -> Self;
}

/// A common builder for all HTTP client objects used in this crate.
/// The common builder allows for the configuration of custom TLS root certificates along with
/// middleware layers for client-side caching.
pub(crate) struct HttpClientBuilder {
    root_certificate: Option<PathBuf>,
    #[cfg(feature = "disk-caching")]
    disk_cache: Option<CACacheManager>,
    #[cfg(feature = "memory-caching")]
    memory_cache: Option<MokaManager>,
    cache_mode: Option<CacheMode>,
    http_cache_options: Option<HttpCacheOptions>,
}

impl ConfigureHttp for HttpClientBuilder {
    fn with_root_certificate(mut self, v: PathBuf) -> HttpClientBuilder {
        self.root_certificate = Some(v);
        self
    }

    #[cfg(feature = "disk-caching")]
    fn with_disk_cache(mut self, v: CACacheManager) -> HttpClientBuilder {
        self.disk_cache = Some(v);
        self
    }

    #[cfg(feature = "memory-caching")]
    fn with_memory_cache(mut self, v: MokaManager) -> HttpClientBuilder {
        self.memory_cache = Some(v);
        self
    }

    fn with_cache_mode(mut self, v: CacheMode) -> HttpClientBuilder {
        self.cache_mode = Some(v);
        self
    }

    fn with_http_cache_options(mut self, v: HttpCacheOptions) -> HttpClientBuilder {
        self.http_cache_options = Some(v);
        self
    }
}

impl HttpClientBuilder {
    /// default constructor
    pub fn new() -> Self {
        Self {
            root_certificate: None,
            #[cfg(feature = "disk-caching")]
            disk_cache: None,
            #[cfg(feature = "memory-caching")]
            memory_cache: None,
            cache_mode: None,
            http_cache_options: None,
        }
    }

    /// Instantiate the client with the desired configuration.
    pub fn build(self) -> Result<ClientWithMiddleware, Error> {
        let mut http_client_builder: ClientBuilder = reqwest::ClientBuilder::new();

        if let Some(root_cert) = self.root_certificate {
            let mut buf = Vec::new();
            File::open(root_cert)?.read_to_end(&mut buf)?;
            let cert = Certificate::from_pem(&buf)?;
            http_client_builder = http_client_builder
                .add_root_certificate(cert)
                // We can skip cert validation for custom root certs.
                // Custom roots are designed as a convenience for non-production environments
                // They allow TLS to be tested but without the creation of CA infrastructure (e.g. using self-signed)
                // Validating such certs would defeat the purpose.
                // There are no security implications here, beyond those of using a custom root cert in the first place.
                .tls_danger_accept_invalid_certs(true);
        }

        let http_client = http_client_builder.use_rustls_tls().build()?;

        // Now add any required middleware to the client
        let mut middleware_builder = reqwest_middleware::ClientBuilder::new(http_client);

        // Add memory caching middleware if configured
        #[cfg(feature = "memory-caching")]
        if let Some(moka_mgr) = self.memory_cache {
            let options = self.http_cache_options.clone().unwrap_or_default();
            middleware_builder = middleware_builder.with(Cache(HttpCache {
                mode: self.cache_mode.unwrap_or(CacheMode::Default),
                manager: moka_mgr,
                options,
            }))
        }

        // Add disk caching middleware if configured (via a root path for the cache)
        #[cfg(feature = "disk-caching")]
        if let Some(ca_mgr) = self.disk_cache {
            let options = self.http_cache_options.clone().unwrap_or_default();
            middleware_builder = middleware_builder.with(Cache(HttpCache {
                mode: self.cache_mode.unwrap_or(CacheMode::Default),
                manager: ca_mgr,
                options,
            }))
        }

        Ok(middleware_builder.build())
    }
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}
