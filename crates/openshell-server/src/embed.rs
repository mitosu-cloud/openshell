// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-process gateway embedding API for host products such as Mitosu.

pub use crate::compute::start_guard::{SandboxStartGuard, StartContext, StartDecision};
use crate::config_file::ConfigFile;
use crate::tracing_bus::TracingLogBus;
use crate::{
    ComputeDriverRegistry, ServerStartupConfig, ServingServer, bootstrap_state, serve,
    shutdown_and_cleanup,
};
use openshell_core::{Config, Result};
use std::sync::Arc;
use tokio::sync::watch;

pub use crate::compute::driver_config::GuestTlsPaths;
pub use crate::{ComputeDriverSelection, ListenerInfo};

/// Programmatic configuration for an embedded gateway process.
#[derive(Clone, Debug)]
pub struct EmbeddedServerConfig {
    config: Config,
    config_file: Option<ConfigFile>,
    guest_tls: Option<GuestTlsPaths>,
    compute_driver: Option<String>,
    start_guard: Option<Arc<dyn SandboxStartGuard>>,
}

impl EmbeddedServerConfig {
    /// Start from a fully constructed [`Config`].
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            config,
            config_file: None,
            guest_tls: None,
            compute_driver: None,
            start_guard: None,
        }
    }

    /// Attach the optional TOML config file used for middleware and driver tables.
    #[must_use]
    pub fn with_config_file(mut self, config_file: ConfigFile) -> Self {
        self.config_file = Some(config_file);
        self
    }

    /// Attach guest TLS material copied into sandboxes.
    #[must_use]
    pub fn with_guest_tls(mut self, guest_tls: GuestTlsPaths) -> Self {
        self.guest_tls = Some(guest_tls);
        self
    }

    /// Select an installed compute driver by name.
    #[must_use]
    pub fn with_compute_driver(mut self, name: impl Into<String>) -> Self {
        self.compute_driver = Some(name.into());
        self
    }

    /// Add product-owned recovery admission without a separate service.
    #[must_use]
    pub fn with_start_guard(mut self, guard: Arc<dyn SandboxStartGuard>) -> Self {
        self.start_guard = Some(guard);
        self
    }

    fn into_startup(self, drivers: &ComputeDriverRegistry) -> Result<ServerStartupConfig> {
        let compute_driver = drivers.select(self.compute_driver.as_deref())?;
        Ok(ServerStartupConfig {
            config: self.config,
            config_file: self.config_file,
            guest_tls: self.guest_tls,
            compute_driver,
            legacy_compute_driver_env_seen: false,
        })
    }
}

/// Handle for a gateway serving in the current process.
pub struct EmbeddedServer {
    serving: ServingServer,
}

impl EmbeddedServer {
    /// Addresses bound during [`serve`]. Completes once listeners are ready.
    pub async fn ready(&mut self) -> Result<ListenerInfo> {
        (&mut self.serving.ready)
            .await
            .map_err(|_| openshell_core::Error::execution("embedded gateway dropped before ready"))
    }

    /// Join listeners after the caller has set the shutdown watch to true.
    pub async fn stop(self) -> Result<()> {
        shutdown_and_cleanup(self.serving).await
    }
}

/// Bootstrap and serve using a caller-owned shutdown watch.
pub async fn run_embedded(
    config: EmbeddedServerConfig,
    drivers: ComputeDriverRegistry,
    tracing_bus: TracingLogBus,
    shutdown: watch::Receiver<bool>,
) -> Result<EmbeddedServer> {
    let start_guard = config.start_guard.clone();
    let startup = config.into_startup(&drivers)?;
    let bootstrapped = bootstrap_state(startup, drivers, tracing_bus, shutdown.clone()).await?;
    if let Some(guard) = start_guard {
        bootstrapped.state.compute.install_start_guard(guard);
    }
    let serving = serve(bootstrapped, shutdown).await?;
    Ok(EmbeddedServer { serving })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn config_builders_are_chainable() {
        let mut config = Config::new(None);
        config.bind_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        config.database_url = "sqlite::memory:".into();
        let embedded = EmbeddedServerConfig::new(config)
            .with_compute_driver("docker")
            .with_guest_tls(GuestTlsPaths::new(
                "/tmp/ca.crt".into(),
                "/tmp/tls.crt".into(),
                "/tmp/tls.key".into(),
            ));
        assert_eq!(embedded.compute_driver.as_deref(), Some("docker"));
        assert!(embedded.guest_tls.is_some());
        assert!(embedded.config_file.is_none());
    }
}
