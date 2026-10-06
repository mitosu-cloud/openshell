// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Optional embedder-owned admission at the existing lifecycle boundary.
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct StartContext {
    pub driver: String,
    pub sandbox_id: String,
    pub labels: HashMap<String, String>,
    /// Restored intent or an interrupted Starting transition, rather than a
    /// separate authenticated owner Start request.
    pub automatic: bool,
}

#[derive(Debug)]
pub enum StartDecision {
    Allow,
    Hold {
        reason: String,
        /// Set only after the embedder verified the original runtime inactive.
        /// Persists Stopped without issuing stop or start to the driver. Unknown
        /// or active runtimes must use false; their intent is left untouched.
        stopped: bool,
    },
}

#[async_trait::async_trait]
pub trait SandboxStartGuard: Send + Sync + std::fmt::Debug {
    async fn check(&self, context: StartContext) -> Result<StartDecision, String>;
}
