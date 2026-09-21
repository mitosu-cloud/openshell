// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wire encoding for `ExecMode::DIRECT` over the supervisor SSH exec channel.

use serde::{Deserialize, Serialize};

/// Prefix the supervisor uses to distinguish a DIRECT payload from a shell command.
pub const DIRECT_EXEC_PREFIX: &str = "openshell-direct/1\n";

/// Argv, environment, and workdir launched without a wrapping shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectExecSpec {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub workdir: Option<String>,
}

/// Encode a DIRECT spec as the SSH exec payload.
pub fn encode(spec: &DirectExecSpec) -> Result<String, String> {
    if spec.program.is_empty() {
        return Err("DIRECT exec program is empty".to_string());
    }
    let body = serde_json::to_string(spec).map_err(|error| error.to_string())?;
    Ok(format!("{DIRECT_EXEC_PREFIX}{body}"))
}

/// Parse a DIRECT SSH exec payload.
pub fn decode(command: &str) -> Result<DirectExecSpec, String> {
    let body = command.strip_prefix(DIRECT_EXEC_PREFIX).ok_or_else(|| {
        "DIRECT exec payload is missing the openshell-direct/1 prefix".to_string()
    })?;
    let spec: DirectExecSpec = serde_json::from_str(body)
        .map_err(|error| format!("invalid DIRECT exec payload: {error}"))?;
    if spec.program.is_empty() {
        return Err("DIRECT exec program is empty".to_string());
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_argv_env_and_workdir() {
        let spec = DirectExecSpec {
            program: "curl".into(),
            args: vec!["-sS".into(), "https://example.test".into()],
            env: vec![("FOO".into(), "bar".into())],
            workdir: Some("/workspace".into()),
        };
        let encoded = encode(&spec).unwrap();
        assert!(encoded.starts_with(DIRECT_EXEC_PREFIX));
        assert_eq!(decode(&encoded).unwrap(), spec);
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(decode("curl -sS https://example.test").is_err());
    }

    #[test]
    fn rejects_empty_program() {
        assert!(
            encode(&DirectExecSpec {
                program: String::new(),
                args: Vec::new(),
                env: Vec::new(),
                workdir: None,
            })
            .is_err()
        );
    }
}
