pub mod auth;
pub mod cli;
pub mod config;
pub mod core;
pub mod dashboard;
pub mod events;
pub mod mcp_proxy;
pub mod mcp_server;
pub mod modules;
pub mod pipeline;
pub mod plugins;
pub mod server;
pub mod storage;

#[cfg(feature = "demo")]
pub mod demo;

#[cfg(not(feature = "demo"))]
pub mod demo {
    pub mod scenarios {
        use crate::core::types::*;
        pub fn demo_profiles() -> Vec<AgentProfile> {
            vec![]
        }
        pub fn demo_workspace_policies() -> Vec<WorkspacePolicy> {
            vec![]
        }
        pub fn demo_scenarios() -> Vec<DemoScenario> {
            vec![]
        }
    }
}
