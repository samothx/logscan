//! logscan: deterministic + LLM-assisted security review of the journal and nginx logs.

pub mod config;
pub mod model;
pub mod rules;
pub mod sources;
pub mod state;
pub mod notify;
pub mod report;
pub mod scan;
pub mod datasets;
pub mod llm;
pub mod skills;
