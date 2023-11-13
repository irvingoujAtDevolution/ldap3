use ldap3_proto::LdapMsg;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::Level;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

pub mod error;
pub mod ldap_session;
#[cfg(test)]
mod test;

pub type JsResult<T> = Result<T, JsValue>;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn set_logging_level(level: LoggingLevel) {
    let mut builder = tracing_wasm::WASMLayerConfigBuilder::new();
    builder.set_max_level(level.into());
    tracing_wasm::set_as_global_default_with_config(builder.build());
}

#[wasm_bindgen]
pub enum LoggingLevel{
    Panic,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Into<Level> for LoggingLevel {
    fn into(self) -> Level {
        match self {
            LoggingLevel::Panic => Level::ERROR,
            LoggingLevel::Warn => Level::WARN,
            LoggingLevel::Info => Level::INFO,
            LoggingLevel::Debug => Level::DEBUG,
            LoggingLevel::Trace => Level::TRACE,
        }
    }
}
