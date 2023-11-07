use async_io_stream::IoStream;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;
use ldap3_proto::{
    parse_ldap_filter_str,
    proto::{LdapBindCred, LdapBindRequest, LdapOp, LdapSearchRequest},
    LdapCodec, LdapFilter, LdapMsg, LdapResultCode,
};
use tokio_util::codec::Framed;
use wasm_bindgen::prelude::*;
use ws_stream_wasm::WsStreamIo;

use crate::{to_js_error, JsLdapMsg};

type JsResult<T> = Result<T, JsValue>;
#[wasm_bindgen]
pub struct LDAPSession {
    frame: Framed<IoStream<WsStreamIo, Vec<u8>>, LdapCodec>,
    message_id: i32,
    parameters: LDAPSessionParameters,
}

#[wasm_bindgen]
pub struct LDAPSessionParameters {
    server_address_ws_proxy: String,
    _kdc_address: Option<String>,
    _kdc_address_ws_endpoint: Option<String>,
}

impl LDAPSessionParameters {
    pub fn new(server_address_ws_proxy: String) -> Self {
        Self {
            server_address_ws_proxy,
            _kdc_address: None,
            _kdc_address_ws_endpoint: None,
        }
    }
}
impl LDAPSession {
    fn next_message_id(&mut self) -> i32 {
        self.message_id = self.message_id + 1;
        self.message_id
    }
}

#[wasm_bindgen]
impl LDAPSession {
    pub async fn connect(parames: LDAPSessionParameters) -> JsResult<LDAPSession> {
        let (_ws_meta, ws_stream_wasm) =
            ws_stream_wasm::WsMeta::connect(&parames.server_address_ws_proxy, None)
                .await
                .unwrap();
        let io_stream = ws_stream_wasm.into_io();
        let framed = Framed::new(io_stream, LdapCodec::default());
        let session = LDAPSession {
            frame: framed,
            message_id: 0,
            parameters: parames,
        };
        Ok(session)
    }

    pub async fn bind(
        &mut self,
        distinguished_name: String,
        password: String,
    ) -> JsResult<JsLdapMsg> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::BindRequest(LdapBindRequest {
                dn: distinguished_name,
                cred: LdapBindCred::Simple(password),
            }),
            ctrl: vec![],
        };
        self.frame
            .send(msg)
            .await
            .map_err(|e| {
                eprintln!("Unable to send bind -> {:?}", e);
            })
            .unwrap();

        if let Some(Ok(msg)) = self.frame.next().await {
            return Ok(msg.into());
        }
        Err(to_js_error!("Failed to bind"))
    }
    pub async fn unbind() -> JsResult<bool> {
        todo!()
    }
    pub async fn search(&mut self, search_base: String, filter: String) -> JsResult<JsLdapMsg> {
        let filter =
            parse_ldap_filter_str(&filter).map_err(|e| to_js_error!("Invalid filter : {:?}", e))?;

        let msg = LdapSearchRequest {
            base: search_base,
            filter: filter,
            scope: ldap3_proto::proto::LdapSearchScope::Subtree,
            attrs: vec![],
            aliases: ldap3_proto::proto::LdapDerefAliases::Never,
            sizelimit: 100,
            timelimit: 100,
            typesonly: false,
        };

        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::SearchRequest(msg),
            ctrl: vec![],
        };

        self.frame
            .send(msg)
            .await
            .map_err(|e| to_js_error!("Unable to send search -> {:?}", e))?;

        let result = self
            .frame
            .next()
            .await
            .ok_or(to_js_error!("No result"))?
            .map_err(|e| to_js_error!("{:?}", e))?;

        Ok(result.into())
    }
}
