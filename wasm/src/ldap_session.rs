use core::panic;
use std::collections::HashMap;

use async_io_stream::IoStream;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;
use ldap3_proto::{
    parse_ldap_filter_str,
    proto::{LdapAddRequest, LdapBindCred, LdapBindRequest, LdapOp, LdapSearchRequest},
    LdapCodec, LdapMsg, LdapSearchScope,
};
use tokio_util::codec::Framed;
use tracing::{debug, info};
use wasm_bindgen::prelude::*;
use ws_stream_wasm::WsStreamIo;

use crate::{to_js_error, JsResult};

#[wasm_bindgen]
pub struct LdapSession {
    frame: Framed<IoStream<WsStreamIo, Vec<u8>>, LdapCodec>,
    message_id: i32,
    _parameters: LdapSessionParameters,
}

#[wasm_bindgen]
pub struct LdapSessionParameters {
    server_address_ws_proxy: String,
    _kdc_address: Option<String>, // to be used in the future
    _kdc_address_ws_endpoint: Option<String>, // to be used in the future
}

#[wasm_bindgen]
impl LdapSessionParameters {
    #[wasm_bindgen(constructor)]
    pub fn new(server_address_ws_proxy: String) -> Self {
        Self {
            server_address_ws_proxy,
            _kdc_address: None,
            _kdc_address_ws_endpoint: None,
        }
    }
}
impl LdapSession {
    fn next_message_id(&mut self) -> i32 {
        self.message_id += 1;
        self.message_id
    }
}

#[wasm_bindgen]
pub struct LdapSearchResultStream;

#[wasm_bindgen]
impl LdapSession {
    pub async fn connect(params: LdapSessionParameters) -> JsResult<LdapSession> {


        let (_ws_meta, ws_stream_wasm) =
            ws_stream_wasm::WsMeta::connect(&params.server_address_ws_proxy, None)
                .await
                .unwrap();
        let io_stream = ws_stream_wasm.into_io();
        let framed = Framed::new(io_stream, LdapCodec::default());
        let session = LdapSession {
            frame: framed,
            message_id: 0,
            _parameters: params,
        };
        Ok(session)
    }

    pub async fn bind(
        &mut self,
        distinguished_name: String,
        password: String,
    ) -> JsResult<JsValue> {
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
            return Ok(serde_wasm_bindgen::to_value(&msg)?);
        }
        Err(to_js_error!("Failed to bind"))
    }

    pub async fn search(
        &mut self,
        search_base: String,
        filter: String,
        scope: JsLdapSearchScope,
        size_limit: Option<i32>,
        time_limit: Option<i32>,
    ) -> JsResult<JsValue> {
        let filter =
            parse_ldap_filter_str(&filter).map_err(|e| to_js_error!("Invalid filter : {:?}", e))?;

        let msg = LdapSearchRequest {
            base: search_base,
            filter,
            scope: scope.into(),
            attrs: vec![],
            aliases: ldap3_proto::proto::LdapDerefAliases::Never,
            sizelimit: size_limit.unwrap_or(100),
            timelimit: time_limit.unwrap_or(10),
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

        let mut res_array = Vec::new();
        loop {
            let res = self
                .frame
                .next()
                .await
                .expect("msg did not arrive")
                .expect("error resolve result");
            match &res.op {
                LdapOp::SearchResultEntry(entry) => {
                    info!("entry = {:?}", entry);
                }
                LdapOp::SearchResultDone(_) => {
                    break;
                }
                LdapOp::SearchResultReference(res) => {
                    info!("reference = {:?}", res);
                }
                _ => {
                    panic!("unexpected result = {:?}", res);
                }
            };
            res_array.push(res);
        }

        Ok(serde_wasm_bindgen::to_value(&res_array)?)
    }

    /// TODO:Attributes cannot be added at this moment, work in progress
    pub async fn add(&mut self, dn: String, attributes: JsValue) -> JsResult<JsValue> {
        let _map:HashMap<String,Vec<u8>> = serde_wasm_bindgen::from_value(attributes)?;
        let request = LdapAddRequest {
            dn,
            attributes: vec![],
        };

        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::AddRequest(request),
            ctrl: vec![],
        };

        self.frame
            .send(msg)
            .await
            .map_err(|e| to_js_error!("failed to add {:?}", e))?;

        let result = self
            .frame
            .next()
            .await
            .ok_or(to_js_error!("No result"))?
            .map_err(|e| to_js_error!("{:?}", e))?;


        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    pub async fn delete(&mut self, dn: String) -> JsResult<JsValue> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::DelRequest(dn),
            ctrl: vec![],
        };

        self.frame
            .send(msg)
            .await
            .map_err(|e| to_js_error!("failed to delete {:?}", e))?;
        self.frame.flush().await.unwrap();

        let result = if let Some(msg) = self.frame.next().await {
            match msg {
                Ok(res) => {
                    debug!(" DELETE RESULT =  {:?}", &res);
                    match res.op {
                        LdapOp::DelResponse(..) => res,
                        _ => panic!("Error: {:?}", res),
                    }
                }
                Err(e) => panic!("Error: {:?}", e),
            }
        } else {
            panic!("No result")
        };

        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    pub async fn modify_dn(
        &mut self,
        dn: String,
        newrdn: String,
        delete_old_rdn: bool,
        new_superior: Option<String>,
    ) -> JsResult<JsValue> {
        let msg = LdapMsg {
            msgid: self.next_message_id(),
            op: LdapOp::ModifyDNRequest(ldap3_proto::proto::LdapModifyDNRequest {
                dn,
                newrdn,
                deleteoldrdn: delete_old_rdn,
                new_superior,
            }),
            ctrl: vec![],
        };

        self.frame
            .send(msg)
            .await
            .map_err(|e| to_js_error!("failed to modify {:?}", e))?;

        let result = self
            .frame
            .next()
            .await
            .ok_or(to_js_error!("No result"))?
            .map_err(|e| to_js_error!("{:?}", e))?;

        Ok(serde_wasm_bindgen::to_value(&result)?)
    }
}

#[wasm_bindgen]
pub enum JsLdapSearchScope {
    Base = 0,
    OneLevel = 1,
    Subtree = 2,
    Children = 3,
}

impl From<JsLdapSearchScope> for LdapSearchScope {
    fn from(val: JsLdapSearchScope) -> Self {
        match val {
            JsLdapSearchScope::Base => LdapSearchScope::Base,
            JsLdapSearchScope::OneLevel => LdapSearchScope::OneLevel,
            JsLdapSearchScope::Subtree => LdapSearchScope::Subtree,
            JsLdapSearchScope::Children => LdapSearchScope::Children,
        }
    }
}
