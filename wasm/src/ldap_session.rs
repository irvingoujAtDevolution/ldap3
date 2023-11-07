
use wasm_bindgen::prelude::*;
use ws_stream_wasm::WsStreamIo;
use async_io_stream::IoStream;

type JsResult<T> = Result<T,JsValue>;
#[wasm_bindgen]
struct LDAPSession {
    ws_stream: IoStream<WsStreamIo, Vec<u8>>,
    parameters: LDAPSessionParameters
}

#[wasm_bindgen]
struct LDAPSessionParameters{
    server_address_ws_proxy:String,
    username:String,
    password:String,
    dn:String,
    domain:Option<String>,
    kdc_address:Option<String>,
    kdc_address_ws_endpoint:Option<String>,
    server_address:Option<String>,
}

#[wasm_bindgen]
impl LDAPSession {
    pub async fn bind(&self,parames:LDAPSessionParameters) -> JsResult<LDAPSession>{
        let (_,ws_stream_wasm) = ws_stream_wasm::WsMeta::connect(&parames.server_address_ws_proxy, None).await.unwrap();
        let session = LDAPSession{
            ws_stream:ws_stream_wasm.into_io(),
            parameters:parames
        };
        Ok(session)
    }
    pub async fn unbind()->JsResult<bool>{
        todo!()
    }
    pub async fn search(search_base:String,filter:String) -> JsValue {
        todo!()
    }
}