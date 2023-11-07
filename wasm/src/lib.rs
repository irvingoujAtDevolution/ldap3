use ldap3_proto::{proto::LdapControl, LdapMsg};
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::wasm_bindgen;

pub mod error;
pub mod ldap_session;
#[cfg(test)]
mod test;

#[wasm_bindgen]
#[derive(Debug, Serialize, Deserialize)]
pub struct JsLdapMsg(LdapMsg);

// impl Serialize for JsLdapMsg {
//     fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         let ldap_controls = &self.0.ctrl;
//         let operation = &self.0.op;
//         let msgid = &self.0.msgid;

//         todo!()
//     }
// }
// fn serialize_ldapControl<S: serde::Serializer>(
//     s: &mut S,
//     ldap_control: &LdapControl,
// ) -> Result<S::Ok, S::Error> {
//     match ldap_control {
//         LdapControl::SyncRequest {
//             criticality,
//             mode,
//             cookie,
//             reload_hint,
//         } => todo!(),
//         LdapControl::SyncState {
//             state,
//             entry_uuid,
//             cookie,
//         } => todo!(),
//         LdapControl::SyncDone {
//             cookie,
//             refresh_deletes,
//         } => todo!(),
//         LdapControl::AdDirsync {
//             flags,
//             max_bytes,
//             cookie,
//         } => todo!(),
//         LdapControl::SimplePagedResults { size, cookie } => todo!(),
//         LdapControl::ManageDsaIT { criticality } => todo!(),
//     };
//     todo!()
// }

impl From<LdapMsg> for JsLdapMsg {
    fn from(value: LdapMsg) -> Self {
        Self(value)
    }
}
