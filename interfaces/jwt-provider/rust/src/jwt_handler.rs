// This file is @generated by wasmcloud/weld-codegen 0.6.0.
// It is not intended for manual editing.
// namespace: com.michaelrademeyer.interfaces.jwt_handler

#[allow(unused_imports)]
use async_trait::async_trait;
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use std::{borrow::Borrow, borrow::Cow, io::Write, string::ToString};
#[allow(unused_imports)]
use wasmbus_rpc::{
    cbor::*,
    common::{
        deserialize, message_format, serialize, Context, Message, MessageDispatch, MessageFormat,
        SendOpts, Transport,
    },
    error::{RpcError, RpcResult},
    Timestamp,
};

#[allow(dead_code)]
pub const SMITHY_VERSION: &str = "1.0";

pub type ClaimMap = std::collections::HashMap<String, String>;

// Encode ClaimMap as CBOR and append to output stream
#[doc(hidden)]
#[allow(unused_mut)]
pub fn encode_claim_map<W: wasmbus_rpc::cbor::Write>(
    mut e: &mut wasmbus_rpc::cbor::Encoder<W>,
    val: &ClaimMap,
) -> RpcResult<()>
where
    <W as wasmbus_rpc::cbor::Write>::Error: std::fmt::Display,
{
    e.map(val.len() as u64)?;
    for (k, v) in val {
        e.str(k)?;
        e.str(v)?;
    }
    Ok(())
}

// Decode ClaimMap from cbor input stream
#[doc(hidden)]
pub fn decode_claim_map(d: &mut wasmbus_rpc::cbor::Decoder<'_>) -> Result<ClaimMap, RpcError> {
    let __result = {
        {
            let map_len = d.fixed_map()? as usize;
            let mut m: std::collections::HashMap<String, String> =
                std::collections::HashMap::with_capacity(map_len);
            for _ in 0..map_len {
                let k = d.str()?.to_string();
                let v = d.str()?.to_string();
                m.insert(k, v);
            }
            m
        }
    };
    Ok(__result)
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct User {
    #[serde(rename = "createdAt")]
    #[serde(default)]
    pub created_at: Timestamp,
    #[serde(default)]
    pub email: String,
    #[serde(rename = "firstName")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default)]
    pub id: String,
    #[serde(rename = "lastName")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(rename = "updatedAt")]
    #[serde(default)]
    pub updated_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

// Encode User as CBOR and append to output stream
#[doc(hidden)]
#[allow(unused_mut)]
pub fn encode_user<W: wasmbus_rpc::cbor::Write>(
    mut e: &mut wasmbus_rpc::cbor::Encoder<W>,
    val: &User,
) -> RpcResult<()>
where
    <W as wasmbus_rpc::cbor::Write>::Error: std::fmt::Display,
{
    e.map(7)?;
    e.str("createdAt")?;
    e.i64(val.created_at.sec)?;
    e.u32(val.created_at.nsec)?;
    e.str("email")?;
    e.str(&val.email)?;
    if let Some(val) = val.first_name.as_ref() {
        e.str("firstName")?;
        e.str(val)?;
    } else {
        e.null()?;
    }
    e.str("id")?;
    e.str(&val.id)?;
    if let Some(val) = val.last_name.as_ref() {
        e.str("lastName")?;
        e.str(val)?;
    } else {
        e.null()?;
    }
    e.str("updatedAt")?;
    e.i64(val.updated_at.sec)?;
    e.u32(val.updated_at.nsec)?;
    if let Some(val) = val.username.as_ref() {
        e.str("username")?;
        e.str(val)?;
    } else {
        e.null()?;
    }
    Ok(())
}

// Decode User from cbor input stream
#[doc(hidden)]
pub fn decode_user(d: &mut wasmbus_rpc::cbor::Decoder<'_>) -> Result<User, RpcError> {
    let __result = {
        let mut created_at: Option<Timestamp> = None;
        let mut email: Option<String> = None;
        let mut first_name: Option<Option<String>> = Some(None);
        let mut id: Option<String> = None;
        let mut last_name: Option<Option<String>> = Some(None);
        let mut updated_at: Option<Timestamp> = None;
        let mut username: Option<Option<String>> = Some(None);

        let is_array = match d.datatype()? {
            wasmbus_rpc::cbor::Type::Array => true,
            wasmbus_rpc::cbor::Type::Map => false,
            _ => {
                return Err(RpcError::Deser(
                    "decoding struct User, expected array or map".to_string(),
                ))
            }
        };
        if is_array {
            let len = d.fixed_array()?;
            for __i in 0..(len as usize) {
                match __i {
                    0 => {
                        created_at = Some(wasmbus_rpc::Timestamp {
                            sec: d.i64()?,
                            nsec: d.u32()?,
                        })
                    }
                    1 => email = Some(d.str()?.to_string()),
                    2 => {
                        first_name = if wasmbus_rpc::cbor::Type::Null == d.datatype()? {
                            d.skip()?;
                            Some(None)
                        } else {
                            Some(Some(d.str()?.to_string()))
                        }
                    }
                    3 => id = Some(d.str()?.to_string()),
                    4 => {
                        last_name = if wasmbus_rpc::cbor::Type::Null == d.datatype()? {
                            d.skip()?;
                            Some(None)
                        } else {
                            Some(Some(d.str()?.to_string()))
                        }
                    }
                    5 => {
                        updated_at = Some(wasmbus_rpc::Timestamp {
                            sec: d.i64()?,
                            nsec: d.u32()?,
                        })
                    }
                    6 => {
                        username = if wasmbus_rpc::cbor::Type::Null == d.datatype()? {
                            d.skip()?;
                            Some(None)
                        } else {
                            Some(Some(d.str()?.to_string()))
                        }
                    }

                    _ => d.skip()?,
                }
            }
        } else {
            let len = d.fixed_map()?;
            for __i in 0..(len as usize) {
                match d.str()? {
                    "createdAt" => {
                        created_at = Some(wasmbus_rpc::Timestamp {
                            sec: d.i64()?,
                            nsec: d.u32()?,
                        })
                    }
                    "email" => email = Some(d.str()?.to_string()),
                    "firstName" => {
                        first_name = if wasmbus_rpc::cbor::Type::Null == d.datatype()? {
                            d.skip()?;
                            Some(None)
                        } else {
                            Some(Some(d.str()?.to_string()))
                        }
                    }
                    "id" => id = Some(d.str()?.to_string()),
                    "lastName" => {
                        last_name = if wasmbus_rpc::cbor::Type::Null == d.datatype()? {
                            d.skip()?;
                            Some(None)
                        } else {
                            Some(Some(d.str()?.to_string()))
                        }
                    }
                    "updatedAt" => {
                        updated_at = Some(wasmbus_rpc::Timestamp {
                            sec: d.i64()?,
                            nsec: d.u32()?,
                        })
                    }
                    "username" => {
                        username = if wasmbus_rpc::cbor::Type::Null == d.datatype()? {
                            d.skip()?;
                            Some(None)
                        } else {
                            Some(Some(d.str()?.to_string()))
                        }
                    }
                    _ => d.skip()?,
                }
            }
        }
        User {
            created_at: if let Some(__x) = created_at {
                __x
            } else {
                return Err(RpcError::Deser(
                    "missing field User.created_at (#0)".to_string(),
                ));
            },

            email: if let Some(__x) = email {
                __x
            } else {
                return Err(RpcError::Deser("missing field User.email (#1)".to_string()));
            },
            first_name: first_name.unwrap(),

            id: if let Some(__x) = id {
                __x
            } else {
                return Err(RpcError::Deser("missing field User.id (#3)".to_string()));
            },
            last_name: last_name.unwrap(),

            updated_at: if let Some(__x) = updated_at {
                __x
            } else {
                return Err(RpcError::Deser(
                    "missing field User.updated_at (#5)".to_string(),
                ));
            },
            username: username.unwrap(),
        }
    };
    Ok(__result)
}
/// The JwtHandler service has a single method, calculate, which
/// calculates the factorial of its whole number parameter.
/// wasmbus.contractId: michaelrademeyer:interfaces:jwt_handler
/// wasmbus.providerReceive
#[async_trait]
pub trait JwtHandler {
    /// returns the capability contract id for this interface
    fn contract_id() -> &'static str {
        "michaelrademeyer:interfaces:jwt_handler"
    }
    async fn generate_jwt(&self, ctx: &Context, arg: &User) -> RpcResult<String>;
    async fn validate_jwt<TS: ToString + ?Sized + std::marker::Sync>(
        &self,
        ctx: &Context,
        arg: &TS,
    ) -> RpcResult<bool>;
    async fn get_jwt_values<TS: ToString + ?Sized + std::marker::Sync>(
        &self,
        ctx: &Context,
        arg: &TS,
    ) -> RpcResult<ClaimMap>;
}

/// JwtHandlerReceiver receives messages defined in the JwtHandler service trait
/// The JwtHandler service has a single method, calculate, which
/// calculates the factorial of its whole number parameter.
#[doc(hidden)]
#[async_trait]
pub trait JwtHandlerReceiver: MessageDispatch + JwtHandler {
    async fn dispatch(&self, ctx: &Context, message: Message<'_>) -> Result<Vec<u8>, RpcError> {
        match message.method {
            "GenerateJwt" => {
                let value: User = wasmbus_rpc::common::deserialize(&message.arg)
                    .map_err(|e| RpcError::Deser(format!("'User': {}", e)))?;

                let resp = JwtHandler::generate_jwt(self, ctx, &value).await?;
                let buf = wasmbus_rpc::common::serialize(&resp)?;

                Ok(buf)
            }
            "ValidateJwt" => {
                let value: String = wasmbus_rpc::common::deserialize(&message.arg)
                    .map_err(|e| RpcError::Deser(format!("'String': {}", e)))?;

                let resp = JwtHandler::validate_jwt(self, ctx, &value).await?;
                let buf = wasmbus_rpc::common::serialize(&resp)?;

                Ok(buf)
            }
            "GetJwtValues" => {
                let value: String = wasmbus_rpc::common::deserialize(&message.arg)
                    .map_err(|e| RpcError::Deser(format!("'String': {}", e)))?;

                let resp = JwtHandler::get_jwt_values(self, ctx, &value).await?;
                let buf = wasmbus_rpc::common::serialize(&resp)?;

                Ok(buf)
            }
            _ => Err(RpcError::MethodNotHandled(format!(
                "JwtHandler::{}",
                message.method
            ))),
        }
    }
}

/// JwtHandlerSender sends messages to a JwtHandler service
/// The JwtHandler service has a single method, calculate, which
/// calculates the factorial of its whole number parameter.
/// client for sending JwtHandler messages
#[derive(Debug)]
pub struct JwtHandlerSender<T: Transport> {
    transport: T,
}

impl<T: Transport> JwtHandlerSender<T> {
    /// Constructs a JwtHandlerSender with the specified transport
    pub fn via(transport: T) -> Self {
        Self { transport }
    }

    pub fn set_timeout(&self, interval: std::time::Duration) {
        self.transport.set_timeout(interval);
    }
}

#[cfg(target_arch = "wasm32")]
impl JwtHandlerSender<wasmbus_rpc::actor::prelude::WasmHost> {
    /// Constructs a client for sending to a JwtHandler provider
    /// implementing the 'michaelrademeyer:interfaces:jwt_handler' capability contract, with the "default" link
    pub fn new() -> Self {
        let transport = wasmbus_rpc::actor::prelude::WasmHost::to_provider(
            "michaelrademeyer:interfaces:jwt_handler",
            "default",
        )
        .unwrap();
        Self { transport }
    }

    /// Constructs a client for sending to a JwtHandler provider
    /// implementing the 'michaelrademeyer:interfaces:jwt_handler' capability contract, with the specified link name
    pub fn new_with_link(link_name: &str) -> wasmbus_rpc::error::RpcResult<Self> {
        let transport = wasmbus_rpc::actor::prelude::WasmHost::to_provider(
            "michaelrademeyer:interfaces:jwt_handler",
            link_name,
        )?;
        Ok(Self { transport })
    }
}
#[async_trait]
impl<T: Transport + std::marker::Sync + std::marker::Send> JwtHandler for JwtHandlerSender<T> {
    #[allow(unused)]
    async fn generate_jwt(&self, ctx: &Context, arg: &User) -> RpcResult<String> {
        let buf = wasmbus_rpc::common::serialize(arg)?;

        let resp = self
            .transport
            .send(
                ctx,
                Message {
                    method: "JwtHandler.GenerateJwt",
                    arg: Cow::Borrowed(&buf),
                },
                None,
            )
            .await?;

        let value: String = wasmbus_rpc::common::deserialize(&resp)
            .map_err(|e| RpcError::Deser(format!("'{}': String", e)))?;
        Ok(value)
    }
    #[allow(unused)]
    async fn validate_jwt<TS: ToString + ?Sized + std::marker::Sync>(
        &self,
        ctx: &Context,
        arg: &TS,
    ) -> RpcResult<bool> {
        let buf = wasmbus_rpc::common::serialize(&arg.to_string())?;

        let resp = self
            .transport
            .send(
                ctx,
                Message {
                    method: "JwtHandler.ValidateJwt",
                    arg: Cow::Borrowed(&buf),
                },
                None,
            )
            .await?;

        let value: bool = wasmbus_rpc::common::deserialize(&resp)
            .map_err(|e| RpcError::Deser(format!("'{}': Boolean", e)))?;
        Ok(value)
    }
    #[allow(unused)]
    async fn get_jwt_values<TS: ToString + ?Sized + std::marker::Sync>(
        &self,
        ctx: &Context,
        arg: &TS,
    ) -> RpcResult<ClaimMap> {
        let buf = wasmbus_rpc::common::serialize(&arg.to_string())?;

        let resp = self
            .transport
            .send(
                ctx,
                Message {
                    method: "JwtHandler.GetJwtValues",
                    arg: Cow::Borrowed(&buf),
                },
                None,
            )
            .await?;

        let value: ClaimMap = wasmbus_rpc::common::deserialize(&resp)
            .map_err(|e| RpcError::Deser(format!("'{}': ClaimMap", e)))?;
        Ok(value)
    }
}
