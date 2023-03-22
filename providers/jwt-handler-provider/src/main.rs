//! jwt_handler-provider capability provider
//!
//!
use std::{collections::{BTreeMap, HashMap}, sync::Arc};

use chrono::Utc;
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use sha2::Sha256;
use tokio::sync::RwLock;
use wasmbus_rpc::provider::prelude::*;
use jwt_provider::{JwtHandler, JwtHandlerReceiver, User};


// main (via provider_main) initializes the threaded tokio executor,
// listens to lattice rpcs, handles actor links,
// and returns only when it receives a shutdown message
//
fn main() -> Result<(), Box<dyn std::error::Error>> {
    provider_main(JwtHandlerProviderProvider::default(), Some("JwtHandlerProvider".to_string()))?;

    eprintln!("jwt_handler-provider provider exiting");
    Ok(())
}

/// jwt_handler-provider capability provider implementation
#[derive(Default, Clone, Provider)]
#[services(JwtHandler)]
struct JwtHandlerProviderProvider {
    secret: Arc<RwLock<String>>,
    issuer: Arc<RwLock<String>>,
    expiration: Arc<RwLock<i64>>
}

/// use default implementations of provider message handlers
impl ProviderDispatch for JwtHandlerProviderProvider {}

#[async_trait]
impl ProviderHandler for JwtHandlerProviderProvider {

    async fn put_link(&self, ld: &LinkDefinition) -> Result<bool, RpcError> {
        let ld_values: HashMap<_, _> = ld.values.clone().into_iter().collect();
        if let Some(value) = ld_values.get("secret") {
            let mut seceret_update_map = self.secret.write().await;
            *seceret_update_map = value.to_string();
        }
        if let Some(value) = ld_values.get("issuer") {
            let mut seceret_update_issuer = self.issuer.write().await;
            *seceret_update_issuer = value.to_string();
        }
        if let Some(value) = ld_values.get("expiration") {
            let mut seceret_update_expiration = self.expiration.write().await;
            *seceret_update_expiration = value.parse::<i64>().unwrap();
        }

        Ok(true)
    }

}

/// Handle Factorial methods
#[async_trait]
impl JwtHandler for JwtHandlerProviderProvider {
    async fn generate_jwt(&self, _ctx: &Context, _arg: &User) -> RpcResult<String> {
        let read_secert = self.secret.read().await;
        let read_issuer = self.issuer.read().await;
        let read_expiration = self.expiration.read().await;
        let key: Hmac<Sha256> = Hmac::new_from_slice(read_secert.as_bytes()).unwrap();
        let mut claims = BTreeMap::new();
        claims.insert("sub", _arg.id.clone());
        claims.insert("username", _arg.username.clone().unwrap());
        claims.insert("first_name", _arg.first_name.clone().unwrap());
        claims.insert("last_name", _arg.last_name.clone().unwrap());
        claims.insert("email", _arg.email.clone());
        claims.insert("nbf", Utc::now().timestamp().to_string());
        claims.insert("iss", (*read_issuer).clone());
        claims.insert("exp", (Utc::now().timestamp() + *read_expiration).to_string());
        claims.insert("iat", Utc::now().timestamp().to_string());

        claims.sign_with_key(&key).map_err(|e| {
            RpcError::Other (e.to_string())
        })       
    }

    async fn validate_jwt<TS: ToString + ?Sized + Sync>(&self, _ctx: &Context, arg: &TS) -> RpcResult<bool>
    {
        let read_secert = self.secret.read().await;
        let key: Hmac<Sha256> = Hmac::new_from_slice(read_secert.as_bytes()).unwrap();
        let token_str = arg.to_string();
        let claims: BTreeMap<String, String> = token_str.verify_with_key(&key).unwrap_or_default();
        if claims.is_empty() {
            return Ok(false);
        }
        Ok(true)
    }

    async fn get_jwt_values<TS: ToString + ?Sized + Sync>(&self, _ctx: &Context, arg: &TS) -> RpcResult<HashMap<String, String>> 
    {
        let read_secert = self.secret.read().await;
        let key: Hmac<Sha256> = Hmac::new_from_slice(read_secert.as_bytes()).unwrap();
        let token_str = arg.to_string();
        let claims: BTreeMap<String, String> = token_str.verify_with_key(&key).unwrap_or_default();
        if claims.is_empty() {
            return Ok(HashMap::new());
        }
        Ok(claims.into_iter().collect())
    }
    
    async fn is_token_expired<TS: ToString + ?Sized + Sync>(&self, _ctx: &Context, arg: &TS) -> RpcResult<bool> 
    {
        let read_secert = self.secret.read().await;
        let key: Hmac<Sha256> = Hmac::new_from_slice(read_secert.as_bytes()).unwrap();
        let token_str = arg.to_string();
        let claims: BTreeMap<String, String> = token_str.verify_with_key(&key).unwrap_or_default();
        if claims.is_empty() {
            return Ok(false);
        }
        let exp = claims.get("exp").unwrap().parse::<i64>().unwrap();
        let now = Utc::now().timestamp();
        if now > exp {
            return Ok(false);
        }
        Ok(true)
    }
}