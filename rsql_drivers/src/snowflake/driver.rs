use crate::snowflake::SnowflakeError;
use crate::MemoryQueryResult;
use crate::Metadata;
use crate::QueryResult;
use crate::Result;
use jwt_simple::algorithms::RS256KeyPair;
use jwt_simple::prelude::Duration;
use async_trait::async_trait;
use jwt_simple::claims::Claims;
use jwt_simple::prelude::RS256PublicKey;
use jwt_simple::prelude::RSAKeyPairLike;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use url::Url;

#[derive(Debug)]
pub struct Driver;

#[async_trait]
impl crate::Driver for Driver {
    fn identifier(&self) -> &'static str {
        "snowflake"
    }

    async fn connect(
        &self,
        url: String,
        _password: Option<String>,
    ) -> Result<Box<dyn crate::Connection>> {
        Ok(Box::new(SnowflakeConnection::new(url).await?))
    }
}

#[derive(Debug)]
pub(crate) struct SnowflakeConnection {
    base_url: String,
    client: Arc<Mutex<reqwest::Client>>,
}

impl SnowflakeConnection {
    pub(crate) async fn new(url: String) -> Result<SnowflakeConnection> {
        let parsed_url = Url::parse(url.as_str())?;
        let query_params: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();
        let base_url = parsed_url.host_str().ok_or(SnowflakeError::MissingAccount)?.to_string();
        let account = base_url.split(".")
            .next()
            .ok_or(SnowflakeError::MissingAccount)?
            .to_string();
        let user = query_params
            .get("user")
            .ok_or(SnowflakeError::MissingUser)?
            .to_string();
        let private_key_file = query_params
            .get("private_key_file")
            .ok_or(SnowflakeError::MissingPrivateKey)?
            .to_string();
        let public_key_file = query_params
            .get("public_key_file")
            .ok_or(SnowflakeError::MissingPublicKey)?
            .to_string();
        eprintln!(
            "private_key: {}, account: {}, user: {}, public_key: {}",
            private_key_file, account, user, public_key_file
        );

        let private_key = std::fs::read_to_string(private_key_file).map_err(|_| SnowflakeError::MissingPrivateKey)?;
        let public_key = std::fs::read_to_string(public_key_file).map_err(|_| SnowflakeError::MissingPublicKey)?;
        let key_pair = RS256KeyPair::from_pem(&private_key).map_err(|_| SnowflakeError::MissingPrivateKey)?;
        let public_key = RS256PublicKey::from_pem(&public_key).map_err(|_| SnowflakeError::MissingPublicKey)?;
        let public_key_fp = public_key.sha256_thumbprint();
        let public_key_fp_forced = "nR8guceFPPPm4oksBB1CGqVA1H/k+LfiwTPEhxevNrs=".to_owned();
        eprintln!("public key fp: {public_key_fp}");
        let claims = Claims::create(Duration::from_hours(1))
            .with_issuer(format!("{}.{}.SHA256:{}", account, user, public_key_fp_forced))
            .with_subject(format!("{}.{}", account, user));

        let token = key_pair.sign(claims).map_err(|_| SnowflakeError::Unspecified)?;

        let mut headers = HashMap::new();
        headers.insert("Authorization".to_owned(), format!("Bearer {}", token.clone()));
        headers.insert("Content-Type".to_owned(), "application/json".to_owned());
        headers.insert("X-Snowflake-Authorization-Token-Type".to_owned(), "KEYPAIR_JWT".to_owned());
        eprintln!("headers: {headers:?}, base_url: {base_url}");

        let client = reqwest::ClientBuilder::new()
            .user_agent("rsql Snowflake Driver")
            .default_headers((&headers).try_into().map_err(|_| SnowflakeError::Unspecified)?)
            .build()
            .map_err(|_| SnowflakeError::Unspecified)?;
        let base_url = format!("https://{}/api/v2/statements", base_url);

        let req = client.post(base_url.to_string())
            .body(json!({
                "statement": "SELECT * FROM CARDSTEST.PUBLIC.CARDS",
                "timeout": 10,
            }).to_string())
            .bearer_auth(token)
            .build().map_err(|_| SnowflakeError::Unspecified)?;
        let resp = client.execute(req).await.map_err(|_| SnowflakeError::Unspecified)?;
        eprintln!("resp: {resp:?}");
        let resp_content = resp.text().await.map_err(|_| SnowflakeError::Unspecified)?;
        eprintln!("resp_content: {resp_content:?}");

        Ok(Self {
            base_url: format!("https://{}/api/v2/statements", base_url),
            client: Arc::new(Mutex::new(client)),
        })
    }
}

#[async_trait]
impl crate::Connection for SnowflakeConnection {
    async fn execute(&mut self, sql: &str) -> Result<u64> {
        Ok(0)
    }

    async fn metadata(&mut self) -> Result<Metadata> {
        Ok(Metadata::default())
    }

    async fn query(&mut self, sql: &str) -> Result<Box<dyn QueryResult>> {
        let qr = MemoryQueryResult::new(vec![], vec![]);
        Ok(Box::new(qr))
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
