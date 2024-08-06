use crate::snowflake::SnowflakeError;
use crate::MemoryQueryResult;
use crate::Metadata;
use crate::QueryResult;
use crate::Result;
use crate::Row;
use crate::Value;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use jwt_simple::algorithms::RS256KeyPair;
use jwt_simple::claims::Claims;
use jwt_simple::prelude::Duration;
use jwt_simple::prelude::RS256PublicKey;
use jwt_simple::prelude::RSAKeyPairLike;
use reqwest::header::HeaderMap;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::sync::Mutex;
use tracing::{error, info};
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
    issuer: String,
    subject: String,
    key_pair: RS256KeyPair,
    jwt_expires_at: DateTime<Utc>,
    client: Mutex<reqwest::Client>,
}

impl SnowflakeConnection {
    /// Generate a fingerprint for a public key
    /// Doing this manually since jwt_simple uses url-safe base64 when standard is required
    ///
    /// # Errors
    /// Errors if the public key is malformed
    fn public_key_fingerprint(public_key: &str) -> Result<String> {
        let public_key = RS256PublicKey::from_pem(&public_key)
            .map_err(|_| SnowflakeError::MalformedPublicKey)?;
        let pub_key_der = public_key
            .to_der()
            .map_err(|_| SnowflakeError::MalformedPublicKey)?;
        let mut hasher = Sha256::new();
        hasher.update(&pub_key_der);
        let hash = hasher.finalize();
        let public_key_fp = STANDARD.encode(hash);
        Ok(public_key_fp)
    }

    pub(crate) async fn new(url: String) -> Result<SnowflakeConnection> {
        let parsed_url = Url::parse(url.as_str())?;
        let query_params: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();
        let base_url = parsed_url
            .host_str()
            .ok_or(SnowflakeError::MissingAccount)?
            .to_string();
        let account = base_url
            .split(".")
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

        let private_key = std::fs::read_to_string(private_key_file)
            .map_err(|_| SnowflakeError::MissingPrivateKey)?;
        let public_key = std::fs::read_to_string(public_key_file)
            .map_err(|_| SnowflakeError::MissingPublicKey)?;
        let key_pair =
            RS256KeyPair::from_pem(&private_key).map_err(|_| SnowflakeError::MissingPrivateKey)?;

        let fingerprint = Self::public_key_fingerprint(&public_key)?;
        let issuer = format!("{}.{}.SHA256:{}", account, user, fingerprint);
        let subject = format!("{}.{}", account, user);

        let base_url = format!("https://{}/api/v2/statements", base_url);
        let jwt_expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
        let client = Mutex::new(Self::new_client(&issuer, &subject, &key_pair)?);

        Ok(Self {
            base_url,
            issuer,
            subject,
            key_pair,
            jwt_expires_at,
            client,
        })
    }

    fn new_client(issuer: &str, subject: &str, key_pair: &RS256KeyPair) -> Result<reqwest::Client> {
        let claims = Claims::create(Duration::from_hours(1))
            .with_issuer(issuer)
            .with_subject(subject);

        let token = key_pair
            .sign(claims)
            .map_err(|_| SnowflakeError::JwtSignature)?;
        info!("{token}");

        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_owned(),
            format!("Bearer {}", token.clone()),
        );
        headers.insert("Content-Type".to_owned(), "application/json".to_owned());
        headers.insert(
            "X-Snowflake-Authorization-Token-Type".to_owned(),
            "KEYPAIR_JWT".to_owned(),
        );
        let header_map: HeaderMap = (&headers)
            .try_into()
            .map_err(|_| SnowflakeError::MalformedHeaders)?;

        reqwest::ClientBuilder::new()
            .user_agent("rsql-Snowflake-Driver")
            .default_headers(header_map)
            .build()
            .map_err(|_| SnowflakeError::ClientCreation.into())
    }

    async fn request(&mut self, sql: &str) -> Result<reqwest::Response> {
        if self.jwt_expires_at < chrono::Utc::now() {
            let mut client = self.client.lock().await;
            *client = Self::new_client(&self.issuer, &self.subject, &self.key_pair)?;
        }

        let client = self.client.lock().await;
        client
            .post(&self.base_url)
            .body(
                json!({
                    "statement": sql,
                    "timeout": 10,
                })
                .to_string(),
            )
            .send()
            .await
            .map_err(|e| {
                error!("snowflake request error: {:?}", e);
                SnowflakeError::Request.into()
            })
    }
}

#[async_trait]
impl crate::Connection for SnowflakeConnection {
    async fn execute(&mut self, sql: &str) -> Result<u64> {
        let response = self.request(sql).await?;
        let status = response.status();
        if !status.is_success() {
            error!("error: {:?}", response.text().await);
            return Err(SnowflakeError::Response.into());
        }
        let response_json: serde_json::Value = response.json().await.map_err(|e| {
            error!("error: {:?}", e);
            SnowflakeError::Response
        })?;
        info!("{:?}", response_json.clone());
        let row_count = response_json["data"][0][0]
            .as_str()
            .ok_or(SnowflakeError::Response)?
            .parse::<u64>()
            .map_err(|_| SnowflakeError::Response)?;
        Ok(row_count)
    }

    async fn metadata(&mut self) -> Result<Metadata> {
        Ok(Metadata::default())
    }

    async fn query(&mut self, sql: &str) -> Result<Box<dyn QueryResult>> {
        let response = self.request(sql).await?;
        let response_json: serde_json::Value = response.json().await.map_err(|e| {
            error!("error: {:?}", e);
            SnowflakeError::Response
        })?;
        info!("{:?}", response_json);

        let _handle = response_json["statementHandle"]
            .as_str()
            .ok_or(SnowflakeError::Response)?;
        let _partitions = response_json["resultSetMetaData"]["partitionInfo"]
            .as_array()
            .ok_or(SnowflakeError::Response)?;
        let column_names: Vec<_> = response_json["resultSetMetaData"]["rowType"]
            .as_array()
            .ok_or(SnowflakeError::Response)?
            .iter()
            .map(|value| {
                let name = value["name"]
                    .as_str()
                    .unwrap_or("name not found")
                    .to_string();
                name
            })
            .collect();

        let rows: Vec<Row> = response_json["data"]
            .as_array()
            .ok_or(SnowflakeError::Response)?
            .iter()
            .map(|row| {
                let default = vec![];
                let row = row.as_array().unwrap_or(&default);
                let values: Vec<Value> = row
                    .iter()
                    .map(|value| {
                        Value::String(value.as_str().unwrap_or("value not found").to_string())
                    })
                    .collect();
                Row::new(values)
            })
            .collect();

        let qr = MemoryQueryResult::new(column_names, rows);
        Ok(Box::new(qr))
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
