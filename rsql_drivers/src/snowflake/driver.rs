use crate::Result;
use crate::Metadata;
use crate::MemoryQueryResult;
use crate::QueryResult;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use url::Url;

#[derive(Debug)]
pub struct Driver;

#[async_trait]
impl crate::Driver for Driver {
    fn identifier(&self) -> &'static str {
        "snowflake"
    }

    async fn connect(&self, url: String, password: Option<String>) -> Result<Box<dyn crate::Connection>> {
        Ok(Box::new(SnowflakeConnection::new(url)?))
    }
}


#[derive(Debug)]
pub(crate) struct SnowflakeConnection {
    client: Arc<Mutex<reqwest::Client>>
}


impl SnowflakeConnection {
    pub(crate) fn new(url: String) -> Result<SnowflakeConnection> {
        let parsed_url = Url::parse(url.as_str())?;
        let client = reqwest::Client::new();

        Ok(Self{
            client: Arc::new(Mutex::new(client))
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
