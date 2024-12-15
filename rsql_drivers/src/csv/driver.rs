use crate::delimited::driver::Driver as DelimitedDriver;
use crate::error::Result;
use async_trait::async_trait;

#[derive(Debug)]
pub struct Driver;

#[async_trait]
impl crate::Driver for Driver {
    fn identifier(&self) -> &'static str {
        "csv"
    }

    async fn connect(
        &self,
        url: String,
        password: Option<String>,
    ) -> Result<Box<dyn crate::Connection>> {
        let url = format!("{url}&separator=,");
        DelimitedDriver.connect(url, password).await
    }
}

#[cfg(test)]
mod test {
    use crate::{DriverManager, Value};

    const CRATE_DIRECTORY: &str = env!("CARGO_MANIFEST_DIR");

    fn database_url() -> String {
        format!("csv://?file={CRATE_DIRECTORY}/../datasets/users.csv")
    }

    #[tokio::test]
    async fn test_driver_connect() -> anyhow::Result<()> {
        let database_url = database_url();
        let driver_manager = DriverManager::default();
        let mut connection = driver_manager.connect(&database_url).await?;
        let expected_url = format!("{database_url}&separator=,");
        assert_eq!(&expected_url, connection.url());
        connection.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_connection_interface() -> anyhow::Result<()> {
        let database_url = database_url();
        let driver_manager = DriverManager::default();
        let mut connection = driver_manager.connect(&database_url).await?;

        let mut query_result = connection
            .query("SELECT id, name FROM users ORDER BY id")
            .await?;

        assert_eq!(query_result.columns().await, vec!["id", "name"]);
        assert_eq!(
            query_result.next().await,
            Some(vec![Value::I64(1), Value::String("John Doe".to_string())])
        );
        assert_eq!(
            query_result.next().await,
            Some(vec![Value::I64(2), Value::String("Jane Smith".to_string())])
        );
        assert!(query_result.next().await.is_none());

        connection.close().await?;
        Ok(())
    }
}
