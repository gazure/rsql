use crate::error::Result;
use crate::value::Value;
use async_trait::async_trait;
use mockall::predicate::*;
use mockall::*;
use std::fmt::Debug;

/// Results from a query
#[async_trait]
pub trait QueryResult: Debug + Send + Sync {
    async fn columns(&self) -> Vec<String>;
    async fn rows(&self) -> Vec<Vec<Option<Value>>>;
}

/// In-memory query result
#[derive(Clone, Debug, Default)]
pub struct MemoryQueryResult {
    columns: Vec<String>,
    rows: Vec<Vec<Option<Value>>>,
}

impl MemoryQueryResult {
    pub fn new(columns: Vec<String>, rows: Vec<Vec<Option<Value>>>) -> Self {
        Self { columns, rows }
    }
}

#[async_trait]
impl QueryResult for MemoryQueryResult {
    async fn columns(&self) -> Vec<String> {
        self.columns.clone()
    }

    async fn rows(&self) -> Vec<Vec<Option<Value>>> {
        self.rows.clone()
    }
}

/// Connection to a database
#[automock]
#[async_trait]
pub trait Connection: Debug + Send + Sync {
    async fn execute(&self, sql: &str) -> Result<u64>;
    async fn indexes<'table>(&mut self, table: Option<&'table str>) -> Result<Vec<String>>;
    async fn query(&self, sql: &str, limit: u64) -> Result<Box<dyn QueryResult>>;
    async fn tables(&mut self) -> Result<Vec<String>>;
    async fn close(&mut self) -> Result<()>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_memory_query_result_new() {
        let columns = vec!["a".to_string()];
        let rows = vec![vec![Some(Value::String("foo".to_string()))]];

        let result = MemoryQueryResult::new(columns, rows);

        let column = result.columns.get(0).expect("no column");
        assert_eq!(column, &"a".to_string());
        let row = result.rows.get(0).expect("no rows");
        let data = row.get(0).expect("no row data");
        let value = data.as_ref().expect("no value");
        assert_eq!(value, &Value::String("foo".to_string()));
    }
}
