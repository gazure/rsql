#[cfg(feature = "postgresql")]
pub(crate) mod postgresql;

mod connection;
mod drivers;
#[cfg(feature = "sqlite")]
pub(crate) mod sqlite;
mod value;

#[cfg(test)]
pub use connection::MockConnection;
pub use connection::{Connection, QueryResult};
pub use drivers::{Driver, DriverManager};