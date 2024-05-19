pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error when a driver for an identifier is not found
    #[error("driver not found for identifier [{identifier}]")]
    DriverNotFound { identifier: String },
    /// Error parsing a URL
    #[error(transparent)]
    InvalidUrl(#[from] url::ParseError),
    /// IO error
    #[error(transparent)]
    IoError(anyhow::Error),
    /// Error when a column type is not supported
    #[error("column type [{column_type}] is not supported for column [{column_name}]")]
    UnsupportedColumnType {
        column_name: String,
        column_type: String,
    },
}

/// Converts a [duckdb::Error] into an [IoError](Error::IoError)
#[cfg(feature = "duckdb")]
impl From<duckdb::Error> for Error {
    fn from(error: duckdb::Error) -> Self {
        Error::IoError(error.into())
    }
}

/// Converts a [libsql::Error] into an [IoError](Error::IoError)
#[cfg(feature = "libsql")]
impl From<libsql::Error> for Error {
    fn from(error: libsql::Error) -> Self {
        Error::IoError(error.into())
    }
}

/// Converts a [postgresql_archive::Error] into an [IoError](Error::IoError)
#[cfg(any(feature = "postgres", feature = "postgresql"))]
impl From<postgresql_archive::Error> for Error {
    fn from(error: postgresql_archive::Error) -> Self {
        Error::IoError(error.into())
    }
}

/// Converts a [postgresql_embedded::Error] into an [IoError](Error::IoError)
#[cfg(any(feature = "postgres", feature = "postgresql"))]
impl From<postgresql_embedded::Error> for Error {
    fn from(error: postgresql_embedded::Error) -> Self {
        Error::IoError(error.into())
    }
}

/// Converts a [regex::Error] into an [IoError](Error::IoError)
impl From<regex::Error> for Error {
    fn from(error: regex::Error) -> Self {
        Error::IoError(error.into())
    }
}

/// Converts a [rusqlite::Error] into an [ParseError](Error::IoError)
#[cfg(feature = "rusqlite")]
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Error::IoError(error.into())
    }
}

/// Converts a [sqlx::Error] into an [ParseError](Error::IoError)
#[cfg(any(feature = "mysql", feature = "postgresql", feature = "sqlite"))]
impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        Error::IoError(error.into())
    }
}

/// Converts a [std::io::Error] into an [IoError](Error::IoError)
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IoError(error.into())
    }
}

/// Converts a [tokio_postgres::Error] into an [IoError](Error::IoError)
#[cfg(feature = "postgres")]
impl From<tokio_postgres::Error> for Error {
    fn from(error: tokio_postgres::Error) -> Self {
        Error::IoError(error.into())
    }
}

/// Converts a [tiberius::error::Error] into an [IoError](Error::IoError)
#[cfg(feature = "sqlserver")]
impl From<tiberius::error::Error> for Error {
    fn from(error: tiberius::error::Error) -> Self {
        Error::IoError(error.into())
    }
}

/// Convert [utf8 errors](std::string::FromUtf8Error) to [IoError](Error::IoError)
impl From<std::string::FromUtf8Error> for Error {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Error::IoError(error.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "duckdb")]
    #[test]
    fn test_duckdb_error() {
        let error = duckdb::Error::QueryReturnedNoRows;
        let io_error = Error::from(error);

        assert_eq!(io_error.to_string(), "Query returned no rows");
    }

    #[cfg(feature = "libsql")]
    #[test]
    fn test_libsql_error() {
        let error = libsql::Error::ConnectionFailed("test".to_string());
        let io_error = Error::from(error);

        assert_eq!(
            io_error.to_string(),
            "Failed to connect to database: `test`"
        );
    }

    #[cfg(any(feature = "postgres", feature = "postgresql"))]
    #[test]
    fn test_archive_error() {
        let error = postgresql_archive::Error::Unexpected("test".to_string());
        let io_error = Error::from(error);

        assert_eq!(io_error.to_string(), "test");
    }

    #[cfg(any(feature = "postgres", feature = "postgresql"))]
    #[test]
    fn test_embedded_error() {
        let archive_error = postgresql_archive::Error::Unexpected("test".to_string());
        let error = postgresql_embedded::Error::ArchiveError(archive_error);
        let io_error = Error::from(error);

        assert_eq!(io_error.to_string(), "test");
    }

    #[test]
    fn test_regex_error() {
        let error = regex::Error::Syntax("test".to_string());
        let io_error = Error::from(error);

        assert_eq!(io_error.to_string(), "test");
    }

    #[cfg(feature = "rusqlite")]
    #[test]
    fn test_rusqlite_error() {
        let error = rusqlite::Error::QueryReturnedNoRows;
        let io_error = Error::from(error);

        assert_eq!(io_error.to_string(), "Query returned no rows");
    }

    #[cfg(any(feature = "mysql", feature = "postgresql", feature = "sqlite"))]
    #[test]
    fn test_sqlx_error() {
        let error = sqlx::Error::RowNotFound;
        let io_error = Error::from(error);

        assert!(io_error.to_string().contains("no rows returned"));
    }

    #[cfg(feature = "sqlserver")]
    #[test]
    fn test_sqlserver_error() {
        let error = tiberius::error::Error::Utf8;
        let io_error = Error::from(error);

        assert_eq!(io_error.to_string(), "UTF-8 error");
    }

    #[test]
    fn test_std_io_error() {
        let error = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let io_error = Error::from(error);

        assert_eq!(io_error.to_string(), "test");
    }

    #[test]
    fn test_from_utf8_error() {
        let invalid_utf8: Vec<u8> = vec![0, 159, 146, 150];
        let utf8_error = String::from_utf8(invalid_utf8).expect_err("expected FromUtf8Error");
        let error = Error::from(utf8_error);
        assert_eq!(
            error.to_string(),
            "invalid utf-8 sequence of 1 bytes from index 1"
        );
    }
}
