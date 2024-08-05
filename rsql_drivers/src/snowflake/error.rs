#[derive(Debug)]
pub enum SnowflakeError {
    MissingPrivateKey,
    MissingAccount,
    MissingUser,
    MissingPublicKey,
    Unspecified,
}

impl From<SnowflakeError> for anyhow::Error {
    fn from(error: SnowflakeError) -> Self {
        match error {
            SnowflakeError::MissingPrivateKey => anyhow::anyhow!("Missing private key"),
            SnowflakeError::MissingAccount => anyhow::anyhow!("Missing account"),
            SnowflakeError::MissingUser => anyhow::anyhow!("Missing user"),
            SnowflakeError::MissingPublicKey => anyhow::anyhow!("Missing public key"),
            SnowflakeError::Unspecified => anyhow::anyhow!("Unspecified error"),
        }
    }
}
