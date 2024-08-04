
#[derive(Debug)]
pub enum SnowflakeError {
    MissingPrivateKey,
    MissingAccount,
    MissingUser,
    MissingPublicKey,
    Unspecified,
}
