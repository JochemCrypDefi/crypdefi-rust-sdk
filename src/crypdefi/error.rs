#[derive(Clone, Debug, uniffi::Error, thiserror::Error)]
pub enum BotSdkError {
    #[error("Could not login to sdk")]
    LoginError,

    #[error("Could not parse pkcs8 error")]
    Pkcs8Error(String),

    #[error("Could not parse enviroment variable")]
    EnvVar(String),

    #[error("Error of durin rest request")]
    RequestError(String),
    #[error("There is no access token available")]
    NoAccessToken,

    #[error("There is no refresh token available")]
    NoRefreshToken,

    #[error("Invalid user id")]
    InvalidUserId,

    #[error("Id is not a user id. User Id starts with 'us'")]
    IdNotUserId,
}
