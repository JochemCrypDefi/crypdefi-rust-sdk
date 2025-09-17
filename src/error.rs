use std::env;

/// Possible errors that can occur inside the library
#[derive(Debug, thiserror::Error)]
pub enum BotSdkError {
    #[error("Error in pkcs8 certificates")]
    Pkcs8Error(#[from] p256::pkcs8::Error),

    #[error("Something happened while doing der encoding and decoding")]
    DerError(#[from] p256::pkcs8::der::Error),

    #[error("Something happened during ecdsa signature operation")]
    EcdsaError(#[from] p256::ecdsa::Error),

    #[error("Error of durin rest request")]
    RequestError(#[from] reqwest::Error),

    #[error("Error during json parsing")]
    SerdeJsonError(#[from] serde_json::Error),

    #[error("Error ruing enviroment variable checking")]
    VarError(#[from] env::VarError),

    #[error("There is no access token available")]
    NoAccessToken,

    #[error("There is no refresh token available")]
    NoRefreshToken,

    #[error("Invalid user id")]
    InvalidUserId,

    #[error("Id is not a user id. User Id starts with 'us'")]
    IdNotUserId,

    #[error("Coudl not decode hex error")]
    HxError(#[from] const_hex::FromHexError),

    #[error("Secp256k1 ecdsa error")]
    Secp256k1Error(#[from] secp256k1::Error),

    #[error("Somethin happened that required a custom error: {0}")]
    Custom(String),
}
