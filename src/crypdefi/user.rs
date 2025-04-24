use super::http::{SigResponse, SignatureRequestKind, get_wallets, logout, refresh_auth, sign};
use super::{
    error::BotSdkError,
    http::{CraRequest, LoginRequest, Wallet, cra_login, login},
};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use p256::ecdsa::{VerifyingKey, signature::Verifier};
use pkcs8::{DecodePrivateKey, der::Encode};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

fn sign_challenge_with_ecdsa(
    signing_key: SigningKey,
    challenge: Vec<u8>,
) -> Result<DerSignature, BotSdkError> {
    // Sign the challenge
    let signature: DerSignature = signing_key.sign(&challenge);
    let verifying_key = VerifyingKey::from(&signing_key);
    assert!(verifying_key.verify(&challenge, &signature).is_ok());

    // Convert the signature to bytes
    Ok(signature)
}

/// Bot used signing requests for crypdefi wallets.
///
/// # Note: Most of the implemented functions in the bot use the tokio runtime inside it.
#[derive(Debug, uniffi::Object)]
pub struct Bot {
    pub wallets: Arc<RwLock<Vec<Wallet>>>,
    private_cert: SigningKey,
    access_token: RwLock<Option<String>>,
    refresh_token: Arc<RwLock<Option<String>>>,
}

#[uniffi::export]
impl Bot {
    #[uniffi::constructor]
    /// constructs a new `Bot`
    /// You need to have a valid pem encoded private key.
    ///
    /// # Example
    /// ```
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    ///let bot = Bot::new(priv_key).unwrap();
    /// ```
    pub fn new(pem_key: String) -> Result<Arc<Self>, BotSdkError> {
        let signing_key = match SigningKey::from_pkcs8_pem(pem_key.as_str()) {
            Ok(val) => val,
            Err(err) => return Err(BotSdkError::Pkcs8Error(err.to_string())),
        };

        Ok(Arc::new(Self {
            private_cert: signing_key,
            access_token: RwLock::new(None),
            refresh_token: Arc::new(RwLock::new(None)),
            wallets: Arc::new(RwLock::new(Vec::new())),
        }))
    }

    /// logs in to the crypdefi user
    ///
    /// # Example
    /// ```
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let bot = Bot::new(priv_key).unwrap();
    ///
    /// bot.login(String::from("us-0000000000-fbf17c83704f04af11c6")).unwrap();
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub fn login(&self, user_id: String) -> Result<(), BotSdkError> {
        let user_iter: Vec<&str> = user_id.split("-").collect();

        if user_iter.len() < 3 {
            return Err(BotSdkError::InvalidUserId);
        }

        if user_iter[0] != "us" {
            return Err(BotSdkError::IdNotUserId);
        }

        let login_req = LoginRequest {
            organization: user_iter[1].to_string(),
            user_id: user_id.clone(),
            auth_method: "cra".to_string(),
        };

        let rt = match Runtime::new() {
            Ok(runtime) => runtime,
            Err(err) => return Err(BotSdkError::TokioError(err.to_string())),
        };

        return rt.block_on(async move || -> Result<(), BotSdkError> {
            let response = login(login_req).await?;

            let challenge_bytes = match hex::decode(response.challenge.clone()) {
                Ok(bytes) => bytes,
                Err(err) => return Err(BotSdkError::HexError(err.to_string())),
            };

            let signed_challenge =
                sign_challenge_with_ecdsa(self.private_cert.clone(), challenge_bytes)?;

            let signed_bytes = match signed_challenge.to_der() {
                Ok(bytes) => bytes,
                Err(err) => return Err(BotSdkError::DEREncodeFail(err.to_string())),
            };

            let hex_signed_challenge = hex::encode(signed_bytes);

            let login_req = CraRequest {
                user_id,
                challenge: response.challenge,
                response: hex_signed_challenge,
                hash_algorithm: "sha256".to_string(),
            };

            let cra_response = cra_login(login_req).await?;

            let mut access_lock = self.access_token.write().await;
            *access_lock = Some(cra_response.token);

            let mut refresh_lock = self.refresh_token.write().await;
            *refresh_lock = Some(cra_response.refresh_token);

            return Ok(());
        }());
    }

    /// Tries to refresh the access_token for the bot.
    ///
    /// # Example
    /// ```
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let bot = Bot::new(priv_key).unwrap();
    /// bot.refresh().unwrap
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub fn refresh(&self) -> Result<(), BotSdkError> {
        let rt = match Runtime::new() {
            Ok(runtime) => runtime,
            Err(err) => return Err(BotSdkError::TokioError(err.to_string())),
        };

        return rt.block_on(async move || -> Result<(), BotSdkError> {
            let access_lock = self.access_token.read().await;
            let refresh_lock = self.refresh_token.read().await;
            let response = refresh_auth(&refresh_lock, &access_lock).await?;

            drop(access_lock);
            drop(refresh_lock);

            let mut access_lock = self.access_token.write().await;
            *access_lock = Some(response.token);

            let mut refresh_lock = self.refresh_token.write().await;
            *refresh_lock = Some(response.refresh_token);

            return Ok(());
        }());
    }

    /// gets the wallets currently stored in the bot
    ///
    /// # Example
    /// ```
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let bot = Bot::new(priv_key).unwrap();
    /// let wallets = bot.get_wallets().unwrap();
    /// println!("wallets: {:?}", wallets);
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub fn get_wallets(&self) -> Result<Vec<Wallet>, BotSdkError> {
        let rt = match Runtime::new() {
            Ok(runtime) => runtime,
            Err(err) => return Err(BotSdkError::TokioError(err.to_string())),
        };

        return rt.block_on(async move || -> Result<Vec<Wallet>, BotSdkError> {
            let access_lock = self.access_token.read().await;
            let wallets = get_wallets(&*access_lock).await?;

            let mut wallets_lock = self.wallets.write().await;
            *wallets_lock = wallets.clone();

            return Ok(wallets);
        }());
    }

    /// send the transaction hex to crypdefi for signging
    ///
    /// # Example
    /// ```
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let bot = Bot::new(priv_key).unwrap();
    ///
    /// let wallet_id = "wa-0000000000-4f45f9d208e9207736fb".to_string();
    /// let transaction_hex = "02f8af01018390f560850461933067828cb394a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844095ea7b300000000000000000000000097802f38a37e1d789eba194513e3eb7e918d34df000000000000000000000000000000000000000000000000000000001dcd6500c001a0ad0b4a87309ef94b96d38f145d676d971ca1f1e4702c9cace99fdec8df4a8814a008651a171f31629bcf3a686ca26b9d3cece44c6dfec39fb2c1848e3b290ba121".to_string();
    ///
    /// let wallets = bot.sign_transaction(wallet_id,crypdefi_bot_sdk::crypdefi::http::SignatureRequestKind::Transaction, transaction_hex).unwrap();
    /// println!("wallets: {:?}", wallets);
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub fn sign_transaction(
        &self,
        wallet_id: String,
        tx_type: SignatureRequestKind,
        hex_value: String,
    ) -> Result<SigResponse, BotSdkError> {
        let rt = match Runtime::new() {
            Ok(runtime) => runtime,
            Err(err) => return Err(BotSdkError::TokioError(err.to_string())),
        };

        return rt.block_on(async move || -> Result<SigResponse, BotSdkError> {
            let access_lock = self.access_token.read().await;
            let signature = sign(&*access_lock, wallet_id, tx_type, hex_value).await?;

            return Ok(signature);
        }());
    }

    /// logs out the user
    ///
    /// # Example
    /// ```
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let bot = Bot::new(priv_key).unwrap();
    ///
    /// let wallet_id = "wa-0000000000-4f45f9d208e9207736fb".to_string();
    /// let transaction_hex = "02f8af01018390f560850461933067828cb394a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844095ea7b300000000000000000000000097802f38a37e1d789eba194513e3eb7e918d34df000000000000000000000000000000000000000000000000000000001dcd6500c001a0ad0b4a87309ef94b96d38f145d676d971ca1f1e4702c9cace99fdec8df4a8814a008651a171f31629bcf3a686ca26b9d3cece44c6dfec39fb2c1848e3b290ba121".to_string();
    ///
    /// let wallets = bot.sign_transaction(wallet_id,crypdefi_bot_sdk::crypdefi::http::SignatureRequestKind::Transaction, transaction_hex).unwrap();
    /// println!("wallets: {:?}", wallets);
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub fn logout(&self) -> Result<(), BotSdkError> {
        let rt = match Runtime::new() {
            Ok(runtime) => runtime,
            Err(err) => return Err(BotSdkError::TokioError(err.to_string())),
        };

        return rt.block_on(async move || -> Result<(), BotSdkError> {
            let access_lock = self.access_token.read().await;
            let res = logout(&*access_lock).await?;
            drop(access_lock);
            let mut access_lock = self.access_token.write().await;
            *access_lock = None;

            let mut refresh_lock = self.refresh_token.write().await;
            *refresh_lock = None;

            return Ok(res);
        }());
    }
}
