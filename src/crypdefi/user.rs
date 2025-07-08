use super::http::{SigResponse, SignatureRequestKind, get_wallets, logout, refresh_auth, sign};
use super::{
    error::BotSdkError,
    http::{CraRequest, LoginRequest, Wallet, cra_login, login},
};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use p256::ecdsa::{VerifyingKey, signature::Verifier};
use pkcs8::{DecodePrivateKey, der::Encode};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};

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
#[derive(Debug)]
pub struct Bot {
    pub wallets: Arc<RwLock<Vec<Wallet>>>,
    private_cert: SigningKey,
    access_token: Arc<RwLock<Option<String>>>,
    refresh_token: Arc<RwLock<Option<String>>>,
    auto_refresh_enabled: Arc<RwLock<bool>>,

    refresh_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    refresh_cancel_sender: Arc<watch::Sender<bool>>,
    refresh_cancel_receiver: watch::Receiver<bool>,
    /// unix timestamp on when the token expires
    refresh_expiration_time: Arc<RwLock<Option<u64>>>,
}

impl Bot {
    /// Creates a bot instance used to sign requests and interact with CrypDefi wallets.
    ///
    /// # Example
    /// ```rust
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    ///let bot = Bot::new(priv_key).await.unwrap();
    /// ```
    pub fn new(pem_key: String) -> Result<Arc<Self>, BotSdkError> {
        let signing_key = match SigningKey::from_pkcs8_pem(pem_key.as_str()) {
            Ok(val) => val,
            Err(err) => return Err(BotSdkError::Pkcs8Error(err.to_string())),
        };

        let (cancel_tx, cancel_rx) = watch::channel(false);

        Ok(Arc::new(Self {
            private_cert: signing_key,
            access_token: Arc::new(RwLock::new(None)),
            refresh_token: Arc::new(RwLock::new(None)),
            wallets: Arc::new(RwLock::new(Vec::new())),
            auto_refresh_enabled: Arc::new(RwLock::new(true)),

            refresh_handle: Arc::new(RwLock::new(None)),
            refresh_cancel_sender: Arc::new(cancel_tx),
            refresh_cancel_receiver: cancel_rx,
            refresh_expiration_time: Arc::new(RwLock::new(None)),
        }))
    }

    /// Authenticates the bot using the provided user ID. If `auto_refresh` is enabled, the SDK will handle token renewal automatically.
    ///
    /// # Example
    /// ```rust
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let bot = Bot::new(priv_key).unwrap();
    ///
    /// NOTE: By default the bot will auto_refresh login
    /// bot.login(String::from("us-0000000000-fbf17c83704f04af11c6"), None).await.unwrap();
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn login(
        &self,
        user_id: String,
        auto_refresh: Option<bool>,
    ) -> Result<(), BotSdkError> {
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

        // Cancel any existing refresh task
        self.cancel_refresh_task().await;

        let mut auto_refresh_lock = self.auto_refresh_enabled.write().await;
        if let Some(auto) = auto_refresh {
            *auto_refresh_lock = auto;
        }
        drop(auto_refresh_lock);

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

        // Store tokens
        let mut access_lock = self.access_token.write().await;
        *access_lock = Some(cra_response.token);
        drop(access_lock);

        let mut refresh_lock = self.refresh_token.write().await;
        *refresh_lock = Some(cra_response.refresh_token);
        drop(refresh_lock);

        let mut refresh_time_lock = self.refresh_expiration_time.write().await;
        *refresh_time_lock = Some(cra_response.expires_at);
        drop(refresh_time_lock);

        // Start refresh task if auto_refresh is enabled
        let auto_refresh_enabled = self.auto_refresh_enabled.read().await;
        if *auto_refresh_enabled {
            drop(auto_refresh_enabled);
            self.start_refresh_task(cra_response.seconds - 10).await?;
        }

        Ok(())
    }

    /// Manually refreshes the bot’s access token. Only needed if auto-refresh is disabled.
    ///
    /// # Example
    /// ```rust
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let bot = Bot::new(priv_key).await.unwrap();
    /// bot.refresh().unwrap
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn refresh(&self) -> Result<(), BotSdkError> {
        let access_lock = self.access_token.read().await;
        let refresh_lock = self.refresh_token.read().await;
        let response = refresh_auth(&refresh_lock, &access_lock).await?;

        drop(access_lock);
        drop(refresh_lock);

        let mut access_lock = self.access_token.write().await;
        *access_lock = Some(response.token);

        let mut refresh_lock = self.refresh_token.write().await;
        *refresh_lock = Some(response.refresh_token);

        let mut refresh_time_lock = self.refresh_expiration_time.write().await;
        *refresh_time_lock = Some(response.expires_at);
        drop(refresh_time_lock);

        // if autorefresh is true we restart the watcher thread.
        let auto_refresh_enabled = self.auto_refresh_enabled.read().await;
        if *auto_refresh_enabled {
            drop(auto_refresh_enabled);

            // Cancel the existing refresh thread and make a new one
            self.refresh_cancel_sender
                .send(true)
                .map_err(|_| BotSdkError::Custom("Failed to send cancel signal".to_string()))?;

            self.start_refresh_task(response.seconds - 10).await?;
        }

        return Ok(());
    }

    /// Fetches all wallets associated with the authenticated bot user.
    ///
    /// # Example
    /// ```rust
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let bot = Bot::new(priv_key).unwrap();
    /// let wallets = bot.get_wallets().await.unwrap();
    /// println!("wallets: {:?}", wallets);
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn get_wallets(&self) -> Result<Vec<Wallet>, BotSdkError> {
        let access_lock = self.access_token.read().await;
        let wallets = get_wallets(&*access_lock).await?;

        let mut wallets_lock = self.wallets.write().await;
        *wallets_lock = wallets.clone();

        return Ok(wallets);
    }

    /// Signs a transaction (hex-encoded) using the specified wallet and signature request kind. The bot must have access to the wallet in the CrypDefi management UI.
    ///
    /// # Example
    /// ```rust
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
    /// let signature = bot.sign_transaction(wallet_id,crypdefi_bot_sdk::crypdefi::http::SignatureRequestKind::Transaction, transaction_hex).await.unwrap();
    /// println!("Signature: {:?}", signature);
    /// ```
    pub async fn sign_transaction(
        &self,
        wallet_id: String,
        tx_type: SignatureRequestKind,
        hex_value: String,
    ) -> Result<SigResponse, BotSdkError> {
        let access_lock = self.access_token.read().await;
        let signature = sign(&*access_lock, wallet_id, tx_type, hex_value).await?;

        return Ok(signature);
    }

    /// Logs out the bot and invalidates its current session token.
    ///
    /// # Example
    /// ```rust
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let bot = Bot::new(priv_key).unwrap();
    ///
    /// bot.logout().await.unwrap();
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn logout(&self) -> Result<(), BotSdkError> {
        self.cancel_refresh_task().await;
        let access_lock = self.access_token.read().await;
        let res = logout(&*access_lock).await?;
        drop(access_lock);
        let mut access_lock = self.access_token.write().await;
        *access_lock = None;

        let mut refresh_lock = self.refresh_token.write().await;
        *refresh_lock = None;
        let mut expiration = self.refresh_expiration_time.write().await;
        *expiration = None;

        return Ok(res);
    }

    /// This watches for refresh
    async fn start_refresh_task(&self, seconds: u64) -> Result<(), BotSdkError> {
        self.refresh_cancel_sender
            .send(false)
            .map_err(|_| BotSdkError::Custom("Failed to reset cancel signal".to_string()))?;

        let auto_refresh_enabled = Arc::clone(&self.auto_refresh_enabled);
        let access_token = Arc::clone(&self.access_token);
        let refresh_token = Arc::clone(&self.refresh_token);
        let refresh_expiration_time = Arc::clone(&self.refresh_expiration_time);
        let mut cancel_receiver = self.refresh_cancel_receiver.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(seconds)) => {
                        let enabled = auto_refresh_enabled.read().await;
                        if !*enabled {
                            break;
                        }
                        drop(enabled);

                        let access_lock = access_token.read().await;
                        let refresh_lock = refresh_token.read().await;
                        let expiration_time_lock = refresh_expiration_time.read().await;

                        match refresh_auth(&refresh_lock, &access_lock).await {
                            Ok(response) => {
                                drop(access_lock);
                                drop(refresh_lock);
                                drop(expiration_time_lock);

                                let mut access_lock = access_token.write().await;
                                *access_lock = Some(response.token);

                                let mut refresh_lock = refresh_token.write().await;
                                *refresh_lock = Some(response.refresh_token);

                                let mut refresh_expiration_lock = refresh_expiration_time.write().await;
                                *refresh_expiration_lock = Some(response.expires_at);
                            }
                            Err(e) => {
                                eprintln!("Failed to refresh token: {:?}", e);
                                break;
                            }
                        }
                    }
                    _ = cancel_receiver.changed() => {
                        if *cancel_receiver.borrow() {
                            println!("stoping thread watching for refresh...");
                            break;
                        }
                    }
                }
            }
        });

        let mut handle_lock = self.refresh_handle.write().await;
        *handle_lock = Some(handle);

        Ok(())
    }
    async fn cancel_refresh_task(&self) {
        let _ = self.refresh_cancel_sender.send(true);

        let mut handle_lock = self.refresh_handle.write().await;
        if let Some(handle) = handle_lock.take() {
            let _ = handle.await;
        }
    }

    ///  Returns the Unix timestamp when the current auth token will expire.
    ///
    /// # Example
    /// ```rust
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let bot = Bot::new(priv_key).unwrap();
    ///
    /// bot.auth_expiration_unix_time().await;
    /// ```
    pub async fn auth_expiration_unix_time(&self) -> Result<Option<u64>, BotSdkError> {
        let expiration = self.refresh_expiration_time.read().await;
        return Ok(*expiration);
    }
}
