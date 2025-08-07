use crate::http::{
    self, SigResponse, SignatureRequestKind, get_wallets, logout, refresh_auth, sign,
};
use crate::{
    error::BotSdkError,
    http::{CraRequest, LoginRequest, Wallet, cra_login, login},
};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use p256::ecdsa::{VerifyingKey, signature::Verifier};
use pkcs8::{DecodePrivateKey, der::Encode};
use std::sync::Arc;
use std::time::Duration;
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

async fn auto_refresh_task(
    client: reqwest::Client,
    base_url: String,
    access_token_rw: Arc<RwLock<Option<String>>>,
    refresh_token_rw: Arc<RwLock<Option<String>>>,
    refresh_expiration_time: Arc<RwLock<Option<u64>>>,
    seconds: u64,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(seconds)).await;
        let access_lock = access_token_rw.read().await;

        let refresh_lock = refresh_token_rw.read().await;

        match refresh_auth(
            &client,
            refresh_lock.clone(),
            access_lock.clone(),
            &base_url,
        )
        .await
        {
            Ok(response) => {
                drop(access_lock);
                drop(refresh_lock);

                let mut access_lock = access_token_rw.write().await;
                *access_lock = Some(response.token);

                let mut refresh_lock = refresh_token_rw.write().await;
                *refresh_lock = Some(response.refresh_token);

                let mut refresh_expiration_lock = refresh_expiration_time.write().await;
                *refresh_expiration_lock = Some(response.expires_at);
            }
            Err(e) => {
                log::error!("Failed to refresh token: {e:?}");
            }
        }
    }
}

/// Bot used signing requests for crypdefi wallets.
///
/// # Note: Most of the implemented functions in the bot use the tokio runtime inside it.
#[derive(Debug)]
pub struct Bot {
    private_cert: SigningKey,
    access_token: Arc<RwLock<Option<String>>>,
    refresh_token: Arc<RwLock<Option<String>>>,
    user_id: String,

    // auto_refresh_enabled: AtomicBool,
    refresh_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// unix timestamp on when the token expires
    refresh_expiration_time: Arc<RwLock<Option<u64>>>,
    base_url: String,
    rest_client: reqwest::Client,
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
    ///let bot = Bot::new(priv_key, None).await.unwrap();
    ///
    /// NOTE: unless changed endpoint will default to: https://api.release.crypdefi.eu.  
    /// ```
    pub async fn new(
        pem_key: String,
        user_id: String,
        base_url: Option<String>,
    ) -> Result<Self, BotSdkError> {
        let signing_key = SigningKey::from_pkcs8_pem(pem_key.as_str())?;

        let mut final_base_url = String::from(http::DEFAULT_URL);

        if let Some(url) = base_url {
            final_base_url = url;
        }

        let rest_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .http2_keep_alive_interval(Duration::from_secs(5))
            .http2_keep_alive_timeout(Duration::from_secs(2))
            .http2_keep_alive_while_idle(true)
            .build()?;

        return Ok(Self {
            private_cert: signing_key,
            access_token: Arc::new(RwLock::new(None)),
            refresh_token: Arc::new(RwLock::new(None)),
            user_id: user_id,

            // auto_refresh_enabled: AtomicBool::new(false),
            refresh_handle: Arc::new(RwLock::new(None)),
            refresh_expiration_time: Arc::new(RwLock::new(None)),
            base_url: final_base_url,
            rest_client,
        });
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
    /// let bot = Bot::new(priv_key, None).unwrap();
    ///
    /// NOTE: By default the bot will auto_refresh login
    /// bot.login(String::from("us-0000000000-fbf17c83704f04af11c6"), None).await.unwrap();
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn login(&self, auto_refresh: bool) -> Result<(), BotSdkError> {
        let mut user_iter = self.user_id.split("-");

        if user_iter.next() != Some("us") {
            return Err(BotSdkError::IdNotUserId);
        }

        let Some(organization) = user_iter.next() else {
            return Err(BotSdkError::InvalidUserId);
        };

        if user_iter.next().is_none() {
            return Err(BotSdkError::InvalidUserId);
        }

        let login_req = LoginRequest {
            organization: organization.to_string(),
            user_id: self.user_id.clone(),
            auth_method: "cra".to_string(),
        };

        // Cancel any existing refresh task
        self.cancel_refresh_task().await;

        let response = login(&self.rest_client, login_req, &self.base_url).await?;

        let challenge_bytes = hex::decode(response.challenge.clone())?;

        let signed_challenge =
            sign_challenge_with_ecdsa(self.private_cert.clone(), challenge_bytes)?;

        let signed_bytes = signed_challenge.to_der()?;

        let hex_signed_challenge = hex::encode(signed_bytes);
        let login_req = CraRequest {
            user_id: self.user_id.clone(),
            challenge: response.challenge,
            response: hex_signed_challenge,
            hash_algorithm: http::HashAlgo::Sha256,
        };

        let cra_response = cra_login(&self.rest_client, login_req, &self.base_url).await?;

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

        self.cancel_refresh_task().await;
        let refresh_handle = if auto_refresh {
            let rest_client_clone = self.rest_client.clone();
            let access_token_clone = self.access_token.clone();
            let refresh_url_clone = self.refresh_token.clone();
            let refresh_expiration_time_clone = self.refresh_expiration_time.clone();
            let base_url_clone = self.base_url.clone();

            // Start the refresh task
            let handle = tokio::spawn(auto_refresh_task(
                rest_client_clone,
                base_url_clone,
                access_token_clone,
                refresh_url_clone,
                refresh_expiration_time_clone,
                cra_response.seconds.clone() - 10,
            ));

            Some(handle)
        } else {
            None
        };

        let mut refresh_handle_lock = self.refresh_handle.write().await;
        *refresh_handle_lock = refresh_handle;
        drop(refresh_handle_lock);

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
    /// let bot = Bot::new(priv_key, None).await.unwrap();
    /// bot.refresh().unwrap
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn refresh(&self, auto_refresh: bool) -> Result<(), BotSdkError> {
        let access_lock = self.access_token.read().await;
        let refresh_lock = self.refresh_token.read().await;
        let response = refresh_auth(
            &self.rest_client,
            refresh_lock.clone(),
            access_lock.clone(),
            &self.base_url,
        )
        .await?;

        drop(access_lock);
        drop(refresh_lock);

        let mut access_lock = self.access_token.write().await;
        *access_lock = Some(response.token);

        let mut refresh_lock = self.refresh_token.write().await;
        *refresh_lock = Some(response.refresh_token);

        let mut refresh_time_lock = self.refresh_expiration_time.write().await;
        *refresh_time_lock = Some(response.expires_at);
        drop(refresh_time_lock);

        self.cancel_refresh_task().await;
        let refresh_handle = if auto_refresh {
            let rest_client_clone = self.rest_client.clone();
            let access_token_clone = self.access_token.clone();
            let refresh_url_clone = self.refresh_token.clone();
            let refresh_expiration_time_clone = self.refresh_expiration_time.clone();
            let base_url_clone = self.base_url.clone();

            // Start the refresh task
            let handle = tokio::spawn(auto_refresh_task(
                rest_client_clone,
                base_url_clone,
                access_token_clone,
                refresh_url_clone,
                refresh_expiration_time_clone,
                response.seconds.clone() - 10,
            ));

            Some(handle)
        } else {
            None
        };

        let mut refresh_handle_lock = self.refresh_handle.write().await;
        *refresh_handle_lock = refresh_handle;
        drop(refresh_handle_lock);

        Ok(())
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
    /// let bot = Bot::new(priv_key, None).unwrap();
    /// let wallets = bot.get_wallets().await.unwrap();
    /// println!("wallets: {:?}", wallets);
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn get_wallets(&self) -> Result<Vec<Wallet>, BotSdkError> {
        let access_lock = self.access_token.read().await;
        let wallets = get_wallets(&self.rest_client, &access_lock, &self.base_url).await?;

        Ok(wallets)
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
    /// let bot = Bot::new(priv_key, None).unwrap();
    ///
    /// let wallet_id = "wa-0000000000-4f45f9d208e9207736fb".to_string();
    /// let transaction_hex = "02f8af01018390f560850461933067828cb394a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844095ea7b300000000000000000000000097802f38a37e1d789eba194513e3eb7e918d34df000000000000000000000000000000000000000000000000000000001dcd6500c001a0ad0b4a87309ef94b96d38f145d676d971ca1f1e4702c9cace99fdec8df4a8814a008651a171f31629bcf3a686ca26b9d3cece44c6dfec39fb2c1848e3b290ba121".to_string();
    ///
    /// let signature = bot.sign_transaction(wallet_id, crate::http::SignatureRequestKind::Transaction, transaction_hex).await.unwrap();
    /// println!("Signature: {:?}", signature);
    /// ```
    pub async fn sign_transaction(
        &self,
        wallet_id: String,
        tx_type: SignatureRequestKind,
        hex_value: String,
    ) -> Result<SigResponse, BotSdkError> {
        let access_lock = self.access_token.read().await;

        sign(
            &self.rest_client,
            &access_lock,
            wallet_id,
            tx_type,
            hex_value,
            &self.base_url,
        )
        .await
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
    /// let bot = Bot::new(priv_key, None).unwrap();
    ///
    /// bot.logout().await.unwrap();
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn logout(&mut self) -> Result<(), BotSdkError> {
        self.cancel_refresh_task().await;
        let access_lock = self.access_token.read().await;
        logout(&self.rest_client, &access_lock, &self.base_url).await?;
        drop(access_lock);

        let mut access_lock = self.access_token.write().await;
        *access_lock = None;

        let mut refresh_lock = self.refresh_token.write().await;
        *refresh_lock = None;
        let mut expiration = self.refresh_expiration_time.write().await;
        *expiration = None;

        Ok(())
    }

    async fn cancel_refresh_task(&self) {
        let mut handle = self.refresh_handle.write().await;

        if let Some(thread_handle) = handle.take() {
            thread_handle.abort();
            let _ = thread_handle.await;
            *handle = None
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
    /// let bot = Bot::new(priv_key, None).unwrap();
    ///
    /// bot.auth_expiration_unix_time().await;
    /// ```
    pub async fn auth_expiration_unix_time(&self) -> Option<u64> {
        let expiration = self.refresh_expiration_time.read().await;
        *expiration
    }
}
