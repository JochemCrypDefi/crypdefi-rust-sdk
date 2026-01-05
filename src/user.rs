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
use tokio::task::AbortHandle;

fn sign_challenge_with_ecdsa(
    signing_key: SigningKey,
    challenge: Vec<u8>,
) -> Result<DerSignature, BotSdkError> {
    // Sign the challenge
    let signature: DerSignature = signing_key.sign(&challenge);
    let verifying_key = VerifyingKey::from(&signing_key);

    verifying_key.verify(&challenge, &signature)?;

    // Convert the signature to bytes
    Ok(signature)
}

#[derive(Debug, Clone)]
pub struct UserId {
    full_id: String,
    organization: String,
}

impl UserId {
    pub fn new(id: String) -> Result<Self, BotSdkError> {
        let mut user_iter = id.split("-");

        if user_iter.next() != Some("us") {
            return Err(BotSdkError::IdNotUserId);
        }

        let Some(organization) = user_iter.next() else {
            return Err(BotSdkError::InvalidUserId);
        };

        if user_iter.next().is_none() {
            return Err(BotSdkError::InvalidUserId);
        }

        Ok(Self {
            organization: organization.to_string(),
            full_id: id,
        })
    }

    pub fn organization(&self) -> &str {
        &self.organization
    }

    pub fn full_id(&self) -> &str {
        &self.full_id
    }
}

async fn auto_refresh_task(
    client: reqwest::Client,
    base_url: String,
    shared_values_rw: Arc<RwLock<SharedValues>>,
    seconds: u64,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(seconds)).await;

        let shared_values_lock = shared_values_rw.read().await;

        match refresh_auth(
            &client,
            &shared_values_lock.refresh_token,
            &shared_values_lock.access_token,
            &base_url,
        )
        .await
        {
            Ok(response) => {
                drop(shared_values_lock);
                let mut shared_values_write_lock = shared_values_rw.write().await;
                shared_values_write_lock.access_token = Some(response.token);
                shared_values_write_lock.refresh_token = Some(response.refresh_token);
                shared_values_write_lock.refresh_expiration_time = Some(response.expires_at);
            }
            Err(e) => {
                log::error!("Failed to refresh token: {e:?}");
            }
        }
    }
}

#[derive(Debug)]
struct SharedValues {
    access_token: Option<String>,
    refresh_token: Option<String>,
    refresh_expiration_time: Option<u64>,
}

/// Bot used signing requests for crypdefi wallets.
///
/// # Note: Most of the implemented functions in the bot use the tokio runtime inside it.
#[derive(Debug)]
pub struct Bot {
    private_cert: SigningKey,
    user_id: UserId,
    refresh_handle: Option<AbortHandle>,

    shared_value: Arc<RwLock<SharedValues>>,
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
    ///
    ///let user_id = UserId::new(String::from("us-0000000000-1d09b044f88074ab7cfd"))?;
    ///let bot = Bot::new(priv_key, user_id, None).await.unwrap();
    ///
    /// NOTE: unless changed endpoint will default to: https://api.release.crypdefi.eu.  
    /// ```
    pub fn new(
        pem_key: String,
        user_id: UserId,
        base_url: Option<String>,
    ) -> Result<Self, BotSdkError> {
        let signing_key = SigningKey::from_pkcs8_pem(pem_key.as_str())?;

        let final_base_url = base_url.unwrap_or_else(|| String::from(http::DEFAULT_URL));

        let rest_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .http2_keep_alive_interval(Duration::from_secs(5))
            .http2_keep_alive_timeout(Duration::from_secs(2))
            .http2_keep_alive_while_idle(true)
            .build()?;

        Ok(Self {
            private_cert: signing_key,
            shared_value: Arc::new(RwLock::new(SharedValues {
                access_token: None,
                refresh_token: None,
                refresh_expiration_time: None,
            })),
            user_id,
            refresh_handle: None,
            base_url: final_base_url,
            rest_client,
        })
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
    /// let user_id = UserId::new(String::from("us-0000000000-1d09b044f88074ab7cfd"))?;
    /// let bot = Bot::new(priv_key, user_id, None).await.unwrap();
    ///
    /// // if auto refresh is set to true a thread will be spun up to do this action.
    /// bot.login(false).await.unwrap();
    ///
    ///
    /// # Note: uses tokio async runtime
    pub async fn login(&mut self, auto_refresh: bool) -> Result<(), BotSdkError> {
        let login_req = LoginRequest {
            organization: self.user_id.organization().to_string(),
            user_id: self.user_id.full_id().to_string(),
            auth_method: "cra".to_string(),
        };

        let response = login(&self.rest_client, login_req, &self.base_url).await?;

        let challenge_bytes = const_hex::decode(response.challenge.clone())?;

        let signed_challenge =
            sign_challenge_with_ecdsa(self.private_cert.clone(), challenge_bytes)?;

        let signed_bytes = signed_challenge.to_der()?;

        let hex_signed_challenge = const_hex::encode(signed_bytes);
        let login_req = CraRequest {
            user_id: self.user_id.full_id().to_string(),
            challenge: response.challenge,
            response: hex_signed_challenge,
            hash_algorithm: http::HashAlgo::Sha256,
        };

        let cra_response = cra_login(&self.rest_client, login_req, &self.base_url).await?;

        let mut shared_value_lock = self.shared_value.write().await;
        shared_value_lock.access_token = Some(cra_response.token);
        shared_value_lock.refresh_token = Some(cra_response.refresh_token);
        shared_value_lock.refresh_expiration_time = Some(cra_response.expires_at);
        drop(shared_value_lock);

        self.start_refresh_task(auto_refresh, cra_response.seconds - 10);

        Ok(())
    }

    /// Manually refreshes the bot's access token. Only needed if auto-refresh is disabled.
    ///
    /// # Example
    /// ```rust
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let user_id = UserId::new(String::from("us-0000000000-1d09b044f88074ab7cfd"))?;
    /// let bot = Bot::new(priv_key, user_id, None).await.unwrap();
    ///
    /// // if auto refresh is set to true a thread will be spun up to do this action.
    ///
    /// bot.refresh(true).await.unwrap()
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn refresh(&mut self, auto_refresh: bool) -> Result<(), BotSdkError> {
        self.cancel_refresh_task();
        let shared_lock = self.shared_value.read().await;
        let response = refresh_auth(
            &self.rest_client,
            &shared_lock.refresh_token,
            &shared_lock.access_token,
            &self.base_url,
        )
        .await?;

        drop(shared_lock);

        let mut shared_value_lock = self.shared_value.write().await;
        shared_value_lock.access_token = Some(response.token);
        shared_value_lock.refresh_token = Some(response.refresh_token);
        shared_value_lock.refresh_expiration_time = Some(response.expires_at);
        drop(shared_value_lock);

        self.start_refresh_task(auto_refresh, response.seconds - 10);

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
    /// let user_id = UserId::new(String::from("us-0000000000-1d09b044f88074ab7cfd"))?;
    /// let bot = Bot::new(priv_key, user_id, None).await.unwrap();
    ///
    /// let wallets = bot.get_wallets().await.unwrap();
    /// println!("wallets: {:?}", wallets);
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn get_wallets(&self) -> Result<Vec<Wallet>, BotSdkError> {
        let shared_access_lock = self.shared_value.read().await;
        let wallets = get_wallets(
            &self.rest_client,
            &shared_access_lock.access_token,
            &self.base_url,
        )
        .await?;

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
    /// let user_id = UserId::new(String::from("us-0000000000-1d09b044f88074ab7cfd"))?;
    /// let bot = Bot::new(priv_key, user_id, None).await.unwrap();
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
        let shared_access_lock = self.shared_value.read().await;

        sign(
            &self.rest_client,
            &shared_access_lock.access_token,
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
    /// let user_id = UserId::new(String::from("us-0000000000-1d09b044f88074ab7cfd"))?;
    /// let bot = Bot::new(priv_key, user_id, None).await.unwrap();
    ///
    /// bot.logout().await.unwrap();
    /// ```
    ///
    /// # Note: uses tokio async runtime
    pub async fn logout(&mut self) -> Result<(), BotSdkError> {
        self.cancel_refresh_task();
        let shared_access_lock = self.shared_value.read().await;
        logout(
            &self.rest_client,
            &shared_access_lock.access_token,
            &self.base_url,
        )
        .await?;
        drop(shared_access_lock);

        let mut shared_value_lock = self.shared_value.write().await;
        shared_value_lock.access_token = None;
        shared_value_lock.refresh_token = None;
        shared_value_lock.refresh_expiration_time = None;
        drop(shared_value_lock);

        Ok(())
    }

    fn cancel_refresh_task(&mut self) {
        if let Some(handle) = self.refresh_handle.take() {
            handle.abort();
        }
    }

    fn start_refresh_task(&mut self, auto_refresh: bool, refresh_in_seconds: u64) {
        self.cancel_refresh_task();
        self.refresh_handle = auto_refresh.then(|| {
            tokio::spawn(auto_refresh_task(
                self.rest_client.clone(),
                self.base_url.clone(),
                self.shared_value.clone(),
                refresh_in_seconds,
            ))
            .abort_handle()
        });
    }
}

impl Drop for Bot {
    fn drop(&mut self) {
        if let Some(handle) = self.refresh_handle.take() {
            handle.abort();
        }
    }
}

impl Bot {
    /// Returns the Unix timestamp when the current auth token will expire.
    ///
    /// # Example
    /// ```rust
    /// let priv_key =   "-----BEGIN PRIVATE KEY-----
    /// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
    /// V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
    /// +zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
    /// -----END PRIVATE KEY-----",
    ///
    /// let user_id = UserId::new(String::from("us-0000000000-1d09b044f88074ab7cfd"))?;
    /// let bot = Bot::new(priv_key, user_id, None).await.unwrap();
    ///
    /// bot.auth_expiration_unix_time().await;
    /// ```
    pub async fn auth_expiration_unix_time(&self) -> Option<u64> {
        let shared_value_lock = self.shared_value.read().await;
        shared_value_lock.refresh_expiration_time
    }
}
