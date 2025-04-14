use super::http::{SigResponse, SignatureRequestKind, get_wallets, logout, refresh_auth, sign};
use super::{
    error::BotSdkError,
    http::{CraRequest, LoginRequest, Wallet, cra_login, login},
};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use p256::ecdsa::{VerifyingKey, signature::Verifier};
use pkcs8::{DecodePrivateKey, der::Encode};
use std::env;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

#[derive(uniffi::Enum)]
pub enum Network {
    Sandbox,
    Dev,
}

fn sign_challenge_with_ecdsa(
    signing_key: SigningKey,
    challenge: Vec<u8>,
) -> Result<DerSignature, BotSdkError> {
    // Sign the challenge
    let signature: DerSignature = signing_key.sign(&challenge);
    let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`
    assert!(verifying_key.verify(&challenge, &signature).is_ok());

    // Convert the signature to bytes
    Ok(signature)
}

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
    pub fn new(pem_key: String) -> Result<Arc<Self>, BotSdkError> {
        let signing_key = match SigningKey::from_pkcs8_pem(pem_key.as_str()) {
            Ok(val) => val,
            Err(err) => return Err(BotSdkError::Pkcs8Error(err.to_string())),
        };

        let key = "CRYPDEFI_API_BASE_URL";
        let _ = match env::var(key) {
            Ok(val) => val,
            Err(_) => {
                return Err(BotSdkError::EnvVar(
                    "CRYPDEFI_API_BASE_URL enviroment variable is not set.".to_string(),
                ));
            }
        };

        Ok(Arc::new(Self {
            private_cert: signing_key,
            access_token: RwLock::new(None),
            refresh_token: Arc::new(RwLock::new(None)),
            wallets: Arc::new(RwLock::new(Vec::new())),
        }))
    }

    /** logs in to the crypdefi user
     */
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

        let rt = Runtime::new().unwrap();
        return rt.block_on(async move || -> Result<(), BotSdkError> {
            let response = login(login_req).await?;

            let challenge_bytes = hex::decode(response.challenge.clone()).unwrap();
            let signed_challenge =
                sign_challenge_with_ecdsa(self.private_cert.clone(), challenge_bytes)?;

            let hex_signed_challenge = hex::encode(signed_challenge.to_der().unwrap());

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

    /** gets the wallets currently stored in the bot
     */
    pub fn refresh(&self) -> Result<(), BotSdkError> {
        let rt = Runtime::new().unwrap();
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

    /** gets the wallets currently stored in the bot
     */
    pub fn get_wallets(&self) -> Result<Vec<Wallet>, BotSdkError> {
        let rt = Runtime::new().unwrap();
        return rt.block_on(async move || -> Result<Vec<Wallet>, BotSdkError> {
            let access_lock = self.access_token.read().await;
            let wallets = get_wallets(&*access_lock).await?;

            let mut wallets_lock = self.wallets.write().await;
            *wallets_lock = wallets.clone();

            return Ok(wallets);
        }());
    }

    /// send the transaction hex to crypdefi for signging
    pub fn sign_transaction(
        &self,
        wallet_id: String,
        tx_type: SignatureRequestKind,
        hex_value: String,
    ) -> Result<SigResponse, BotSdkError> {
        let rt = Runtime::new().unwrap();
        return rt.block_on(async move || -> Result<SigResponse, BotSdkError> {
            let access_lock = self.access_token.read().await;
            let signature = sign(&*access_lock, wallet_id, tx_type, hex_value).await?;

            return Ok(signature);
        }());
    }

    pub fn logout(&self) -> Result<(), BotSdkError> {
        let rt = Runtime::new().unwrap();
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
