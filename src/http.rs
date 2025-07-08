use crate::error::BotSdkError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

pub const DEFAULT_URL: &str = "https://api.release.crypdefi.eu";
pub fn get_url_base(endpoint: String) -> String {
    let key = "CRYPDEFI_BASE_URL";
    let base_url = match env::var(key) {
        Ok(val) => val,
        Err(_) => DEFAULT_URL.to_string(),
    };

    let joinded_url: String = format!("{}{}", base_url, endpoint);

    return joinded_url;
}

#[derive(Serialize)]
pub struct LoginRequest {
    pub organization: String,
    pub user_id: String,
    pub auth_method: String,
}
#[derive(Deserialize, Serialize, Debug)]
pub struct LoginResponse {
    pub challenge: String,
    pub deadline: usize,
}

/// makes login call to the crypdefi servers
pub async fn login(req: LoginRequest) -> Result<LoginResponse, BotSdkError> {
    let url = get_url_base("/auth/login".to_string());
    let client = Client::new();
    let response = client.post(url).json(&req).send().await?;

    if response.status().is_success() {
        let text = response.text().await?;
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let res = serde_json::from_value::<LoginResponse>(v)?;
        return Ok(res);
    }

    let status = response.status();
    let res = response.text().await?;

    return Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not make login request".to_string(),
        status,
        res
    )));
}

#[derive(Serialize)]
pub struct CraRequest {
    pub user_id: String,
    pub challenge: String,
    pub response: String,
    pub hash_algorithm: String,
}

#[derive(Deserialize, Debug)]
pub struct CraResponse {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: u64,
    pub seconds: u64,
}

/// makes the cra login auth call to servers
pub async fn cra_login(req: CraRequest) -> Result<CraResponse, BotSdkError> {
    let url = get_url_base("/auth/cra".to_string());
    let client = Client::new();
    let response = client.post(url).json(&req).send().await?;

    if response.status().is_success() {
        let text = response.text().await?;
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let res = serde_json::from_value::<CraResponse>(v)?;
        return Ok(res);
    }

    let status = response.status();
    let res = response.text().await?;

    return Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not make CRA login".to_string(),
        status,
        res
    )));
}

#[derive(Deserialize, Debug, Clone, Serialize)]
enum WalletState {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "inactive")]
    Inactive,
}

#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct ChainSimple {
    /** The ID of the chain */
    chain_id: String,
    /** The common name of the chain */
    name: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct Wallet {
    /** The id of the wallet */
    wallet_id: String,
    /** The friendly name of the wallet */
    name: String,
    /** The date when this wallet was created */
    created_at: String,
    /** The status of the wallet */
    state: WalletState,
    address: String,
    chain: ChainSimple,
}

/// makes call to get wallets from backend for user.
pub async fn get_wallets(access_token_arc: &Option<String>) -> Result<Vec<Wallet>, BotSdkError> {
    let access_token = match access_token_arc {
        Some(acc) => acc,
        None => return Err(BotSdkError::NoAccessToken),
    };

    let url = get_url_base("/wallets?accessOnly=true".to_string());

    let client = Client::new();

    let response = client
        .get(url)
        .bearer_auth(access_token.clone())
        .send()
        .await?;

    if response.status().is_success() {
        let text = response.text().await?;
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let res = serde_json::from_value::<Vec<Wallet>>(v)?;
        return Ok(res);
    }

    let status = response.status();
    let res = response.text().await?;

    return Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not get wallets".to_string(),
        status,
        res
    )));
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignRequest {
    pub kind: SignatureRequestKind,
    pub data: String,
    // /** The hashed bytes that were or should be signed */
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_bytes: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct Signature {
    r: String,
    s: String,
    recovery_id: Option<u64>,
}

impl Signature {
    pub fn to_der(&self) -> Result<Vec<u8>, BotSdkError> {
        // Convert hex strings to byte vectors
        let r_bytes = hex::decode(&self.r)?;

        let s_bytes = hex::decode(&self.s)?;

        // Ensure r and s are properly padded or trimmed for DER encoding
        let r_der = self.encode_integer(&r_bytes);
        let s_der = self.encode_integer(&s_bytes);

        // Construct the sequence: 0x30 (sequence tag) + length + r_der + s_der
        let mut der = Vec::new();
        der.push(0x30); // Sequence tag

        let total_length = r_der.len() + s_der.len();
        der.push(total_length as u8); // Length of the sequence

        der.extend_from_slice(&r_der);
        der.extend_from_slice(&s_der);

        Ok(der)
    }

    fn encode_integer(&self, bytes: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(0x02); // Integer tag

        // Remove leading zeros, but ensure at least one byte remains
        let mut trimmed = bytes;
        while trimmed.len() > 1 && trimmed[0] == 0 {
            trimmed = &trimmed[1..];
        }

        // If the first bit is 1, prepend a 0x00 to avoid interpreting as negative
        if trimmed[0] & 0x80 != 0 {
            result.push((trimmed.len() + 1) as u8); // Length includes the extra 0x00
            result.push(0x00);
        } else {
            result.push(trimmed.len() as u8); // Length of the integer
        }

        result.extend_from_slice(trimmed);
        result
    }
}

#[derive(Deserialize, Debug, Clone, Serialize)]
pub enum KeyAlgorithm {
    #[serde(rename = "ECDSA_SECP256k1")]
    EcdsaSecp256k1,
    #[serde(rename = "EDDSA_ED25519")]
    EddsaEd25519,
}

#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct PublicKey {
    algorithm: KeyAlgorithm,
    public_key: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct SigResponse {
    payload: SignRequest,
    key: PublicKey,
    signature: Signature,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
pub enum SignatureRequestKind {
    #[serde(rename = "raw")]
    Raw,
    #[serde(rename = "transaction")]
    Transaction,
    #[serde(rename = "message")]
    Message,
    #[serde(rename = "rdx_authentication_request")]
    RdxAuthenticationRequest,
    #[serde(rename = "evm_eip712")]
    EvmEip712,
}

/// Request signature from keyvault passing hex transactions
pub async fn sign(
    access_token_arc: &Option<String>,
    wallet_id: String,
    tx_type: SignatureRequestKind,
    hex: String,
) -> Result<SigResponse, BotSdkError> {
    let access_token = match access_token_arc {
        Some(acc) => acc,
        None => return Err(BotSdkError::NoAccessToken),
    };

    let url = get_url_base(format!("/wallets/{}/sign", wallet_id));

    let client = Client::new();

    let req = SignRequest {
        kind: tx_type,
        data: hex,
        raw_bytes: None,
    };

    let response = client
        .post(url)
        .json(&req)
        .bearer_auth(access_token.clone())
        .send()
        .await?;

    if response.status().is_success() {
        let text = response.text().await?;
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let res = serde_json::from_value::<SigResponse>(v)?;
        return Ok(res);
    }

    let status = response.status();
    let res = response.text().await?;

    return Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not get signature".to_string(),
        status,
        res
    )));
}

/// Request signature from keyvault passing hex transactions
pub async fn logout(access_token_arc: &Option<String>) -> Result<(), BotSdkError> {
    let access_token = match access_token_arc {
        Some(acc) => acc,
        None => return Err(BotSdkError::NoAccessToken),
    };

    let url = get_url_base("/auth/logout".to_string());

    let client = Client::new();

    let response = client
        .post(url)
        .bearer_auth(access_token.clone())
        .send()
        .await?;

    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let res = response.text().await?;

    return Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not logout".to_string(),
        status,
        res
    )));
}

#[derive(Serialize, Debug)]
struct RefreshRequest {
    refresh_token: String,
}

/// Make call to try to refresh the access token
pub async fn refresh_auth(
    refresh_token_opt: &Option<String>,
    access_token_opt: &Option<String>,
) -> Result<CraResponse, BotSdkError> {
    let access_token = match access_token_opt {
        Some(acc) => acc,
        None => return Err(BotSdkError::NoAccessToken),
    };
    let refresh_token = match refresh_token_opt {
        Some(acc) => acc,
        None => return Err(BotSdkError::NoRefreshToken),
    };

    let url = get_url_base("/auth/refresh".to_string());

    let client = Client::new();

    let req_body: RefreshRequest = RefreshRequest {
        refresh_token: refresh_token.clone(),
    };

    let response = client
        .post(url)
        .json(&req_body)
        .bearer_auth(access_token.clone())
        .send()
        .await?;
    if response.status().is_success() {
        let text = response.text().await?;
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let res = serde_json::from_value::<CraResponse>(v)?;
        return Ok(res);
    }

    let status = response.status();
    let res = response.text().await?;

    return Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not refresh auth".to_string(),
        status,
        res
    )));
}
