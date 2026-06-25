use crate::error::BotSdkError;
use secp256k1::ecdsa::{self, SerializedSignature};
use serde::{Deserialize, Serialize};

pub const DEFAULT_URL: &str = "https://api.release.crypdefi.eu";
fn set_url(base_url: &str, endpoint: &str) -> String {
    let joinded_url: String = format!("{base_url}{endpoint}");

    joinded_url
}

#[derive(Serialize)]
pub enum AuthMethod {
    #[serde(rename(serialize = "cra"))]
    Cra,
}
#[derive(Serialize)]
pub struct LoginRequest {
    pub user_id: String,
    pub auth_method: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct LoginResponse {
    pub challenge: String,
    pub nonce: String,
    pub timestamp: i64,
    pub deadline: usize,
}

/// makes login call to the crypdefi servers
pub async fn login(
    client: &reqwest::Client,
    req: LoginRequest,
    base_url: &str,
) -> Result<LoginResponse, BotSdkError> {
    let url = set_url(base_url, "/auth/login");
    let response = client.post(url).json(&req).send().await?;

    if response.status().is_success() {
        let res = response.json::<LoginResponse>().await?;
        return Ok(res);
    }

    let status = response.status();
    let res = response.text().await?;

    Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not make login request", status, res
    )))
}

pub async fn warmup_connection(client: &reqwest::Client, url: &str) -> Result<(), BotSdkError> {
    let url = set_url(url, "/health");
    let response = client.get(url).send().await?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let res: String = response.text().await?;

    Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not warmup connection", status, res
    )))
}

#[derive(Serialize)]
pub enum HashAlgo {
    #[serde(rename(serialize = "sha256"))]
    Sha256,
}

#[derive(Serialize)]
pub struct CraRequest {
    pub user_id: String,
    pub challenge: String,
    pub response: String,
    pub hash_algorithm: HashAlgo,
}

#[derive(Deserialize, Debug)]
pub struct CraResponse {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: u64,
    pub seconds: u64,
}

/// makes the cra login auth call to servers
pub async fn cra_login(
    client: &reqwest::Client,
    req: CraRequest,
    base_url: &str,
) -> Result<CraResponse, BotSdkError> {
    let url = set_url(base_url, "/auth/cra");
    let response = client.post(url).json(&req).send().await?;

    if response.status().is_success() {
        let res = response.json::<CraResponse>().await?;
        return Ok(res);
    }

    let status = response.status();
    let res = response.text().await?;

    Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not make CRA login", status, res
    )))
}

#[derive(Deserialize, Debug, Clone, Serialize)]
pub enum WalletState {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "inactive")]
    Inactive,
}

#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct ChainSimple {
    /** The ID of the chain */
    pub chain_id: String,
    /** The common name of the chain */
    pub name: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct Wallet {
    /** The id of the wallet */
    pub wallet_id: String,
    /** The friendly name of the wallet */
    pub name: String,
    /** The date when this wallet was created */
    pub created_at: String,
    /** The status of the wallet */
    pub state: WalletState,

    pub address: String,
    pub chain: ChainSimple,
}

/// makes call to get wallets from backend for user.
pub async fn get_wallets(
    client: &reqwest::Client,
    access_token: &str,
    base_url: &str,
) -> Result<Vec<Wallet>, BotSdkError> {
    let url = set_url(base_url, "/wallets?accessOnly=true");

    let response = client.get(url).bearer_auth(access_token).send().await?;

    if response.status().is_success() {
        let res = response.json::<Vec<Wallet>>().await?;
        return Ok(res);
    }

    let status = response.status();
    let res = response.text().await?;

    Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not get wallets", status, res
    )))
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
    pub r: String,
    pub s: String,
    pub recovery_id: Option<u64>,
}

impl Signature {
    pub fn to_der(&self) -> Result<SerializedSignature, BotSdkError> {
        let mut data = [8u8; 64];
        const_hex::decode_to_slice(&self.r, &mut data[..32])?;
        const_hex::decode_to_slice(&self.s, &mut data[32..])?;

        let sig = ecdsa::Signature::from_compact(&data)?;
        Ok(sig.serialize_der())
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
    pub algorithm: KeyAlgorithm,
    pub public_key: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct SigResponse {
    pub payload: SignRequest,
    pub key: PublicKey,
    pub signature: Signature,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureRequestKind {
    Raw,
    Transaction,
    Message,
    RdxAuthenticationRequest,
    EvmEip712,
    CantonTopology,
}

/// Request signature from keyvault passing hex transactions
pub async fn sign(
    client: &reqwest::Client,
    access_token: &str,
    wallet_id: &str,
    tx_type: SignatureRequestKind,
    hex: String,
    base_url: &str,
) -> Result<SigResponse, BotSdkError> {
    let url = set_url(base_url, &format!("/wallets/{wallet_id}/sign"));

    let req = SignRequest {
        kind: tx_type,
        data: hex,
        raw_bytes: None,
    };

    let response = client
        .post(url)
        .json(&req)
        .bearer_auth(access_token)
        .send()
        .await?;

    if response.status().is_success() {
        let res = response.json::<SigResponse>().await?;
        return Ok(res);
    }

    let status = response.status();
    let res = response.text().await?;

    Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not get signature", status, res
    )))
}

/// Request signature from keyvault passing hex transactions
pub async fn logout(
    client: &reqwest::Client,
    access_token: &str,
    base_url: &str,
) -> Result<(), BotSdkError> {
    let url = set_url(base_url, "/auth/logout");

    let response = client.post(url).bearer_auth(access_token).send().await?;

    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let res = response.text().await?;

    Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not logout", status, res
    )))
}

#[derive(Serialize, Debug)]
struct RefreshRequest {
    refresh_token: String,
}

/// Make call to try to refresh the access token
pub async fn refresh_auth(
    client: &reqwest::Client,
    refresh_token: &str,
    access_token: &str,
    base_url: &str,
) -> Result<CraResponse, BotSdkError> {
    let url = set_url(base_url, "/auth/refresh");

    let req_body = RefreshRequest {
        refresh_token: refresh_token.to_owned(),
    };

    let response = client
        .post(url)
        .json(&req_body)
        .bearer_auth(access_token)
        .send()
        .await?;
    if response.status().is_success() {
        let res = response.json::<CraResponse>().await?;
        return Ok(res);
    }

    let status = response.status();
    let res = response.text().await?;

    Err(BotSdkError::Custom(format!(
        "{}.\n Status: {} \n Body: {}",
        "Could not refresh auth", status, res
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_to_der() {
        let signature = Signature {
            r: "bc87e27ae505b41bab7f228a60205f61756b3f5ba67ad33fd35664731720a0c9".to_string(),
            s: "4a28dc564d87e36871d032a208ccef1229a8c95875928f867d77daa21991ca2e".to_string(),
            recovery_id: Some(0),
        };

        let der_result = signature.to_der().unwrap();
        let der_hex = const_hex::encode(&der_result);

        let expected_der_hex = "3045022100bc87e27ae505b41bab7f228a60205f61756b3f5ba67ad33fd35664731720a0c902204a28dc564d87e36871d032a208ccef1229a8c95875928f867d77daa21991ca2e";

        assert_eq!(der_hex, expected_der_hex);
    }
    #[test]
    fn test_signature_to_der_2() {
        let signature = Signature {
            r: "d12c949a67ebdaf38350fda2b6d4e0e2bb8a8c8160cfbc6487a3719e2187dd02".to_string(),
            s: "18f9b3eb182ef670832698f57dc663ddf0501e202aa90865d13abe12e2cd7559".to_string(),
            recovery_id: Some(1),
        };

        let der_result = signature.to_der().unwrap();
        let der_hex = const_hex::encode(&der_result);

        let expected_der_hex = "3045022100d12c949a67ebdaf38350fda2b6d4e0e2bb8a8c8160cfbc6487a3719e2187dd02022018f9b3eb182ef670832698f57dc663ddf0501e202aa90865d13abe12e2cd7559";

        assert_eq!(der_hex, expected_der_hex);
    }
}
