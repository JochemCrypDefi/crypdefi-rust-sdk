use crate::error::BotSdkError;
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
    access_token_arc: &Option<String>,
    base_url: &str,
) -> Result<Vec<Wallet>, BotSdkError> {
    let access_token = match access_token_arc {
        Some(acc) => acc,
        None => return Err(BotSdkError::NoAccessToken),
    };

    let url = set_url(base_url, "/wallets?accessOnly=true");

    let response = client
        .get(url)
        .bearer_auth(access_token.clone())
        .send()
        .await?;

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

fn encode_integer(bytes: &[u8], buff: &mut Vec<u8>) {
    buff.push(0x02); // Integer tag

    // Remove leading zeros, but ensure at least one byte remains
    let mut trimmed = bytes;
    while trimmed.len() > 1 && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }

    // If the first bit is 1, prepend a 0x00 to avoid interpreting as negative
    if trimmed[0] & 0x80 != 0 {
        buff.push((trimmed.len() + 1) as u8); // Length includes the extra 0x00
        buff.push(0x00);
    } else {
        buff.push(trimmed.len() as u8); // Length of the integer
    }

    buff.extend_from_slice(trimmed);
}

impl Signature {
    pub fn to_der(&self) -> Result<Vec<u8>, BotSdkError> {
        // Convert hex strings to byte vectors
        let r_bytes = hex::decode(&self.r)?;
        let s_bytes = hex::decode(&self.s)?;

        // Speculatively reserve 64 bytes. Unsure if this is the correct value, but
        // Vec reserves values quasi-exponentially (0, 1, 2, 4, 8, 16..) to speculatively
        // avoid frequent reallocations. Next higher value should be 128
        let mut der = Vec::with_capacity(total_length + 2);

        // Byte 0 is sequence tag 0x30, byte 1 is the length which we don't yet know, we'll edit later
        der.extend_from_slice(&[0x30, 0]);

        // Append encoded integer
        encode_integer(&r_bytes, &mut der);
        encode_integer(&s_bytes, &mut der);

        der[1] = der.len() as u8 - 2;

        Ok(der)
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
}

/// Request signature from keyvault passing hex transactions
pub async fn sign(
    client: &reqwest::Client,
    access_token_arc: &Option<String>,
    wallet_id: String,
    tx_type: SignatureRequestKind,
    hex: String,
    base_url: &str,
) -> Result<SigResponse, BotSdkError> {
    let access_token = match access_token_arc {
        Some(acc) => acc,
        None => return Err(BotSdkError::NoAccessToken),
    };

    let url = set_url(base_url, &format!("/wallets/{wallet_id}/sign"));

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
    access_token_arc: &Option<String>,
    base_url: &str,
) -> Result<(), BotSdkError> {
    let access_token = match access_token_arc {
        Some(acc) => acc,
        None => return Err(BotSdkError::NoAccessToken),
    };

    let url = set_url(base_url, "/auth/logout");

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
    refresh_token_opt: &Option<String>,
    access_token_opt: &Option<String>,
    base_url: &str,
) -> Result<CraResponse, BotSdkError> {
    let access_token = match access_token_opt {
        Some(acc) => acc,
        None => return Err(BotSdkError::NoAccessToken),
    };
    let refresh_token = match refresh_token_opt {
        Some(acc) => acc,
        None => return Err(BotSdkError::NoRefreshToken),
    };

    let url = set_url(base_url, "/auth/refresh");

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
        let der_hex = hex::encode(&der_result);

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
        let der_hex = hex::encode(&der_result);

        let expected_der_hex = "3045022100d12c949a67ebdaf38350fda2b6d4e0e2bb8a8c8160cfbc6487a3719e2187dd02022018f9b3eb182ef670832698f57dc663ddf0501e202aa90865d13abe12e2cd7559";
        
        assert_eq!(der_hex, expected_der_hex);
    }

    #[test]
    fn test_encode_integer_positive() {
        // Test with a positive number that doesn't need padding
        let bytes = hex::decode("bc87e27ae505b41bab7f228a60205f61756b3f5ba67ad33fd35664731720a0c9").unwrap();
        let mut buffer = Vec::new();
        
        encode_integer(&bytes, &mut buffer);
        
        let expected = hex::decode("022100bc87e27ae505b41bab7f228a60205f61756b3f5ba67ad33fd35664731720a0c9").unwrap();
        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_encode_integer_remove_leading_zeros() {
        // Test removing leading zeros (but keeping at least one)
        let bytes = hex::decode("0000bc87e27ae505b41bab7f228a60205f61756b3f5ba67ad33fd35664731720a0c9").unwrap();
        let mut buffer = Vec::new();
        
        encode_integer(&bytes, &mut buffer);
        
        // Should remove leading zeros
        let expected = hex::decode("022100bc87e27ae505b41bab7f228a60205f61756b3f5ba67ad33fd35664731720a0c9").unwrap();
        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_encode_integer_keep_single_zero() {
        // Test that single zero is preserved
        let bytes = vec![0x00];
        let mut buffer = Vec::new();
        
        encode_integer(&bytes, &mut buffer);
        
        let expected = vec![0x02, 0x01, 0x00]; // INTEGER tag, length 1, value 0
        assert_eq!(buffer, expected);
    }
}
