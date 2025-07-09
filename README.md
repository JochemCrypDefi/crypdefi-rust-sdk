# Rust Bot SDK


Bot traders interact with the CrypDefi backend via API calls. To simplify
authentication and transaction signing, the Bot SDK can be used instead
of manually managing individual API requests.

## Create keys for the Bot login.

### Generate Bot's private key

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private_key_pkcs8.pem
```

### Generate Bot's public key

```bash
openssl pkey -in private_key_pkcs8.pem -pubout -out public_key.pem
```

## Examples

```rust
// --------------------------- IMPORT ---------------------------
use crypdefi_bot_sdk::crypdefi::user::Bot;
use crypdefi_bot_sdk::crypdefi::SignatureRequestKind;
use std::fs;

// --------------------------- CONFIG ---------------------------
// Replace with your bot's user_id.
let user_id = "us-0000000000-94518ea57547afd340c3";
// Replace with the wallet_id of the wallet you want to trade with.
let wallet_id = "wa-0000000000-9f3542a65690ff697b85"; 
// This is the bot's private key used to authenticate with CrypDefi (not the wallet's private key).
let private_key_pem = fs::read_to_string("private_key_pkcs8.pem").expect("Failed to read private_key_pkcs8.pem");


// --------------------------- INIT BOT ---------------------------
println!("Initializing Bot...\n");
let bot = Bot::new(String::from(private_key_pem), None).unwrap();
   
// --------------------------- LOGIN WITH BOT ---------------------------
println!("Logging in with Bot...");
// if you turn off auto_refresh the bot will not automatically re-authenticate itself when its login-token is about to expire
bot.login(
    user_id.to_string(),
    Some(false)
).await.unwrap();
 
// --------------------------- Check for expiration time of AUTH ---------------------------
let expiration = bot.auth_expiration_unix_time().await;
println!("Expiration: {:?}\n", expiration);
 
// --------------------------- FETCH ASSOCIATED WALLETS ---------------------------
println!("Fetching wallets associated with Bot...");
let wallets = bot.get_wallets().await.unwrap();
println!("Wallets: {:?}\n", wallets);
 
// --------------------------- CREATE & SIGN TRANSACTION ---------------------------
println!("Preparing transaction to sign...\n");
// Include steps to create transaction here. Replace hex below with the actual hex string of the transaction to sign.
let example_evm_hex = "02f8af01018390f560850461933067828cb394a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844095ea7b300000000000000000000000097802f38a37e1d789eba194513e3eb7e918d34df000000000000000000000000000000000000000000000000000000001dcd6500c001a0ad0b4a87309ef94b96d38f145d676d971ca1f1e4702c9cace99fdec8df4a8814a008651a171f31629bcf3a686ca26b9d3cece44c6dfec39fb2c1848e3b290ba121";

println!("Signing transaction...");
// Sign the transaction using the wallet that was configured. Make sure the bot has access to this wallet in the Management UI.
let signature = bot.sign_transaction(
    wallet_id.to_string(),
    SignatureRequestKind::Transaction,
    example_evm_hex.to_string()
).await.unwrap();
println!("Signature: {:?}\n", signature);
 
// --------------------------- REFRESH SESSION ---------------------------
println!("Refreshing Bot session...");
let refresh_result = bot.refresh().await.unwrap();
println!("Refresh result: {:?}\n", refresh_result);
 
// --------------------------- LOGOUT ---------------------------
let logout_result = bot.logout().await.unwrap();
println!("Logout result: {:?}", logout_result);
```

## DEVELOPMENT

This are commands and tools for developers of the SDK.

You will need to have the static library somewhere in the file system.

### Building library locally
Run: 
```bash
cargo build
```

### run example bot

This runs a very simple main function with the basic functionality of the SDK
```bash
cargo run --bin crypdefi-bot
```
