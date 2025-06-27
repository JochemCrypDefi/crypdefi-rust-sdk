# Rust Bot SDK


Bot traders interact with the CrypDefi backend via API calls. To simplify
authentication and transaction signing, the Bot SDK can be used instead
of manually managing individual API requests.

This rust library is also used for making bindings in the Go and Python languages.

## Create keys for the Bot login.

### Generate Bot's private key.

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private_key_pkcs8.pem
```

### Generate Bot's Public key

```bash
openssl pkey -in private_key_pkcs8.pem -pubout -out public_key.pem
```



## build python 

Run: 

```
cargo build --release

cargo run --bin uniffi-bindgen generate --library target/release/libcrypdefi_bot_sdk.so --language python --out-dir python-sdk

```
## build GO and C

Run: 

```
cargo build --release

uniffi-bindgen-go --library target/release/libcrypdefi_bot_sdk.so --out-dir go-sdk
scp target/release/libcrypdefi_bot_sdk.so go-sdk/crypdefi_bot_sdk
```
## run example bot

Run: 

```
cargo run --bin crypdefi-bot
```

## Example

```rust
// --------------------------- IMPORT ---------------------------
// Use the appropriate import syntax depending on your development environment.
// E.g.: for Node.js (npm), use: import { BotSigner } from "@crypdefi/ts-bot-sdk";

// --------------------------- CONFIG ---------------------------
const userId = "us-0000000000-691dc9136b45c44f621f"; // Replace with your bot's user_id.
const walletId = "wa-0000000000-93cbea463ddfa0afc3a3"; // Replace with the wallet_id of the wallet you want to trade with.

const privateKeyPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNuHfSocQxRsmuNM2
WEayB/SPAF3nRuSIkmRfRzky/7GhRANCAARz1ItrxGVCPwNN4HQPPWis09yQr5YH
HThQDWWDPkkZ8RM6DFGHu+UpFKGgQ+u33huXc4n0xb3WYIygPMf4SkUh
-----END PRIVATE KEY-----`; // This is the bot's private key used to authenticate with CrypDefi (not the wallet's private key).


// NOTE: If you want to change the backend endpoint you will need to set the env variable: CRYPDEFI_BASE_URL

// --------------------------- INIT BOT ---------------------------
println!("Initializing Bot...");
// Remove the JavaScript syntax 'const bot = new BotSigner(privateKeyPem);'
let bot = Bot::new(String::from(privateKeyPem)).unwrap();

// --------------------------- LOGIN WITH BOT ---------------------------
println!("Logging in with Bot...");
// You have the option to turn off authentication refresh if needed.
bot.login(
    String::from("us-0000000000-691dc9136b45c44f621f"),
    Some(false), // Changed from Option::Some(false) to Some(false)
).unwrap();

// --------------------------- Check for expiration time of AUTH ---------------------------
let expiration = bot.auth_expiration_unix_time().await;
println!("expiration: {}", expiration);

// --------------------------- FETCH ASSOCIATED WALLETS ---------------------------
println!("Fetching wallets associated with Bot...");
let wallets = bot.get_wallets().unwrap();
println!("wallets: {:?}", wallets);

// --------------------------- CREATE & SIGN TRANSACTION ---------------------------
println!("Preparing transaction to sign...");
// Include steps to create transaction here. Replace hex below with the actual hex string of the transaction to sign.
let hex = "02f8af01018390f560850461933067828cb394a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844095ea7b300000000000000000000000097802f38a37e1d789eba194513e3eb7e918d34df000000000000000000000000000000000000000000000000000000001dcd6500c001a0ad0b4a87309ef94b96d38f145d676d971ca1f1e4702c9cace99fdec8df4a8814a008651a171f31629bcf3a686ca26b9d3cece44c6dfec39fb2c1848e3b290ba121"; // Changed from const to let

println!("Signing transaction...");
// Sign the transaction using the wallet that was configured. Make sure the bot has access to this wallet in the Management UI.
let signature = bot.sign_transaction(
    "wa-0000000000-c23f217716b68ae96415".to_string(),
    SignatureRequestKind::Transaction,
    hex.to_string()
).unwrap();
println!("signature: {:?}", signature);

// --------------------------- REFRESH SESSION ---------------------------
println!("Refreshing Bot session...");
let result = bot.refresh().unwrap();
println!("refresh result: {:?}", result);

// --------------------------- LOGOUT ---------------------------
let result = bot.logout().unwrap();
println!("logout result: {:?}", result);

```

