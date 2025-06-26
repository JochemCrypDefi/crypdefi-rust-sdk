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
