# Rust Bot SDK


This library is used for generating bindings to other languages.


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
```
