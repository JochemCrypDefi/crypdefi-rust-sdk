use crypdefi_bot_sdk::{error::BotSdkError, http::SignatureRequestKind, user::Bot};

#[tokio::main]
async fn main() -> Result<(), BotSdkError> {
    let bot = Bot::new(String::from(
        "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgT/x59Xqj/UnxmiO0
VfdMlG3IA6EhXb0a3TePDvWw6RqhRANCAAQfPDagIdi3luh8HaOBihcKqgaCsYsU
6hpCDdXZruL5+EnOhscqQQqRhJ0zIeCeIBR6oTHOFhVVkzE6Dw9JeArx
-----END PRIVATE KEY-----",
    ))
    .unwrap();

    println!("loginging");
    bot.login(
        String::from("us-0000000000-1dcf6986e73a839391f1"),
        Option::Some(true),
    )
    .await
    .unwrap();

    let wallets = bot.get_wallets().await.unwrap();
    println!("wallets: {:?}", wallets);

    let signature = bot.sign_transaction("wa-0000000000-613ae92733b8fe1b07a6".to_string(),SignatureRequestKind::Transaction  ,"02f8af01018390f560850461933067828cb394a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844095ea7b300000000000000000000000097802f38a37e1d789eba194513e3eb7e918d34df000000000000000000000000000000000000000000000000000000001dcd6500c001a0ad0b4a87309ef94b96d38f145d676d971ca1f1e4702c9cace99fdec8df4a8814a008651a171f31629bcf3a686ca26b9d3cece44c6dfec39fb2c1848e3b290ba121".to_string()).await.unwrap();
    println!("signature: {:?}", signature);

    let result = bot.refresh().await.unwrap();
    println!("refresh result: {:?}", result);

    let expiration = bot.auth_expiration_unix_time().await.unwrap();
    println!("expiration: {:?}", expiration);

    let result = bot.logout().await.unwrap();
    println!("logout result: {:?}", result);

    return Ok(());
}
