use crypdefi_bot_sdk::{
    error::BotSdkError,
    http::SignatureRequestKind,
    user::{Bot, UserId},
};
use tokio::time::{Duration, sleep};

#[tokio::main]
async fn main() -> Result<(), BotSdkError> {
    let user_id = UserId::new(String::from("us-0000000000-1d09b044f88074ab7cfd"))?;

    let mut bot = Bot::new(
        String::from(
            "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXQP2Nr18sJuL7BiO
E+jpJnxOH/5nIg6Nk8HJtL7dlNOhRANCAARLFq3OvO/McpHQud7nLUAgo+wv64kL
nIgrbZYBLkODZwt4/3AlcQuZTpBNqLpF62plLLV+9RJffQndWaiGFNff
-----END PRIVATE KEY-----",
        ),
        user_id,
        Some(String::from("https://api.sandbox.crypdefi.eu")),
    )?;

    println!("Bot: {:?}", bot);
    bot.login(true).await?;

    println!("loginging");
    let wallets = bot.get_wallets().await?;
    println!("wallets: {:?}", wallets);

    for i in 0..5 {
        println!("\n loop: {}", i);
        let signature = bot.sign_transaction("wa-0000000000-e92b31b7d1ec34ce6ad1".to_string(),SignatureRequestKind::Transaction  ,"02f8af01018390f560850461933067828cb394a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844095ea7b300000000000000000000000097802f38a37e1d789eba194513e3eb7e918d34df000000000000000000000000000000000000000000000000000000001dcd6500c001a0ad0b4a87309ef94b96d38f145d676d971ca1f1e4702c9cace99fdec8df4a8814a008651a171f31629bcf3a686ca26b9d3cece44c6dfec39fb2c1848e3b290ba121".to_string()).await?;
        println!("signature: {:?}", signature);
        println!(
            "\n payload being signed: {:?}",
            const_hex::encode(signature.payload.raw_bytes.unwrap())
        );
        println!(
            "\n der hex signature: {:?}",
            const_hex::encode(signature.signature.to_der()?)
        );

        println!(
            "\n der hex secp signature: {:?}",
            const_hex::encode(signature.signature.secp_der()?)
        );

        // println!("refreshing");
        // let result = bot.refresh(true).await?;
        // println!("refresh result: {:?}", result);

        let expiration = bot.auth_expiration_unix_time().await;
        println!("expiration: {:?}", expiration);
        sleep(Duration::from_secs(25)).await;
    }

    let result = bot.logout().await?;
    println!("logout result: {:?}", result);

    let expiration = bot.auth_expiration_unix_time().await;
    println!("expiration: {:?}", expiration);

    return Ok(());
}
