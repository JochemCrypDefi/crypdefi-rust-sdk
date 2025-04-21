use crypdefi_bot_sdk::crypdefi::{SignatureRequestKind, error::BotSdkError, user::Bot};

fn main() -> Result<(), BotSdkError> {
    let bot = Bot::new(String::from(
        "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWy5TsnH8AwJVPLJS
V6AYLJlpVcTjZi4Pwil8lN79Xr+hRANCAARsNq7YC/YhcveRVnwzSnIUvbpbdHFy
+zR4VVTid8eKVEneOef9lSiFyQczQh6MPwpKGtjAexp3sxJryohTQylr
-----END PRIVATE KEY-----",
    ))
    .unwrap();

    bot.login(String::from("us-0000000000-fbf17c83804f03af10c6"))
        .unwrap();

    let wallets = bot.get_wallets().unwrap();
    println!("wallets: {:?}", wallets);

    let signature = bot.sign_transaction("wa-0000000000-4f45f9d208e9207736fb".to_string(),SignatureRequestKind::Transaction  ,"02f8af01018390f560850461933067828cb394a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844095ea7b300000000000000000000000097802f38a37e1d789eba194513e3eb7e918d34df000000000000000000000000000000000000000000000000000000001dcd6500c001a0ad0b4a87309ef94b96d38f145d676d971ca1f1e4702c9cace99fdec8df4a8814a008651a171f31629bcf3a686ca26b9d3cece44c6dfec39fb2c1848e3b290ba121".to_string()).unwrap();
    println!("signature: {:?}", signature);

    let result = bot.refresh().unwrap();
    println!("refresh result: {:?}", result);

    let result = bot.logout().unwrap();
    println!("logout result: {:?}", result);
    // bot.

    return Ok(());
}
