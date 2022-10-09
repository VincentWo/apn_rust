use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH}, env, 
};

use jsonwebtoken as jwt;
use dotenv::dotenv;
use jwt::Algorithm;

use reqwest::{Client, header::{HeaderMap, HeaderValue}};
use serde::Serialize;
use tokio::{fs, io::{stdin, Stdin, self, BufReader, AsyncBufReadExt}};

#[derive(Serialize)]
struct PushNotification {
    aps: Aps,
}

#[derive(Serialize)]
struct Aps {
    alert: String,
}

#[derive(Serialize)]
struct JWTClaims {
    iss: String,
    iat: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    dotenv()?;

    let token_key = fs::read(env::var("TOKEN_KEY_FILE_NAME")?).await?;

    let team_id = env::var("TEAM_ID")?;
    let auth_key_id = env::var("AUTH_KEY_ID")?;
    let topic = env::var("TOPIC")?;
    let device_token = env::var("DEVICE_TOKEN")?;
    let apns_host = env::var("APNS_HOST_NAME")?;

    let mut header = jwt::Header::new(Algorithm::ES256);
    header.kid = Some(auth_key_id);


    let mut default_header = HeaderMap::new();
    default_header.insert("apns-topic", HeaderValue::from_str(&topic)?);
    default_header.insert("apns-push-type", HeaderValue::from_static("alert"));

    let client = Client::builder().default_headers(default_header).build()?;


    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    let claims = JWTClaims {
        iss: team_id.to_string(),
        iat: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
    };
    let token = jwt::encode(&header, &claims, &jwt::EncodingKey::from_ec_pem(&token_key)?)?;

    loop {
        let line = lines.next_line().await?.unwrap();
        let response = client
            .post(format!("{apns_host}/3/device/{device_token}"))
            .bearer_auth(&token)
            .json(&PushNotification {
                aps: Aps {
                    alert: line,
                }
            })
            .send()
            .await?;
        println!("{response:#?}");
        println!("{:#?}", response.text().await);
    }
}
