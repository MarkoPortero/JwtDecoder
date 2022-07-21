extern crate jsonwebtoken as jwt;
extern crate serde_json;
use jwt::{decode_header, decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

use std::*;
 
fn main() {
    io::stdin().read_line(&mut token).unwrap();
    decode_jwt_header(&token);
    decode_body(&token);
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Claims {
    pub jti: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub nbf: i64,
    pub ver: String,
    pub region: String,
    #[serde(rename = "merchant_account_id")]
    pub merchant_account_id: String,
    pub channel: String,
    pub aud: Vec<String>,
    pub scopes: Scopes,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scopes {
    pub intent: Intent,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Intent {
    #[serde(rename = "intent_type")]
    pub intent_type: String,
    #[serde(rename = "intent_reference_id")]
    pub intent_reference_id: String,
}

fn decode_jwt_header(token: &str) {
    let header = decode_header(&token);
    let header_result = header.unwrap();
    println!("{}", serde_json::to_string_pretty(&header_result).unwrap());
}
 
fn decode_body(token: &str){
        // Default value
    let mut validation = Validation::default();
    validation.leeway = 999999;
    validation.validate_exp = false;
    let token_message = decode::<Claims>(&token, &DecodingKey::from_secret("PUT DECODING SECRET HERE".as_ref()), &validation);
    let  token_message_result = token_message.unwrap();
    let claims = token_message_result.claims;
    println!("{}", serde_json::to_string_pretty(&claims).unwrap());
}