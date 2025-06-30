use std::str::FromStr;

use actix_web::{App, HttpResponse, HttpServer, Responder, post, web};
use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
use spl_token::{ID as TOKEN_PROGRAM_ID, instruction as token_instruction};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let port: u16 = std::env::var("PORT")
        .expect("PORT env not set")
        .parse()
        .expect("Port should be a number");

    HttpServer::new(|| {
        App::new()
            .service(generate_keypair)
            .service(create_token)
            .service(mint_to_token)
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}

#[post("/keypair")]
async fn generate_keypair() -> impl Responder {
    let keypair = Keypair::new();
    let pub_key = keypair.pubkey().to_string();
    let secret_key = keypair.to_base58_string();
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "pubkey": pub_key,
            "secret": secret_key
        }
    }))
}

#[derive(Deserialize)]
struct CreateTokenBody {
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[post("/token/create")]
async fn create_token(token_details: web::Json<CreateTokenBody>) -> impl Responder {
    let mint_authority = match Pubkey::from_str(&token_details.mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid mint authority public key"
            }));
        }
    };

    let mint = match Pubkey::from_str(&token_details.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            }));
        }
    };

    let instruction = token_instruction::initialize_mint(
        &TOKEN_PROGRAM_ID,
        &mint,
        &mint_authority,
        None,
        token_details.decimals,
    )
    .unwrap();

    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|account| AccountInfo {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let instruction_data = base64::encode(&instruction.data);

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "program_id": instruction.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }
    }))
}

#[derive(Deserialize)]
struct MintTokenBody {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[post("/token/mint")]
async fn mint_to_token(mint_to_details: web::Json<MintTokenBody>) -> impl Responder {
    let mint = match Pubkey::from_str(&mint_to_details.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            }));
        }
    };

    let destination = match Pubkey::from_str(&mint_to_details.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid destination public key"
            }));
        }
    };

    let authority = match Pubkey::from_str(&mint_to_details.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid authority public key"
            }));
        }
    };

    if mint_to_details.amount == 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Amount must be greater than 0"
        }));
    }

    let instruction = token_instruction::mint_to(
        &TOKEN_PROGRAM_ID,
        &mint,
        &destination,
        &authority,
        &[],
        mint_to_details.amount,
    )
    .unwrap();

    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|account| AccountInfo {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let instruction_data = base64::encode(&instruction.data);

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "program_id": instruction.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }
    }))
}
