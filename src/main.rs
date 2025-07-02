use std::str::FromStr;

use actix_web::{App, HttpResponse, HttpServer, Responder, post, web};
use base64::prelude::*;
use bs58;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    system_instruction,
};
use spl_associated_token_account;
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
            .service(sign_message)
            .service(verify_message)
            .service(send_sol)
            .service(send_token)
    })
    .bind(("0.0.0.0", port))?
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
    #[serde(rename = "mintAuthority")]
    mint_authority: Option<String>,
    mint: Option<String>,
    decimals: Option<u8>,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[post("/token/create")]
async fn create_token(token_details: web::Json<CreateTokenBody>) -> impl Responder {
    let mint_authority = match &token_details.mint_authority {
        Some(authority) if !authority.is_empty() => authority,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };

    let mint = match &token_details.mint {
        Some(mint_key) if !mint_key.is_empty() => mint_key,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };

    let decimals = match token_details.decimals {
        Some(dec) if dec > 0 => dec,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };

    let mint_authority_pubkey = match Pubkey::from_str(mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid mint authority public key"
            }));
        }
    };

    let mint_pubkey = match Pubkey::from_str(mint) {
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
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        decimals,
    )
    .unwrap();
    println!("{:?}", instruction.accounts);
    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|account| AccountInfo {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let instruction_data = BASE64_STANDARD.encode(&instruction.data);

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
    mint: Option<String>,
    destination: Option<String>,
    authority: Option<String>,
    amount: Option<u64>,
}

#[post("/token/mint")]
async fn mint_to_token(mint_to_details: web::Json<MintTokenBody>) -> impl Responder {
    let mint_authority = match &mint_to_details.authority {
        Some(authority) if !authority.is_empty() => authority,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };
    let destination = match &mint_to_details.destination {
        Some(destination) if !destination.is_empty() => destination,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };

    let amount = match mint_to_details.amount {
        Some(amount) if amount > 0 => amount,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };

    let mint = match &mint_to_details.mint {
        Some(mint) if !mint.is_empty() => mint,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };

    let mint = match Pubkey::from_str(mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            }));
        }
    };

    let destination = match Pubkey::from_str(destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid destination public key"
            }));
        }
    };

    let authority = match Pubkey::from_str(mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid authority public key"
            }));
        }
    };

    if amount == 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Amount must be greater than 0"
        }));
    }

    let destination_ata =
        spl_associated_token_account::get_associated_token_address(&destination, &mint);

    let instruction = token_instruction::mint_to(
        &TOKEN_PROGRAM_ID,
        &mint,
        &destination_ata,
        &authority,
        &[],
        amount,
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

    let instruction_data = BASE64_STANDARD.encode(&instruction.data);

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
struct SignMessageBody {
    message: String,
    secret: String,
}

#[post("/message/sign")]
async fn sign_message(sign_details: web::Json<SignMessageBody>) -> impl Responder {
    if sign_details.message.is_empty() || sign_details.secret.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    let keypair =
        match std::panic::catch_unwind(|| Keypair::from_base58_string(&sign_details.secret)) {
            Ok(kp) => kp,
            Err(_) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid secret key format"
                }));
            }
        };

    let message_bytes = sign_details.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    let public_key = keypair.pubkey().to_string();

    let signature_base58 = bs58::encode(&signature.as_ref()).into_string();

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "signature": signature_base58,
            "pubkey": public_key,
            "message": sign_details.message
        }
    }))
}

#[derive(Deserialize)]
struct VerifyMessageBody {
    message: String,
    signature: String,
    pubkey: String,
}

#[post("/message/verify")]
async fn verify_message(verify_details: web::Json<VerifyMessageBody>) -> impl Responder {
    if verify_details.message.is_empty()
        || verify_details.signature.is_empty()
        || verify_details.pubkey.is_empty()
    {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    let pubkey = match Pubkey::from_str(&verify_details.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid public key format"
            }));
        }
    };

    let signature_bytes = match bs58::decode(&verify_details.signature).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid signature format"
            }));
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid signature length"
            }));
        }
    };

    let message_bytes = verify_details.message.as_bytes();
    let is_valid = signature.verify(pubkey.as_ref(), message_bytes);

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "valid": is_valid,
            "message": verify_details.message,
            "pubkey": verify_details.pubkey
        }
    }))
}

#[derive(Deserialize)]
struct SendSolBody {
    from: String,
    to: String,
    lamports: u64,
}

#[post("/send/sol")]
async fn send_sol(transfer_details: web::Json<SendSolBody>) -> impl Responder {
    if transfer_details.from.is_empty() || transfer_details.to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    if transfer_details.lamports == 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Amount must be greater than 0"
        }));
    }

    let from_pubkey = match Pubkey::from_str(&transfer_details.from) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid sender public key"
            }));
        }
    };

    let to_pubkey = match Pubkey::from_str(&transfer_details.to) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid recipient public key"
            }));
        }
    };

    if from_pubkey == to_pubkey {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Sender and recipient addresses cannot be the same"
        }));
    }

    let instruction =
        system_instruction::transfer(&from_pubkey, &to_pubkey, transfer_details.lamports);

    let accounts: Vec<String> = instruction
        .accounts
        .iter()
        .map(|account| account.pubkey.to_string())
        .collect();

    let instruction_data = bs58::encode(&instruction.data).into_string();

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
struct SendTokenBody {
    destination: Option<String>,
    mint: Option<String>,
    owner: Option<String>,
    amount: Option<u64>,
}

#[derive(Serialize)]
struct TokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[post("/send/token")]
async fn send_token(transfer_details: web::Json<SendTokenBody>) -> impl Responder {
    // Check if required fields are missing or empty
    let destination = match &transfer_details.destination {
        Some(dest) if !dest.is_empty() => dest,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };

    let mint = match &transfer_details.mint {
        Some(mint_key) if !mint_key.is_empty() => mint_key,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };

    let owner = match &transfer_details.owner {
        Some(owner_key) if !owner_key.is_empty() => owner_key,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };

    let amount = match transfer_details.amount {
        Some(amt) if amt > 0 => amt,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Missing required fields"
            }));
        }
    };

    let destination_pubkey = match Pubkey::from_str(destination) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid destination public key"
            }));
        }
    };

    let mint_pubkey = match Pubkey::from_str(mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            }));
        }
    };

    let owner_pubkey = match Pubkey::from_str(owner) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid owner public key"
            }));
        }
    };

    let source_pubkey =
        spl_associated_token_account::get_associated_token_address(&owner_pubkey, &mint_pubkey);

    let destination_ata = spl_associated_token_account::get_associated_token_address(
        &destination_pubkey,
        &mint_pubkey,
    );

    let instruction = token_instruction::transfer(
        &TOKEN_PROGRAM_ID,
        &source_pubkey,
        &destination_ata,
        &owner_pubkey,
        &[],
        amount,
    )
    .unwrap();

    let accounts: Vec<TokenAccountInfo> = instruction
        .accounts
        .iter()
        .map(|account| TokenAccountInfo {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
        })
        .collect();

    let instruction_data = bs58::encode(&instruction.data).into_string();

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "program_id": instruction.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }
    }))
}
