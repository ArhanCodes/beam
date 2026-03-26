use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::code::generate_code;

#[derive(Clone)]
struct AppState {
    transfers: Arc<Mutex<HashMap<String, TransferInfo>>>,
    storage_dir: PathBuf,
}

struct TransferInfo {
    filename: String,
    size: u64,
    checksum: String,
    path: PathBuf,
}

#[derive(Serialize)]
struct UploadResponse {
    code: String,
    filename: String,
    size: u64,
}

#[derive(Serialize)]
struct FileInfo {
    filename: String,
    size: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn run_web(addr: SocketAddr) -> Result<()> {
    let storage_dir = std::env::temp_dir().join("beam_transfers");
    tokio::fs::create_dir_all(&storage_dir).await?;

    let state = AppState {
        transfers: Arc::new(Mutex::new(HashMap::new())),
        storage_dir,
    };

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/upload", post(handle_upload))
        .route("/api/info/{code}", get(handle_info))
        .route("/api/download/{code}", get(handle_download))
        .layer(DefaultBodyLimit::disable()) // No file size limit
        .layer(CorsLayer::permissive())
        .with_state(state);

    info!("Web UI running at http://{}", addr);
    println!("\n  beam web");
    println!("  ────────────────────────────");
    println!("  Open http://{} in your browser", addr);
    println!("  Press Ctrl+C to stop\n");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn serve_index() -> impl IntoResponse {
    Html(include_str!("../web/index.html"))
}

async fn handle_upload(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    while let Ok(Some(field)) = multipart.next_field().await {
        let filename: String = field
            .file_name()
            .unwrap_or("unnamed")
            .to_string();

        let data: bytes::Bytes = match field.bytes().await {
            Ok(d) => d,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("Failed to read file: {}", e)})),
                );
            }
        };

        let size = data.len() as u64;
        let checksum = hex::encode(Sha256::digest(&data));
        let code = generate_code();

        let file_path = state.storage_dir.join(&code);
        if let Err(e) = tokio::fs::write(&file_path, &data).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to save file: {}", e)})),
            );
        }

        let transfer = TransferInfo {
            filename: filename.clone(),
            size,
            checksum,
            path: file_path,
        };

        state.transfers.lock().await.insert(code.clone(), transfer);

        info!("File uploaded: {} ({} bytes) -> code: {}", filename, size, code);

        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "code": code,
                "filename": filename,
                "size": size,
            })),
        );
    }

    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "No file provided"})),
    )
}

async fn handle_info(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> impl IntoResponse {
    let transfers = state.transfers.lock().await;
    match transfers.get(&code) {
        Some(transfer) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "filename": transfer.filename,
                "size": transfer.size,
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Transfer not found. Check your code and try again."})),
        ),
    }
}

async fn handle_download(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> impl IntoResponse {
    let transfers = state.transfers.lock().await;
    match transfers.get(&code) {
        Some(transfer) => {
            let mut file = match File::open(&transfer.path).await {
                Ok(f) => f,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [
                            (header::CONTENT_TYPE, "application/json".to_string()),
                            (header::CONTENT_DISPOSITION, String::new()),
                        ],
                        Body::from(r#"{"error":"File not found on disk"}"#),
                    );
                }
            };

            let mut data = Vec::new();
            if let Err(_) = file.read_to_end(&mut data).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [
                        (header::CONTENT_TYPE, "application/json".to_string()),
                        (header::CONTENT_DISPOSITION, String::new()),
                    ],
                    Body::from(r#"{"error":"Failed to read file"}"#),
                );
            }

            let content_type = mime_guess::from_path(&transfer.filename)
                .first_or_octet_stream()
                .to_string();

            let disposition = format!("attachment; filename=\"{}\"", transfer.filename);

            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CONTENT_DISPOSITION, disposition),
                ],
                Body::from(data),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (header::CONTENT_DISPOSITION, String::new()),
            ],
            Body::from(r#"{"error":"Transfer not found"}"#),
        ),
    }
}
