use std::collections::HashMap;
use std::sync::Mutex;
use tokio_util::sync::CancellationToken;

mod config;
mod ppk;
mod ssh;

pub struct SessionManager {
    sessions: Mutex<HashMap<String, CancellationToken>>,
}

impl SessionManager {
    fn new() -> Self {
        SessionManager {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

#[tauri::command]
async fn get_configs(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    config::read_configs(&app).map_err(|e| e.to_string())
}

#[tauri::command]
async fn save_configs(app: tauri::AppHandle, data: serde_json::Value) -> Result<(), String> {
    config::write_configs(&app, &data).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_prefs(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    config::read_prefs(&app).map_err(|e| e.to_string())
}

#[tauri::command]
async fn save_prefs(app: tauri::AppHandle, data: serde_json::Value) -> Result<(), String> {
    config::write_prefs(&app, &data).map_err(|e| e.to_string())
}

#[tauri::command]
async fn browse_sftp(
    host: String,
    port: u16,
    username: String,
    #[allow(non_snake_case)] authType: String,
    password: Option<String>,
    #[allow(non_snake_case)] privateKey: Option<String>,
    passphrase: Option<String>,
    path: String,
) -> Result<serde_json::Value, String> {
    ssh::browse_sftp(host, port, username, authType, password, privateKey, passphrase, path)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ssh_connect(
    app: tauri::AppHandle,
    state: tauri::State<'_, SessionManager>,
    #[allow(non_snake_case)] tabId: String,
    host: String,
    port: u16,
    username: String,
    #[allow(non_snake_case)] authType: String,
    password: Option<String>,
    #[allow(non_snake_case)] privateKey: Option<String>,
    passphrase: Option<String>,
    #[allow(non_snake_case)] filePath: String,
    lines: u32,
) -> Result<(), String> {
    // Cancel any existing session for this tab
    if let Some(old) = state.sessions.lock().unwrap().remove(&tabId) {
        old.cancel();
    }

    let cancel = CancellationToken::new();
    state
        .sessions
        .lock()
        .unwrap()
        .insert(tabId.clone(), cancel.clone());

    tokio::spawn(ssh::tail_session(
        app,
        tabId,
        cancel,
        host,
        port,
        username,
        authType,
        password,
        privateKey,
        passphrase,
        filePath,
        lines,
    ));

    Ok(())
}

#[tauri::command]
async fn ssh_disconnect(
    state: tauri::State<'_, SessionManager>,
    #[allow(non_snake_case)] tabId: String,
) -> Result<(), String> {
    if let Some(token) = state.sessions.lock().unwrap().remove(&tabId) {
        token.cancel();
    }
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn run() {
    tauri::Builder::default()
        .manage(SessionManager::new())
        .invoke_handler(tauri::generate_handler![
            get_configs,
            save_configs,
            get_prefs,
            save_prefs,
            browse_sftp,
            ssh_connect,
            ssh_disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
