use std::collections::HashMap;
use std::sync::Mutex;
use tauri::{Emitter, Manager};
use tokio_util::sync::CancellationToken;

mod config;
mod local;
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

pub(crate) fn emit(app: &tauri::AppHandle, tab_id: &str, kind: &str, text: &str) {
    let _ = app.emit(
        "log-event",
        serde_json::json!({ "tabId": tab_id, "type": kind, "text": text }),
    );
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
async fn get_history(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    config::read_history(&app).map_err(|e| e.to_string())
}

#[tauri::command]
async fn save_history(app: tauri::AppHandle, data: serde_json::Value) -> Result<(), String> {
    config::write_history(&app, &data).map_err(|e| e.to_string())
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
async fn local_connect(
    app: tauri::AppHandle,
    state: tauri::State<'_, SessionManager>,
    #[allow(non_snake_case)] tabId: String,
    #[allow(non_snake_case)] filePath: String,
    lines: u32,
) -> Result<(), String> {
    if let Some(old) = state.sessions.lock().unwrap().remove(&tabId) {
        old.cancel();
    }

    let cancel = CancellationToken::new();
    state
        .sessions
        .lock()
        .unwrap()
        .insert(tabId.clone(), cancel.clone());

    tokio::spawn(local::local_tail_session(app, tabId, cancel, filePath, lines));

    Ok(())
}

#[tauri::command]
async fn get_startup_args() -> Result<Option<serde_json::Value>, String> {
    let args: Vec<String> = std::env::args().collect();
    Ok(parse_open_tab_args(&args))
}

#[tauri::command]
async fn disconnect(
    state: tauri::State<'_, SessionManager>,
    #[allow(non_snake_case)] tabId: String,
) -> Result<(), String> {
    if let Some(token) = state.sessions.lock().unwrap().remove(&tabId) {
        token.cancel();
    }
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn parse_open_tab_args(args: &[String]) -> Option<serde_json::Value> {
    let mut map = std::collections::HashMap::new();
    for arg in args.iter().skip(1) {
        if let Some(kv) = arg.strip_prefix("--") {
            if let Some((k, v)) = kv.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    if !map.contains_key("host") || !map.contains_key("path") {
        return None;
    }
    let private_key = map.get("key")
        .and_then(|p| std::fs::read_to_string(p).ok());
    Some(serde_json::json!({
        "host":       map["host"],
        "port":       map.get("port").and_then(|p| p.parse::<u16>().ok()).unwrap_or(22),
        "username":   map.get("username").map(|s| s.as_str()).unwrap_or(""),
        "authType":   map.get("auth").map(|s| s.as_str()).unwrap_or("password"),
        "password":   map.get("password"),
        "privateKey": private_key,
        "passphrase": map.get("passphrase"),
        "filePath":   map["path"],
    }))
}

pub fn run() {
    tauri::Builder::default()
        .manage(SessionManager::new())
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if let Some(payload) = parse_open_tab_args(&args) {
                let _ = app.emit("open-tab", payload);
            }
            // Bring the window to the front
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            get_configs,
            save_configs,
            get_prefs,
            save_prefs,
            get_history,
            save_history,
            browse_sftp,
            ssh_connect,
            local_connect,
            get_startup_args,
            disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
