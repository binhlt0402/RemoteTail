use anyhow::{anyhow, Result};
use async_trait::async_trait;
use russh::client;
use russh_keys::key::PublicKey;
use serde_json::Value;
use std::sync::Arc;
use tauri::Emitter;
use tokio_util::sync::CancellationToken;

use crate::ppk::convert_ppk_to_openssh;

// ── Shared SSH client handler ────────────────────────────────────────────────

struct SshClient;

#[async_trait]
impl client::Handler for SshClient {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

// ── Auth helpers ─────────────────────────────────────────────────────────────

async fn authenticate(
    session: &mut client::Handle<SshClient>,
    username: &str,
    auth_type: &str,
    password: Option<&str>,
    private_key: Option<&str>,
    passphrase: Option<&str>,
) -> Result<()> {
    if auth_type == "password" {
        let pw = password.unwrap_or("");
        if !session.authenticate_password(username, pw).await? {
            return Err(anyhow!("SSH password authentication failed."));
        }
    } else {
        let key_str = private_key.unwrap_or("");
        let (pem, decode_passphrase) = if key_str.contains("PuTTY-User-Key-File-") {
            (convert_ppk_to_openssh(key_str, passphrase)?, None)
        } else {
            (key_str.to_string(), passphrase)
        };
        let key_pair = russh_keys::decode_secret_key(&pem, decode_passphrase)?;
        if !session
            .authenticate_publickey(username, Arc::new(key_pair))
            .await?
        {
            return Err(anyhow!("SSH key authentication failed."));
        }
    }
    Ok(())
}

async fn connect_session(
    host: &str,
    port: u16,
    username: &str,
    auth_type: &str,
    password: Option<&str>,
    private_key: Option<&str>,
    passphrase: Option<&str>,
) -> Result<client::Handle<SshClient>> {
    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, (host, port), SshClient).await?;
    authenticate(
        &mut session,
        username,
        auth_type,
        password,
        private_key,
        passphrase,
    )
    .await?;
    Ok(session)
}

// ── Log streaming ─────────────────────────────────────────────────────────────

fn emit(app: &tauri::AppHandle, tab_id: &str, kind: &str, text: &str) {
    let _ = app.emit(
        "log-event",
        serde_json::json!({ "tabId": tab_id, "type": kind, "text": text }),
    );
}

pub async fn tail_session(
    app: tauri::AppHandle,
    tab_id: String,
    cancel: CancellationToken,
    host: String,
    port: u16,
    username: String,
    auth_type: String,
    password: Option<String>,
    private_key: Option<String>,
    passphrase: Option<String>,
    file_path: String,
    lines: u32,
) {
    emit(
        &app,
        &tab_id,
        "status",
        &format!("Connecting to {username}@{host}:{port}…"),
    );

    let session = connect_session(
        &host,
        port,
        &username,
        &auth_type,
        password.as_deref(),
        private_key.as_deref(),
        passphrase.as_deref(),
    )
    .await;

    let session = match session {
        Ok(s) => s,
        Err(e) => {
            emit(&app, &tab_id, "error", &format!("Connection failed: {e}"));
            emit(&app, &tab_id, "closed", "");
            return;
        }
    };

    let mut channel = match session.channel_open_session().await {
        Ok(c) => c,
        Err(e) => {
            emit(&app, &tab_id, "error", &format!("Channel error: {e}"));
            emit(&app, &tab_id, "closed", "");
            return;
        }
    };

    let escaped = file_path.replace('\'', "'\\''");
    let cmd = format!(
        "bash -c 'tail -n {lines} \"{escaped}\"; sz=$(wc -c < \"{escaped}\"); \
         while true; do sleep 0.5; nsz=$(wc -c < \"{escaped}\"); \
         if [ \"$nsz\" -gt \"$sz\" ] 2>/dev/null; then tail -c +$((sz+1)) \"{escaped}\"; sz=$nsz; \
         elif [ \"$nsz\" -lt \"$sz\" ] 2>/dev/null; then sz=0; fi; done'"
    );

    if let Err(e) = channel.exec(true, cmd.as_str()).await {
        emit(&app, &tab_id, "error", &format!("Exec error: {e}"));
        emit(&app, &tab_id, "closed", "");
        return;
    }

    emit(
        &app,
        &tab_id,
        "status",
        &format!("Connected! Tailing {file_path}"),
    );

    loop {
        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    Some(russh::ChannelMsg::Data { ref data }) => {
                        let text = String::from_utf8_lossy(data).into_owned();
                        if !text.is_empty() {
                            emit(&app, &tab_id, "log", &text);
                        }
                    }
                    Some(russh::ChannelMsg::ExtendedData { ref data, ext: 1 }) => {
                        let text = String::from_utf8_lossy(data).into_owned();
                        if !text.is_empty() {
                            emit(&app, &tab_id, "error", &text);
                        }
                    }
                    None
                    | Some(russh::ChannelMsg::Eof)
                    | Some(russh::ChannelMsg::Close)
                    | Some(russh::ChannelMsg::ExitStatus { .. }) => {
                        emit(&app, &tab_id, "status", "Stream closed.");
                        break;
                    }
                    _ => {}
                }
            }
            _ = cancel.cancelled() => {
                let _ = channel.close().await;
                break;
            }
        }
    }

    emit(&app, &tab_id, "closed", "");
    let _ = session.disconnect(russh::Disconnect::ByApplication, "", "en").await;
}

// ── SFTP browse ───────────────────────────────────────────────────────────────

pub async fn browse_sftp(
    host: String,
    port: u16,
    username: String,
    auth_type: String,
    password: Option<String>,
    private_key: Option<String>,
    passphrase: Option<String>,
    path: String,
) -> Result<Value> {
    let session = connect_session(
        &host,
        port,
        &username,
        &auth_type,
        password.as_deref(),
        private_key.as_deref(),
        passphrase.as_deref(),
    )
    .await?;

    let channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream()).await?;

    let target = path.trim_end_matches('/');
    let target = if target.is_empty() { "/" } else { target };

    let dir = sftp.read_dir(target).await?;

    // ReadDir iterator already skips "." and ".."
    let entries: Vec<Value> = dir
        .map(|e| {
            let meta = e.metadata();
            let is_dir = e.file_type().is_dir();
            serde_json::json!({
                "name": e.file_name(),
                "isDir": is_dir,
                "size": meta.size.unwrap_or(0),
                "mtime": meta.mtime.unwrap_or(0),
            })
        })
        .collect();

    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;

    Ok(serde_json::json!({ "path": target, "entries": entries }))
}
