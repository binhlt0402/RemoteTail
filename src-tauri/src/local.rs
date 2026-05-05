use std::io::SeekFrom;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::sync::CancellationToken;

const TAIL_BUF: u64 = 131_072; // 128 KB

pub async fn local_tail_session(
    app: tauri::AppHandle,
    tab_id: String,
    cancel: CancellationToken,
    file_path: String,
    lines: u32,
) {
    crate::emit(&app, &tab_id, "status", &format!("Opening {file_path}…"));

    let mut file = match tokio::fs::File::open(&file_path).await {
        Ok(f) => f,
        Err(e) => {
            crate::emit(&app, &tab_id, "error", &format!("Cannot open file: {e}"));
            crate::emit(&app, &tab_id, "closed", "");
            return;
        }
    };

    let file_len = match file.metadata().await {
        Ok(m) => m.len(),
        Err(e) => {
            crate::emit(&app, &tab_id, "error", &format!("Cannot read metadata: {e}"));
            crate::emit(&app, &tab_id, "closed", "");
            return;
        }
    };

    let seek_to = file_len.saturating_sub(TAIL_BUF);
    if seek_to > 0 {
        let _ = file.seek(SeekFrom::Start(seek_to)).await;
    }

    let mut raw = Vec::new();
    let _ = file.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw);
    let all_lines: Vec<&str> = text.lines().collect();
    let start = all_lines.len().saturating_sub(lines as usize);
    let initial = all_lines[start..].join("\n");
    if !initial.is_empty() {
        crate::emit(&app, &tab_id, "log", &initial);
    }

    let mut offset = file_len;
    crate::emit(&app, &tab_id, "status", &format!("Tailing {file_path}"));

    loop {
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(300)) => {
                let cur_len = match tokio::fs::metadata(&file_path).await {
                    Ok(m) => m.len(),
                    Err(_) => continue,
                };

                if cur_len > offset {
                    match tokio::fs::File::open(&file_path).await {
                        Ok(mut f) => {
                            let _ = f.seek(SeekFrom::Start(offset)).await;
                            let mut chunk = Vec::new();
                            if f.read_to_end(&mut chunk).await.is_ok() && !chunk.is_empty() {
                                let chunk_text = String::from_utf8_lossy(&chunk);
                                crate::emit(&app, &tab_id, "log", &chunk_text);
                            }
                        }
                        Err(_) => continue,
                    }
                    offset = cur_len;
                } else if cur_len < offset {
                    crate::emit(&app, &tab_id, "status", "File rotated, restarting…");
                    offset = 0;
                }
            }
            _ = cancel.cancelled() => break,
        }
    }

    crate::emit(&app, &tab_id, "closed", "");
}
