use anyhow::Result;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tauri::Manager;

fn config_dir(app: &tauri::AppHandle) -> Result<PathBuf> {
    Ok(app.path().app_data_dir()?)
}

fn read_json(path: &PathBuf) -> Value {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Object(Default::default()))
}

fn write_json(path: &PathBuf, data: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(data)?)?;
    Ok(())
}

pub fn read_configs(app: &tauri::AppHandle) -> Result<Value> {
    let dir = config_dir(app)?;
    Ok(read_json(&dir.join("configs.json")))
}

pub fn write_configs(app: &tauri::AppHandle, data: &Value) -> Result<()> {
    let dir = config_dir(app)?;
    write_json(&dir.join("configs.json"), data)
}

pub fn read_prefs(app: &tauri::AppHandle) -> Result<Value> {
    let dir = config_dir(app)?;
    Ok(read_json(&dir.join("prefs.json")))
}

pub fn write_prefs(app: &tauri::AppHandle, data: &Value) -> Result<()> {
    let dir = config_dir(app)?;
    write_json(&dir.join("prefs.json"), data)
}

pub fn read_history(app: &tauri::AppHandle) -> Result<Value> {
    let dir = config_dir(app)?;
    let val = read_json(&dir.join("history.json"));
    Ok(if val.is_array() { val } else { Value::Array(vec![]) })
}

pub fn write_history(app: &tauri::AppHandle, data: &Value) -> Result<()> {
    let dir = config_dir(app)?;
    write_json(&dir.join("history.json"), data)
}
