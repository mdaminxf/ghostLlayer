mod commands;
mod db;
mod sentinel;
mod whitelist;
mod engines;

#[cfg(test)]
mod test_migration;

use db::Database;
use std::sync::Arc;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use engines::sentinel::ProcessSentinel;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // Initialize database
            let app_dir = app.path().app_data_dir().expect("Failed to get app data dir");
            std::fs::create_dir_all(&app_dir).expect("Failed to create app directory");
            let db_path = app_dir.join("ghost_layer.db");
            let db = Arc::new(Database::new(db_path.to_str().unwrap()).expect("Failed to initialize database"));
            app.manage(db);
            
            // Initialize sandbox system
            let mut sentinel = ProcessSentinel::new();
            if let Err(e) = sentinel.initialize() {
                eprintln!("Failed to initialize sentinel: {}", e);
            }
            app.manage(Arc::new(sentinel));
            
            // Create main dashboard window
            let _main_window = WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::App("index.html".into())
            )
            .title("Ghost Layer - Security Console")
            .inner_size(1200.0, 800.0)
            .center()
            .build()
            .expect("Failed to create main window");
            
            // Create pet overlay window
            let _pet_window = WebviewWindowBuilder::new(
                app,
                "pet",
                WebviewUrl::App("index.html".into())
            )
            .title("Ghost Pet")
            .inner_size(200.0, 200.0)
            .decorations(false)
            .transparent(true)
            .always_on_top(true)
            .skip_taskbar(true)
            .build()
            .expect("Failed to create pet window");
            
            // Start sentinel services
            let app_handle = app.handle().clone();
            let app_dir_for_db = app_dir.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = sentinel::start_file_watcher(app_handle.clone()).await {
                    eprintln!("File watcher error: {}", e);
                }
                if let Err(e) = sentinel::start_process_monitor(app_handle.clone()).await {
                    eprintln!("Process monitor error: {}", e);
                }
                // Use proper database path from app directory
                let db_path = app_dir_for_db.join("ghost_layer.db");
                let db = Arc::new(Database::new(db_path.to_str().unwrap()).expect("Failed to initialize database"));
                if let Err(e) = engines::rce_detector::start_rce_detection_with_db(app_handle.clone(), db).await {
                    eprintln!("RCE detection error: {}", e);
                }
            });
            
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::kill_process,
            commands::get_logs,
            commands::add_to_whitelist,
            commands::get_whitelist,
            commands::remove_from_whitelist,
            commands::request_ai_explanation,
            commands::get_system_health,
            commands::check_file_hash,
            commands::add_trusted_app,
            commands::get_trusted_apps,
            commands::add_trusted_folder,
            commands::get_trusted_folders,
            commands::remove_trusted_folder,
            commands::migrate_process_to_sandbox,
            commands::get_sandbox_status,
            commands::update_process_risk_score,
            commands::handle_threat_decision,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
