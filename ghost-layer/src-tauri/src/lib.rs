mod commands;
mod db;
mod sentinel;
mod engines;

use db::Database;
use engines::sandbox::Sandbox;
use engines::analyst::Analyst;
use std::sync::{Arc, Mutex};
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

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
            
            // Initialize sandbox
            let mut sandbox = Sandbox::new().expect("Failed to initialize sandbox");
            if let Err(e) = sandbox.create_ephemeral_disk() {
                eprintln!("Warning: Failed to create ephemeral disk: {}", e);
            }
            app.manage(Arc::new(Mutex::new(sandbox)));
            
            // Initialize analyst
            let analyst = Analyst::new();
            app.manage(Arc::new(Mutex::new(analyst)));
            
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
            tauri::async_runtime::spawn(async move {
                if let Err(e) = sentinel::start_file_watcher(app_handle.clone()).await {
                    eprintln!("File watcher error: {}", e);
                }
                if let Err(e) = sentinel::start_process_monitor(app_handle.clone()).await {
                    eprintln!("Process monitor error: {}", e);
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
            commands::purge_ghost_layer,
            commands::get_sandbox_status,
            commands::mount_ghost_layer,
            commands::get_ai_explanation,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
