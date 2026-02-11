use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;
use sysinfo::System;
use tauri::{AppHandle, Emitter};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub threat_type: String,
    pub severity: String,
    pub target: String,
    pub timestamp: String,
    pub entropy: Option<f64>,
    pub explanation: String,
}

/// Calculate Shannon Entropy for malware detection
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Monitor file system for suspicious activity
pub async fn start_file_watcher(app_handle: AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = channel();
    
    let mut watcher: RecommendedWatcher = Watcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        Config::default(),
    )?;
    
    // Watch the Ghost_Secrets directory
    let watch_path = PathBuf::from("C:\\Ghost_Secrets");
    if !watch_path.exists() {
        std::fs::create_dir_all(&watch_path)?;
    }
    
    watcher.watch(&watch_path, RecursiveMode::Recursive)?;
    
    tokio::spawn(async move {
        loop {
            if let Ok(event) = rx.recv() {
                if let Some(path) = event.paths.first() {
                    // Read file and check entropy
                    if let Ok(data) = std::fs::read(path) {
                        let entropy = calculate_entropy(&data);
                        
                        // High entropy suggests encryption/packing
                        if entropy > 7.5 {
                            let alert = ThreatAlert {
                                threat_type: "High Entropy File".to_string(),
                                severity: "HIGH".to_string(),
                                target: path.display().to_string(),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                entropy: Some(entropy),
                                explanation: format!(
                                    "Detected file with entropy {:.2}. May be encrypted or packed malware.",
                                    entropy
                                ),
                            };
                            
                            // Emit to all windows
                            let _ = app_handle.emit("threat-alert", &alert);
                            println!("Emitted threat-alert: {:?}", alert);
                        }
                    }
                }
            }
        }
    });
    
    // Keep watcher alive
    std::mem::forget(watcher);
    Ok(())
}

/// Monitor running processes for suspicious behavior
pub async fn start_process_monitor(app_handle: AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    tokio::spawn(async move {
        let mut sys = System::new_all();
        
        loop {
            sys.refresh_all();
            
            for (pid, process) in sys.processes() {
                let name = process.name().to_string_lossy().to_lowercase();
                
                // Whitelist legitimate Windows processes
                let whitelist = ["msfeedssync.exe", "svchost.exe", "explorer.exe", "system"];
                if whitelist.iter().any(|&safe| name.contains(safe)) {
                    continue;
                }
                
                // Detect suspicious process names
                let suspicious_keywords = ["mimikatz", "psexec", "netcat", "nc.exe", "meterpreter"];
                if suspicious_keywords.iter().any(|&kw| name.contains(kw)) {
                    let alert = ThreatAlert {
                        threat_type: "Suspicious Process".to_string(),
                        severity: "CRITICAL".to_string(),
                        target: format!("{} (PID: {})", process.name().to_string_lossy(), pid),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        entropy: None,
                        explanation: format!(
                            "Detected suspicious process: {}. This may be a hacking tool.",
                            process.name().to_string_lossy()
                        ),
                    };
                    
                    // Emit to all windows
                    let _ = app_handle.emit("threat-alert", &alert);
                    println!("Emitted threat-alert: {:?}", alert);
                }
            }
            
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    
    Ok(())
}
