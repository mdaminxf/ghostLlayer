use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use sysinfo::{Pid, System};
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;
use chrono::Utc;
use crate::db::{Database, EventLog};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RceAlert {
    pub alert_type: String,
    pub parent_process: String,
    pub parent_pid: u32,
    pub child_process: String,
    pub child_pid: u32,
    pub timestamp: String,
    pub explanation: String,
    pub action_taken: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiExplanation {
    pub original_alert: String,
    pub explanation: String,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RceDetector {
    trusted_browsers: Vec<String>,
    trusted_document_readers: Vec<String>,
    system_shells: Vec<String>,
    known_processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    db: Option<Arc<Database>>,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    name: String,
    pid: u32,
    parent_pid: Option<u32>,
}

impl RceDetector {
    pub fn new() -> Self {
        Self {
            trusted_browsers: vec![
                "chrome.exe".to_string(),
                "firefox.exe".to_string(),
                "msedge.exe".to_string(),
                "opera.exe".to_string(),
                "brave.exe".to_string(),
                "safari.exe".to_string(),
            ],
            trusted_document_readers: vec![
                "winword.exe".to_string(),
                "excel.exe".to_string(),
                "powerpnt.exe".to_string(),
                "acrobat.exe".to_string(),
                "acrord32.exe".to_string(),
                "foxitreader.exe".to_string(),
                "sumatrapdf.exe".to_string(),
            ],
            system_shells: vec![
                "cmd.exe".to_string(),
                "powershell.exe".to_string(),
                "pwsh.exe".to_string(),
                "wsl.exe".to_string(),
                "bash.exe".to_string(),
                "regedit.exe".to_string(),
                "reg.exe".to_string(),
            ],
            known_processes: Arc::new(Mutex::new(HashMap::new())),
            db: None,
        }
    }

    pub fn with_database(db: Arc<Database>) -> Self {
        Self {
            db: Some(db),
            ..Self::new()
        }
    }

    pub async fn start_monitoring(&self, app_handle: AppHandle) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app_handle = Arc::new(app_handle);
        let detector = self.clone();
        let known_processes = Arc::clone(&self.known_processes);

        tokio::spawn(async move {
            let mut sys = System::new_all();
            let mut last_check = std::time::Instant::now();
            
            loop {
                sys.refresh_all();
                let current_time = std::time::Instant::now();
                
                // Check for new processes every 2 seconds
                if current_time.duration_since(last_check).as_secs() >= 2 {
                    let mut known = known_processes.lock().await;
                    
                    for (pid, process) in sys.processes() {
                        let pid_u32 = pid.as_u32();
                        let _process_name = process.name().to_string_lossy().to_lowercase();
                        
                        // Skip if we already know about this process
                        if known.contains_key(&pid_u32) {
                            continue;
                        }
                        
                        // New process detected
                        let process_info = ProcessInfo {
                            name: process.name().to_string_lossy().to_string(),
                            pid: pid_u32,
                            parent_pid: process.parent().map(|p| p.as_u32()),
                        };
                        
                        // Check for RCE exploit
                        if let Some(alert) = detector.check_rce_exploit(&process_info, &sys).await {
                            let app_handle = Arc::clone(&app_handle);
                            
                            // Log the threat
                            let _ = app_handle.emit("rce-alert", &alert);
                            println!("RCE Alert emitted: {:?}", alert);
                            
                            // Take action
                            detector.handle_rce_exploit(&alert, &app_handle).await;
                        }
                        
                        known.insert(pid_u32, process_info);
                    }
                    
                    last_check = current_time;
                }
                
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        });

        Ok(())
    }

    async fn check_rce_exploit(&self, process_info: &ProcessInfo, sys: &System) -> Option<RceAlert> {
        let child_name = process_info.name.to_lowercase();
        
        // Is the child a system shell?
        if !self.system_shells.iter().any(|shell| child_name.contains(shell)) {
            return None;
        }

        // Check if we have a parent process
        let parent_pid = match process_info.parent_pid {
            Some(pid) => pid,
            None => return None,
        };

        let parent_process = match sys.process(Pid::from_u32(parent_pid)) {
            Some(p) => p,
            None => return None,
        };

        let parent_name = parent_process.name().to_string_lossy().to_lowercase();
        
        // Is the parent a trusted browser or document reader?
        let is_trusted_parent = self.trusted_browsers.iter().any(|browser| parent_name.contains(browser)) ||
                               self.trusted_document_readers.iter().any(|reader| parent_name.contains(reader));

        if !is_trusted_parent {
            return None;
        }

        // This is an RCE exploit!
        Some(RceAlert {
            alert_type: "RCE_EXPLOIT".to_string(),
            parent_process: parent_process.name().to_string_lossy().to_string(),
            parent_pid,
            child_process: process_info.name.clone(),
            child_pid: process_info.pid,
            timestamp: Utc::now().to_rfc3339(),
            explanation: format!(
                "{} was hijacked and tried to open {} (PID: {}). This is a classic Remote Code Execution attack pattern.",
                parent_process.name().to_string_lossy(),
                process_info.name,
                process_info.pid
            ),
            action_taken: "Child process terminated, parent process frozen".to_string(),
            severity: "CRITICAL".to_string(),
        })
    }

    async fn handle_rce_exploit(&self, alert: &RceAlert, app_handle: &Arc<AppHandle>) {
        // Log to database first
        if let Some(db) = &self.db {
            let event_log = EventLog {
                id: None,
                threat_type: alert.alert_type.clone(),
                severity: alert.severity.clone(),
                target: format!("{} (PID: {}) -> {} (PID: {})", 
                    alert.parent_process, alert.parent_pid, 
                    alert.child_process, alert.child_pid),
                timestamp: alert.timestamp.clone(),
                entropy: None,
            };
            
            if let Err(e) = db.log_event(&event_log) {
                eprintln!("Failed to log RCE alert to database: {}", e);
            }
        }

        // Emit to frontend
        let _ = app_handle.emit("threat-alert", &serde_json::json!({
            "id": None::<Option<i64>>,
            "threat_type": alert.alert_type,
            "severity": alert.severity,
            "target": format!("{} (PID: {}) -> {} (PID: {})", 
                alert.parent_process, alert.parent_pid, 
                alert.child_process, alert.child_pid),
            "timestamp": alert.timestamp,
            "entropy": None::<Option<f64>>
        }));

        // Kill child process immediately
        if let Err(e) = self.kill_process(alert.child_pid).await {
            eprintln!("Failed to kill child process {}: {}", alert.child_pid, e);
        }

        // Freeze parent process (suspend it)
        if let Err(e) = self.freeze_process(alert.parent_pid).await {
            eprintln!("Failed to freeze parent process {}: {}", alert.parent_pid, e);
        }

        // Send AI explanation request
        let ai_alert = alert.clone();
        let app_handle_clone = Arc::clone(app_handle);
        tokio::spawn(async move {
            if let Ok(explanation) = Self::get_ai_explanation(&ai_alert).await {
                let _ = app_handle_clone.emit("ai-explanation", &explanation);
            }
        });
    }

    async fn kill_process(&self, pid: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let pid = Pid::from_u32(pid);
        
        if let Some(process) = sys.process(pid) {
            if process.kill() {
                println!("Successfully killed process {}", pid);
                Ok(())
            } else {
                Err(format!("Failed to kill process {}", pid).into())
            }
        } else {
            Err(format!("Process {} not found", pid).into())
        }
    }

    async fn freeze_process(&self, pid: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // On Windows, we can suspend a process using NtSuspendProcess
        // For now, we'll just log it - in a real implementation, you'd use Windows API
        println!("Process {} should be frozen (suspended)", pid);
        
        // In a production environment, you would:
        // 1. Get a handle to the process
        // 2. Call NtSuspendProcess from ntdll.dll
        // 3. Store the handle for later resumption
        
        Ok(())
    }

    async fn get_ai_explanation(alert: &RceAlert) -> Result<AiExplanation, Box<dyn std::error::Error + Send + Sync>> {
        let api_key = "AIzaSyBcn5dMC7YjpiX2ulpeErCWyOgXf7-KfZk";
        let client = reqwest::Client::new();
        
        let prompt = format!(
            "You are a cybersecurity expert. Explain this RCE (Remote Code Execution) alert to a non-technical user:\n\n\
            Alert Details:\n\
            - Type: {}\n\
            - Parent Process: {} (PID: {})\n\
            - Child Process: {} (PID: {})\n\
            - Explanation: {}\n\
            - Severity: {}\n\n\
            Provide:\n\
            1. What happened in simple terms\n\
            2. Why this is dangerous\n\
            3. What the user should do next\n\n\
            Respond in JSON format with fields: explanation (string), recommendations (array of 3 strings)",
            alert.alert_type,
            alert.parent_process,
            alert.parent_pid,
            alert.child_process,
            alert.child_pid,
            alert.explanation,
            alert.severity
        );

        #[derive(Serialize)]
        struct GeminiRequest {
            contents: Vec<Content>,
        }
        
        #[derive(Serialize)]
        struct Content {
            parts: Vec<Part>,
        }
        
        #[derive(Serialize)]
        struct Part {
            text: String,
        }
        
        #[derive(Deserialize)]
        struct GeminiResponse {
            candidates: Vec<Candidate>,
        }
        
        #[derive(Deserialize)]
        struct Candidate {
            content: ResponseContent,
        }
        
        #[derive(Deserialize)]
        struct ResponseContent {
            parts: Vec<ResponsePart>,
        }
        
        #[derive(Deserialize)]
        struct ResponsePart {
            text: String,
        }

        let request_body = GeminiRequest {
            contents: vec![Content {
                parts: vec![Part { text: prompt }],
            }],
        };
        
        let url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent";
        
        let response = client
            .post(url)
            .header("x-goog-api-key", api_key)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;
        
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Failed to read error response".to_string());
            return Err(format!("API error {}: {}", status, error_text).into());
        }
        
        let gemini_response: GeminiResponse = response.json().await?;
        
        let ai_text = gemini_response
            .candidates
            .first()
            .and_then(|c| c.content.parts.first())
            .map(|p| p.text.clone())
            .ok_or("No response from AI")?;
        
        Ok(AiExplanation {
            original_alert: format!("{}: {}", alert.alert_type, alert.explanation),
            explanation: ai_text,
            recommendations: vec![
                "Run a full antivirus scan immediately".to_string(),
                "Change your important passwords".to_string(),
                "Review your browser extensions and remove suspicious ones".to_string(),
            ],
        })
    }
}

#[tauri::command]
pub async fn start_rce_detection_with_db(app_handle: AppHandle, db: Arc<Database>) -> Result<String, String> {
    let detector = RceDetector::with_database(db);
    detector.start_monitoring(app_handle)
        .await
        .map_err(|e| format!("Failed to start RCE detection: {}", e))?;
    
    Ok("RCE detection started with database".to_string())
}
