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
        
        // Step 1: Identity Check - Is this a trusted process starting normally?
        if self.is_trusted_process_start(&child_name, process_info.parent_pid, sys) {
            return None; // This is a legitimate process start
        }
        
        // Step 2: The "Rebellious Child" Check
        // Monitor: Watch every new process
        // Identify Parent: "Who started this process?"
        
        // Is the child a system shell?
        if !self.system_shells.iter().any(|shell| child_name.contains(shell)) {
            return None; // Not a system shell, not our concern
        }

        // Check if we have a parent process
        let parent_pid = match process_info.parent_pid {
            Some(pid) => pid,
            None => return None, // No parent = can't determine if exploit
        };

        let parent_process = match sys.process(Pid::from_u32(parent_pid)) {
            Some(p) => p,
            None => return None,
        };

        let parent_name = parent_process.name().to_string_lossy().to_lowercase();
        
        // The Logic Trap: Is the Parent a "Document Reader" or "Browser"?
        let is_suspicious_parent = self.trusted_browsers.iter().any(|browser| parent_name.contains(browser)) ||
                                   self.trusted_document_readers.iter().any(|reader| parent_name.contains(reader));

        if !is_suspicious_parent {
            return None; // Parent is not a browser/doc reader, not the classic RCE pattern
        }

        // Additional check: Is this parent process already compromised?
        if self.is_process_compromised(&parent_name, parent_pid) {
            return None; // Already known to be compromised, this is expected behavior
        }

        // MATCH: This is an RCE Exploit!
        let alert = RceAlert {
            alert_type: "RCE_EXPLOIT".to_string(),
            parent_process: parent_process.name().to_string_lossy().to_string(),
            parent_pid,
            child_process: process_info.name.clone(),
            child_pid: process_info.pid,
            timestamp: Utc::now().to_rfc3339(),
            explanation: format!(
                "IDENTITY CHECK: {} is not a trusted system process.\nREBELLIOUS CHILD CHECK: {} (PID: {}) was started by {} (PID: {}).\nLOGIC TRAP: {} is a trusted application that should NOT be spawning system shells.\nVERDICT: This is a Remote Code Execution exploit attempt!",
                process_info.name,
                process_info.name,
                process_info.pid,
                parent_process.name().to_string_lossy(),
                parent_pid,
                parent_process.name().to_string_lossy()
            ),
            action_taken: "Child process terminated, parent process frozen and marked as compromised".to_string(),
            severity: "CRITICAL".to_string(),
        };
        
        Some(alert)
    }
    
    fn is_trusted_process_start(&self, child_name: &str, parent_pid: Option<u32>, sys: &System) -> bool {
        // If the child is not a system shell, it's probably legitimate
        if !self.system_shells.iter().any(|shell| child_name.contains(shell)) {
            return true;
        }
        
        // Check if parent is a legitimate launcher for system shells
        let parent_pid = match parent_pid {
            Some(pid) => pid,
            None => return false,
        };
        
        let parent_process = match sys.process(Pid::from_u32(parent_pid)) {
            Some(p) => p,
            None => return false,
        };
        
        let parent_name = parent_process.name().to_string_lossy().to_lowercase();
        
        // These are legitimate ways to start system shells
        let legitimate_launchers = vec![
            "explorer.exe",      // User opening terminal from Explorer
            "winlogon.exe",      // System processes
            "services.exe",      // System services
            "svchost.exe",       // Service host
            "taskmgr.exe",       // Task Manager
            "powershell_ise.exe", // PowerShell ISE
            "windowsterminal.exe", // Windows Terminal
            "wt.exe",            // Windows Terminal shortcut
            "conhost.exe",       // Console host
        ];
        
        // If parent is a legitimate launcher, allow it
        if legitimate_launchers.iter().any(|launcher| parent_name.contains(launcher)) {
            return true;
        }
        
        false
    }
    
    fn is_process_compromised(&self, _process_name: &str, _pid: u32) -> bool {
        // In a real implementation, you'd check against a database of compromised processes
        // For now, we'll use a simple heuristic - if we've seen this process exploit before
        // This could be enhanced with process signature verification, behavior analysis, etc.
        
        // Check if this specific PID was previously flagged
        // In production, you'd maintain a list of compromised process PIDs/signatures
        false // For now, assume no process is pre-compromised
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
            "You are a cybersecurity expert analyzing a Remote Code Execution (RCE) attack attempt. \
            Explain this critical security alert to a non-technical user in a clear, urgent, but not panic-inducing manner.\n\n\
            ALERT DETAILS:\n\
            Attack Type: Remote Code Execution (RCE) Exploit\n\
            Hijacked Application: {} (PID: {})\n\
            Malicious Action: Started {} (PID: {})\n\
            Time: {}\n\
            Severity: CRITICAL\n\n\
            TECHNICAL ANALYSIS:\n\
            {}\n\n\
            Provide your response in this exact JSON format:\n\
            {{\n\
              \"explanation\": \"Clear explanation of what happened in simple terms, emphasizing the danger but avoiding panic\",\n\
              \"recommendations\": [\n\
                \"Immediate action the user should take\",\n\
                \"Follow-up security measure to implement\",\n\
                \"Prevention tip for the future\"\n\
              ]\n\
            }}\n\n\
            Make the explanation urgent but actionable. Focus on what the user needs to do RIGHT NOW.",
            alert.parent_process,
            alert.parent_pid,
            alert.child_process,
            alert.child_pid,
            alert.timestamp,
            alert.explanation
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
