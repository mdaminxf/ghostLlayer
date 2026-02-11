use crate::db::{Database, EventLog, WhitelistEntry};
use crate::engines::sandbox::{Sandbox, SandboxStatus};
use crate::engines::analyst::{Analyst, ThreatExplanation};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use sysinfo::{Pid, System};
use tauri::State;

#[derive(Debug, Serialize, Deserialize)]
pub struct AiExplanation {
    pub original_log: String,
    pub explanation: String,
    pub recommendations: Vec<String>,
}

#[tauri::command]
pub async fn kill_process(pid: u32) -> Result<String, String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    let pid = Pid::from_u32(pid);
    
    if let Some(process) = sys.process(pid) {
        if process.kill() {
            Ok(format!("Process {} terminated successfully", pid))
        } else {
            Err("Failed to terminate process".to_string())
        }
    } else {
        Err("Process not found".to_string())
    }
}

#[tauri::command]
pub async fn get_logs(db: State<'_, Arc<Database>>, limit: usize) -> Result<Vec<EventLog>, String> {
    db.get_recent_logs(limit)
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub async fn add_to_whitelist(
    db: State<'_, Arc<Database>>,
    process_name: String,
) -> Result<String, String> {
    db.add_to_whitelist(&process_name)
        .map_err(|e| format!("Database error: {}", e))?;
    Ok(format!("Added {} to whitelist", process_name))
}

#[tauri::command]
pub async fn get_whitelist(db: State<'_, Arc<Database>>) -> Result<Vec<WhitelistEntry>, String> {
    db.get_whitelist()
        .map_err(|e| format!("Database error: {}", e))
}

#[tauri::command]
pub async fn remove_from_whitelist(
    db: State<'_, Arc<Database>>,
    id: i64,
) -> Result<String, String> {
    db.remove_from_whitelist(id)
        .map_err(|e| format!("Database error: {}", e))?;
    Ok("Removed from whitelist".to_string())
}

#[tauri::command]
pub async fn request_ai_explanation(
    api_key: String,
    log_text: String,
) -> Result<AiExplanation, String> {
    let client = reqwest::Client::new();
    
    let prompt = format!(
        "You are a cybersecurity expert explaining threats to non-technical users. \
        Analyze this security log and provide:\n\
        1. A simple explanation of what happened\n\
        2. Why it's dangerous\n\
        3. Three actionable recommendations\n\n\
        Log: {}\n\n\
        Respond in JSON format with fields: explanation (string), recommendations (array of strings)",
        log_text
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
    
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={}",
        api_key
    );
    
    let response = client
        .post(&url)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("API error: {}", response.status()));
    }
    
    let gemini_response: GeminiResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    let ai_text = gemini_response
        .candidates
        .first()
        .and_then(|c| c.content.parts.first())
        .map(|p| p.text.clone())
        .ok_or("No response from AI")?;
    
    // Parse the AI response (simplified - in production, use proper JSON parsing)
    Ok(AiExplanation {
        original_log: log_text,
        explanation: ai_text.clone(),
        recommendations: vec![
            "Keep your antivirus updated".to_string(),
            "Avoid downloading files from untrusted sources".to_string(),
            "Enable Windows Defender real-time protection".to_string(),
        ],
    })
}

#[tauri::command]
pub async fn get_system_health() -> Result<SystemHealth, String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    Ok(SystemHealth {
        total_processes: sys.processes().len(),
        cpu_usage: sys.global_cpu_usage() as f64,
        memory_used_gb: sys.used_memory() as f64 / 1_073_741_824.0,
        memory_total_gb: sys.total_memory() as f64 / 1_073_741_824.0,
    })
}

#[derive(Debug, Serialize)]
pub struct SystemHealth {
    pub total_processes: usize,
    pub cpu_usage: f64,
    pub memory_used_gb: f64,
    pub memory_total_gb: f64,
}

// ============================================================================
// SANDBOX COMMANDS
// ============================================================================

#[tauri::command]
pub async fn purge_ghost_layer(
    sandbox: State<'_, Arc<Mutex<Sandbox>>>,
) -> Result<String, String> {
    let mut sandbox = sandbox.lock().map_err(|e| format!("Lock error: {}", e))?;
    sandbox.purge_session()
        .map_err(|e| format!("Failed to purge session: {}", e))?;
    Ok("Ghost Layer purged successfully. All session data has been erased.".to_string())
}

#[tauri::command]
pub async fn get_sandbox_status(
    sandbox: State<'_, Arc<Mutex<Sandbox>>>,
) -> Result<SandboxStatus, String> {
    let sandbox = sandbox.lock().map_err(|e| format!("Lock error: {}", e))?;
    Ok(sandbox.get_status())
}

#[tauri::command]
pub async fn mount_ghost_layer(
    sandbox: State<'_, Arc<Mutex<Sandbox>>>,
) -> Result<String, String> {
    let mut sandbox = sandbox.lock().map_err(|e| format!("Lock error: {}", e))?;
    sandbox.mount_ghost_layer()
        .map_err(|e| format!("Failed to mount: {}", e))
}

// ============================================================================
// ANALYST COMMANDS
// ============================================================================

#[tauri::command]
pub async fn get_ai_explanation(
    analyst: State<'_, Arc<Mutex<Analyst>>>,
    api_key: String,
    log_text: String,
) -> Result<ThreatExplanation, String> {
    let mut analyst = analyst.lock().map_err(|e| format!("Lock error: {}", e))?;
    analyst.set_api_key(api_key);
    
    analyst.explain_threat(log_text)
        .await
        .map_err(|e| format!("AI analysis failed: {}", e))
}
