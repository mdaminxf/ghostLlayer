use reqwest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatExplanation {
    pub original_log: String,
    pub user_friendly_explanation: String,
    pub risk_level: String,
    pub recommendations: Vec<String>,
}

pub struct Analyst {
    api_key: Option<String>,
    client: reqwest::Client,
}

impl Analyst {
    pub fn new() -> Self {
        Self {
            api_key: None,
            client: reqwest::Client::new(),
        }
    }
    
    pub fn set_api_key(&mut self, key: String) {
        self.api_key = Some(key);
    }
    
    /// Explain a security threat using Google Gemini AI
    pub async fn explain_threat(&self, log: String) -> Result<ThreatExplanation, Box<dyn std::error::Error>> {
        let api_key = self.api_key.as_ref()
            .ok_or("API key not set")?;
        
        let prompt = format!(
            r#"You are a cybersecurity expert explaining threats to non-technical users.

Analyze this security log and provide:
1. A simple, clear explanation of what happened (2-3 sentences)
2. The risk level (LOW, MEDIUM, HIGH, CRITICAL)
3. Three specific, actionable recommendations

Security Log:
{}

Respond in JSON format:
{{
  "explanation": "simple explanation here",
  "risk_level": "HIGH",
  "recommendations": ["action 1", "action 2", "action 3"]
}}"#,
            log
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
        
        let response = self.client
            .post(&url)
            .json(&request_body)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(format!("API error: {}", response.status()).into());
        }
        
        let gemini_response: GeminiResponse = response.json().await?;
        
        let ai_text = gemini_response
            .candidates
            .first()
            .and_then(|c| c.content.parts.first())
            .map(|p| p.text.clone())
            .ok_or("No response from AI")?;
        
        // Try to parse JSON response
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&ai_text);
        
        let explanation = match parsed {
            Ok(json) => ThreatExplanation {
                original_log: log.clone(),
                user_friendly_explanation: json["explanation"]
                    .as_str()
                    .unwrap_or("Unable to parse explanation")
                    .to_string(),
                risk_level: json["risk_level"]
                    .as_str()
                    .unwrap_or("UNKNOWN")
                    .to_string(),
                recommendations: json["recommendations"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_else(|| vec![
                        "Keep your system updated".to_string(),
                        "Run a full antivirus scan".to_string(),
                        "Monitor system behavior".to_string(),
                    ]),
            },
            Err(_) => {
                // Fallback if JSON parsing fails
                ThreatExplanation {
                    original_log: log.clone(),
                    user_friendly_explanation: ai_text,
                    risk_level: "MEDIUM".to_string(),
                    recommendations: vec![
                        "Review the security alert carefully".to_string(),
                        "Consider isolating affected files".to_string(),
                        "Consult with IT security if unsure".to_string(),
                    ],
                }
            }
        };
        
        Ok(explanation)
    }
    
    /// Quick threat assessment without AI (fallback)
    pub fn quick_assess(&self, threat_type: &str, entropy: Option<f64>) -> ThreatExplanation {
        let (explanation, risk, recommendations) = match threat_type {
            "High Entropy File" => (
                format!(
                    "A file with very high randomness (entropy: {:.2}) was detected. \
                    This is typical of encrypted or compressed malware trying to hide its true nature.",
                    entropy.unwrap_or(0.0)
                ),
                "HIGH",
                vec![
                    "Do not open or execute this file".to_string(),
                    "Scan the file with updated antivirus software".to_string(),
                    "Delete the file if it's not from a trusted source".to_string(),
                ],
            ),
            "Suspicious Process" => (
                "A process with a name matching known hacking tools was detected running on your system.".to_string(),
                "CRITICAL",
                vec![
                    "Terminate the process immediately".to_string(),
                    "Run a full system scan".to_string(),
                    "Change all passwords from a clean device".to_string(),
                ],
            ),
            _ => (
                "An unknown security event was detected.".to_string(),
                "MEDIUM",
                vec![
                    "Review system logs".to_string(),
                    "Monitor for unusual activity".to_string(),
                    "Keep security software updated".to_string(),
                ],
            ),
        };
        
        ThreatExplanation {
            original_log: format!("Threat Type: {}", threat_type),
            user_friendly_explanation: explanation,
            risk_level: risk.to_string(),
            recommendations,
        }
    }
}
