import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

interface EventLog {
  id?: number;
  threat_type: string;
  severity: string;
  target: string;
  timestamp: string;
  entropy?: number;
}

interface SystemHealth {
  total_processes: number;
  cpu_usage: number;
  memory_used_gb: number;
  memory_total_gb: number;
}

interface WhitelistEntry {
  id?: number;
  process_name: string;
  added_at: string;
}

interface AiExplanation {
  original_log: string;
  explanation: string;
  recommendations: string[];
}

function Dashboard() {
  const [logs, setLogs] = useState<EventLog[]>([]);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
  const [newProcess, setNewProcess] = useState("");


  
  


  const [aiExplanation, setAiExplanation] = useState<AiExplanation | null>(null);
  const [showAiModal, setShowAiModal] = useState(false);

  useEffect(() => {
    loadLogs();
    loadHealth();
    loadWhitelist();

    const interval = setInterval(() => {
      loadHealth();
    }, 5000);

    const currentWindow = getCurrentWebviewWindow();
    const unlisten = currentWindow.listen("threat-alert", (event: any) => {
      const alert = event.payload;
      setLogs((prev) => [alert, ...prev]);
    });

    return () => {
      clearInterval(interval);
      unlisten.then((fn) => fn());
    };
  }, []);

  const loadLogs = async () => {
    try {
      const result = await invoke<EventLog[]>("get_logs", { limit: 50 });
      setLogs(result);
    } catch (error) {
      console.error("Failed to load logs:", error);
    }
  };

  const loadHealth = async () => {
    try {
      const result = await invoke<SystemHealth>("get_system_health");
      setHealth(result);
    } catch (error) {
      console.error("Failed to load health:", error);
    }
  };

  const loadWhitelist = async () => {
    console.log("Loading whitelist...");
    try {
      const result = await invoke<WhitelistEntry[]>("get_whitelist");
      console.log("Whitelist loaded:", result);
      console.log("Number of whitelist entries:", result.length);
      if (result.length > 0) {
        console.log("First entry:", result[0]);
      }
      setWhitelist(result);
    } catch (error) {
      console.error("Failed to load whitelist:", error);
    }
  };

  const addToWhitelist = async () => {
    console.log("addToWhitelist called, newProcess:", `"${newProcess}"`);
    console.log("newProcess.trim() length:", newProcess.trim().length);
    
    if (!newProcess.trim()) {
      console.log("Empty process name, skipping");
      return;
    }
    console.log("Adding to whitelist:", newProcess);
    try {
      const result = await invoke("add_to_whitelist", { processName: newProcess });
      console.log("Add result:", result);
      setNewProcess("");
      loadWhitelist();
    } catch (error) {
      console.error("Failed to add to whitelist:", error);
      alert(`Failed to add to whitelist: ${error}`);
    }
  };

  const removeFromWhitelist = async (id: number, processName: string) => {
    console.log("Removing from whitelist:", id, processName);
    try {
      const result = await invoke("remove_from_whitelist", { id, processName });
      console.log("Remove result:", result);
      loadWhitelist();
    } catch (error) {
      console.error("Failed to remove from whitelist:", error);
      alert(`Failed to remove from whitelist: ${error}`);
    }
  };

  const explainThreat = async (log: EventLog) => {
    try {
      const result = await invoke("request_ai_explanation", {
        logText: JSON.stringify(log),
      });
      setAiExplanation(result as AiExplanation);
      setShowAiModal(true);
    } catch (error) {
      console.error("Failed to get AI explanation:", error);
      alert("Failed to get AI explanation. Check console for details.");
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "text-red-500";
      case "HIGH":
        return "text-orange-500";
      case "MEDIUM":
        return "text-yellow-500";
      default:
        return "text-blue-500";
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-6">
      <header className="mb-8">
        <h1 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-600">
          Ghost Layer Security Console
        </h1>
        <p className="text-gray-400 mt-2">Industrial-grade threat detection and isolation</p>
      </header>

      {/* System Health */}
      {health && (
        <div className="grid grid-cols-4 gap-4 mb-8">
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="text-gray-400 text-sm mb-1">Active Processes</div>
            <div className="text-2xl font-bold text-blue-400">{health.total_processes}</div>
            <div className="text-xs text-gray-500 mt-1">Running applications</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="text-gray-400 text-sm mb-1">CPU Usage</div>
            <div className={`text-2xl font-bold ${health.cpu_usage > 80 ? 'text-red-400' : health.cpu_usage > 50 ? 'text-yellow-400' : 'text-green-400'}`}>
              {health.cpu_usage.toFixed(1)}%
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {health.cpu_usage > 80 ? 'High load' : health.cpu_usage > 50 ? 'Moderate load' : 'Normal'}
            </div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="text-gray-400 text-sm mb-1">Memory Usage</div>
            <div className={`text-2xl font-bold ${(health.memory_used_gb / health.memory_total_gb) > 0.8 ? 'text-red-400' : (health.memory_used_gb / health.memory_total_gb) > 0.6 ? 'text-yellow-400' : 'text-green-400'}`}>
              {health.memory_used_gb.toFixed(1)} / {health.memory_total_gb.toFixed(1)} GB
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {((health.memory_used_gb / health.memory_total_gb) * 100).toFixed(1)}% utilized
            </div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="text-gray-400 text-sm mb-1">Threats Detected</div>
            <div className={`text-2xl font-bold ${logs.length > 0 ? 'text-red-500' : 'text-green-400'}`}>
              {logs.length}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {logs.length > 0 ? `${logs.length} security events` : 'System secure'}
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-6">
        {/* Threat Logs */}
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h2 className="text-xl font-bold mb-4">Threat Logs</h2>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {logs.length === 0 ? (
              <div className="text-center text-gray-500 py-8">
                <div className="text-lg mb-2">No Threats Detected</div>
                <div className="text-sm">System is running smoothly with no security threats detected.</div>
              </div>
            ) : (
              logs.map((log, idx) => (
                <div key={idx} className="bg-gray-700 rounded p-4 border border-gray-600 hover:border-gray-500 transition-colors">
                  <div className="flex justify-between items-start mb-3">
                    <div className="flex items-center gap-2">
                      <span className={`font-bold text-lg ${getSeverityColor(log.severity)}`}>
                        {log.severity}
                      </span>
                      {log.threat_type.toLowerCase().includes('rce') && (
                        <span className="bg-red-600 text-white text-xs px-2 py-1 rounded-full font-semibold">
                          RCE
                        </span>
                      )}
                    </div>
                    <span className="text-xs text-gray-400">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                  </div>
                  
                  <div className="mb-2">
                    <div className="text-sm font-semibold text-blue-400 mb-1">Threat Type:</div>
                    <div className="text-sm text-gray-200">{log.threat_type}</div>
                  </div>
                  
                  <div className="mb-2">
                    <div className="text-sm font-semibold text-yellow-400 mb-1">Target:</div>
                    <div className="text-xs text-gray-300 font-mono bg-gray-800 px-2 py-1 rounded">
                      {log.target}
                    </div>
                  </div>
                  
                  {log.entropy && (
                    <div className="mb-3">
                      <div className="text-xs text-purple-400">
                        <span className="font-semibold">Entropy:</span> {log.entropy.toFixed(2)}
                        {log.entropy > 7.0 && (
                          <span className="ml-2 text-orange-400">(High - Suspicious)</span>
                        )}
                      </div>
                    </div>
                  )}
                  
                  <div className="flex gap-2 mt-3">
                    <button
                      onClick={() => explainThreat(log)}
                      className="text-xs bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded transition-colors"
                    >
                      AI Explain
                    </button>
                    {log.threat_type.toLowerCase().includes('rce') && (
                      <div className="text-xs bg-red-900 bg-opacity-50 px-2 py-1 rounded text-red-300">
                        Remote Code Execution Attempt
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Whitelist */}
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h2 className="text-xl font-bold mb-4">Process Whitelist</h2>
          <div className="mb-4 p-3 bg-gray-700 rounded border border-gray-600">
            <div className="text-sm text-gray-300 mb-2">
              <strong>Trusted Applications:</strong> {whitelist.length} processes whitelisted
            </div>
            <div className="text-xs text-gray-400">
              Whitelisted processes are allowed to run without triggering security alerts
            </div>
          </div>
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              placeholder="Process name (e.g., chrome.exe)"
              value={newProcess}
              onChange={(e) => setNewProcess(e.target.value)}
              className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2"
              onKeyPress={(e) => e.key === 'Enter' && addToWhitelist()}
            />
            <button
              onClick={() => {
                console.log("Add button clicked!");
                addToWhitelist();
              }}
              className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded font-medium transition-colors"
            >
              Add
            </button>
          </div>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {whitelist.length === 0 ? (
              <div className="text-center text-gray-500 py-6">
                <div className="text-sm">No whitelisted processes</div>
                <div className="text-xs mt-1">Add trusted applications to prevent false positives</div>
              </div>
            ) : (
              whitelist.map((entry) => (
                <div
                  key={entry.id}
                  className="bg-gray-700 rounded p-3 border border-gray-600 flex justify-between items-center hover:border-gray-500 transition-colors"
                >
                  <div className="flex-1">
                    <div className="font-medium text-green-400">{entry.process_name}</div>
                    <div className="text-xs text-gray-400">
                      Added: {new Date(entry.added_at).toLocaleString()}
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      console.log("Remove button clicked for:", entry.id, entry.process_name);
                      entry.id && removeFromWhitelist(entry.id, entry.process_name);
                    }}
                    className="text-red-400 hover:text-red-300 text-sm hover:bg-red-900 hover:bg-opacity-30 px-2 py-1 rounded transition-colors"
                  >
                    Remove
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* AI Explanation Modal */}
      {showAiModal && aiExplanation && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-3xl max-h-[85vh] overflow-y-auto border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-6 border-b border-gray-700 pb-4">
              <div>
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  AI Threat Analysis
                </h3>
                <p className="text-sm text-gray-400 mt-1">Powered by Google Gemini AI</p>
              </div>
              <button
                onClick={() => setShowAiModal(false)}
                className="text-gray-400 hover:text-white text-xl hover:bg-gray-700 w-8 h-8 rounded-full flex items-center justify-center transition-colors"
              >
                ×
              </button>
            </div>
            
            <div className="space-y-6">
              <div>
                <h4 className="font-semibold text-blue-400 mb-3 flex items-center gap-2">
                  Original Security Log:
                </h4>
                <pre className="bg-gray-900 p-4 rounded text-sm text-gray-300 overflow-x-auto border border-gray-700">
                  {aiExplanation.original_log}
                </pre>
              </div>
              
              <div>
                <h4 className="font-semibold text-green-400 mb-3 flex items-center gap-2">
                  AI Analysis & Explanation:
                </h4>
                <div className="bg-gray-900 p-4 rounded text-sm text-gray-300 whitespace-pre-wrap border border-gray-700 leading-relaxed">
                  {aiExplanation.explanation}
                </div>
              </div>
              
              <div>
                <h4 className="font-semibold text-yellow-400 mb-3 flex items-center gap-2">
                  Security Recommendations:
                </h4>
                <div className="bg-gray-900 p-4 rounded border border-gray-700">
                  <ul className="space-y-3">
                    {aiExplanation.recommendations.map((rec, index) => (
                      <li key={index} className="text-sm text-gray-300 flex items-start gap-3">
                        <span className="text-yellow-400 font-bold mt-0.5">{index + 1}.</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
              
              <div className="pt-4 border-t border-gray-700">
                <div className="flex items-center justify-between">
                  <div className="text-xs text-gray-500">
                    This AI analysis is for informational purposes. Always verify threats through multiple security layers.
                  </div>
                  <button
                    onClick={() => setShowAiModal(false)}
                    className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded text-sm font-medium transition-colors"
                  >
                    Close Analysis
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
