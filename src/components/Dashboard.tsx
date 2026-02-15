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


  
  // here to put our api key


  const [apiKey, setApiKey] = useState("");



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
    if (!apiKey.trim()) {
      alert("Please enter your Google Gemini API key");
      return;
    }
    try {
      const result = await invoke("request_ai_explanation", {
        apiKey,
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
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="text-gray-400 text-sm">Processes</div>
            <div className="text-2xl font-bold">{health.total_processes}</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="text-gray-400 text-sm">CPU Usage</div>
            <div className="text-2xl font-bold">{health.cpu_usage.toFixed(1)}%</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="text-gray-400 text-sm">Memory</div>
            <div className="text-2xl font-bold">
              {health.memory_used_gb.toFixed(1)} / {health.memory_total_gb.toFixed(1)} GB
            </div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="text-gray-400 text-sm">Threats Detected</div>
            <div className="text-2xl font-bold text-red-500">{logs.length}</div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-6">
        {/* Threat Logs */}
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h2 className="text-xl font-bold mb-4">Threat Logs</h2>
          <div className="mb-4">
            <input
              type="password"
              placeholder="Gemini API Key (pre-filled, optional)"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
            />
          </div>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {logs.map((log, idx) => (
              <div key={idx} className="bg-gray-700 rounded p-3 border border-gray-600">
                <div className="flex justify-between items-start mb-2">
                  <span className={`font-bold ${getSeverityColor(log.severity)}`}>
                    {log.severity}
                  </span>
                  <span className="text-xs text-gray-400">
                    {new Date(log.timestamp).toLocaleString()}
                  </span>
                </div>
                <div className="text-sm mb-1">{log.threat_type}</div>
                <div className="text-xs text-gray-400 mb-2">{log.target}</div>
                {log.entropy && (
                  <div className="text-xs text-purple-400">Entropy: {log.entropy.toFixed(2)}</div>
                )}
                <button
                  onClick={() => explainThreat(log)}
                  className="mt-2 text-xs bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded"
                >
                  AI Explain
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Whitelist */}
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h2 className="text-xl font-bold mb-4">Process Whitelist</h2>
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              placeholder="Process name (e.g., chrome.exe)"
              value={newProcess}
              onChange={(e) => setNewProcess(e.target.value)}
              className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2"
            />
            <button
              onClick={() => {
                console.log("Add button clicked!");
                addToWhitelist();
              }}
              className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded font-medium"
            >
              Add
            </button>
          </div>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {whitelist.map((entry) => (
              <div
                key={entry.id}
                className="bg-gray-700 rounded p-3 border border-gray-600 flex justify-between items-center"
              >
                <div>
                  <div className="font-medium">{entry.process_name}</div>
                  <div className="text-xs text-gray-400">
                    Added: {new Date(entry.added_at).toLocaleString()}
                  </div>
                </div>
                <button
                  onClick={() => {
                    console.log("Remove button clicked for:", entry.id, entry.process_name);
                    entry.id && removeFromWhitelist(entry.id, entry.process_name);
                  }}
                  className="text-red-400 hover:text-red-300 text-sm"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* AI Explanation Modal */}
      {showAiModal && aiExplanation && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-2xl max-h-[80vh] overflow-y-auto border border-gray-700">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold text-white">AI Threat Explanation</h3>
              <button
                onClick={() => setShowAiModal(false)}
                className="text-gray-400 hover:text-white text-xl"
              >
                ×
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <h4 className="font-semibold text-blue-400 mb-2">Original Log:</h4>
                <pre className="bg-gray-900 p-3 rounded text-sm text-gray-300 overflow-x-auto">
                  {aiExplanation.original_log}
                </pre>
              </div>
              
              <div>
                <h4 className="font-semibold text-green-400 mb-2">AI Explanation:</h4>
                <div className="bg-gray-900 p-3 rounded text-sm text-gray-300 whitespace-pre-wrap">
                  {aiExplanation.explanation}
                </div>
              </div>
              
              <div>
                <h4 className="font-semibold text-yellow-400 mb-2">Recommendations:</h4>
                <ul className="list-disc list-inside space-y-1">
                  {aiExplanation.recommendations.map((rec, index) => (
                    <li key={index} className="text-sm text-gray-300">
                      {rec}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
