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

interface SandboxStatus {
  is_active: boolean;
  mount_point: string | null;
  session_id: string;
}

function Dashboard() {
  const [logs, setLogs] = useState<EventLog[]>([]);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
  const [newProcess, setNewProcess] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [sandboxStatus, setSandboxStatus] = useState<SandboxStatus | null>(null);
  const [isPurging, setIsPurging] = useState(false);

  useEffect(() => {
    loadLogs();
    loadHealth();
    loadWhitelist();
    loadSandboxStatus();

    const interval = setInterval(() => {
      loadHealth();
      loadSandboxStatus();
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
    try {
      const result = await invoke<WhitelistEntry[]>("get_whitelist");
      setWhitelist(result);
    } catch (error) {
      console.error("Failed to load whitelist:", error);
    }
  };

  const addToWhitelist = async () => {
    if (!newProcess.trim()) return;
    try {
      await invoke("add_to_whitelist", { processName: newProcess });
      setNewProcess("");
      loadWhitelist();
    } catch (error) {
      console.error("Failed to add to whitelist:", error);
    }
  };

  const removeFromWhitelist = async (id: number) => {
    try {
      await invoke("remove_from_whitelist", { id });
      loadWhitelist();
    } catch (error) {
      console.error("Failed to remove from whitelist:", error);
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
      alert(JSON.stringify(result, null, 2));
    } catch (error) {
      console.error("Failed to get AI explanation:", error);
    }
  };

  const loadSandboxStatus = async () => {
    try {
      const result = await invoke<SandboxStatus>("get_sandbox_status");
      setSandboxStatus(result);
    } catch (error) {
      console.error("Failed to load sandbox status:", error);
    }
  };

  const purgeGhostLayer = async () => {
    if (!confirm("⚠️ PURGE GHOST LAYER?\n\nThis will erase all session data and reset the sandbox. Continue?")) {
      return;
    }
    
    setIsPurging(true);
    try {
      const result = await invoke<string>("purge_ghost_layer");
      alert(result);
      loadSandboxStatus();
    } catch (error) {
      console.error("Failed to purge:", error);
      alert("Failed to purge Ghost Layer: " + error);
    } finally {
      setIsPurging(false);
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
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-600">
              Ghost Layer Security Console
            </h1>
            <p className="text-gray-400 mt-2">Industrial-grade threat detection and isolation</p>
          </div>
          <button
            onClick={purgeGhostLayer}
            disabled={isPurging}
            className="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-6 py-3 rounded-lg font-bold text-lg transition-colors"
          >
            {isPurging ? "PURGING..." : "🔥 PURGE GHOST LAYER"}
          </button>
        </div>
      </header>

      {/* System Health */}
      {health && (
        <div className="grid grid-cols-5 gap-4 mb-8">
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
          <div className={`rounded-lg p-4 border ${sandboxStatus?.is_active ? 'bg-green-900 border-green-700' : 'bg-gray-800 border-gray-700'}`}>
            <div className="text-gray-400 text-sm">Sandbox</div>
            <div className="text-2xl font-bold">
              {sandboxStatus?.is_active ? '🛡️ ACTIVE' : '⚪ INACTIVE'}
            </div>
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
              placeholder="Gemini API Key (for AI explanations)"
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
              onClick={addToWhitelist}
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
                  onClick={() => entry.id && removeFromWhitelist(entry.id)}
                  className="text-red-400 hover:text-red-300 text-sm"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
