import { useEffect, useState } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

function PetOverlay() {
  const [isAlarmed, setIsAlarmed] = useState(false);
  const [alertCount, setAlertCount] = useState(0);

  useEffect(() => {
    console.log("PetOverlay: Component mounted, window label:", getCurrentWebviewWindow().label);
    console.log("PetOverlay: Setting up threat-alert listener...");
    
    const currentWindow = getCurrentWebviewWindow();
    
    const setupListener = async () => {
      const unlisten = await currentWindow.listen("threat-alert", (event) => {
        console.log("PetOverlay: *** RECEIVED THREAT-ALERT ***", event);
        setIsAlarmed(true);
        setAlertCount(prev => prev + 1);
        setTimeout(() => setIsAlarmed(false), 3000);
      });
      
      console.log("PetOverlay: Listener registered successfully on window:", currentWindow.label);
      return unlisten;
    };

    let unlistenFn: (() => void) | null = null;
    
    setupListener().then(fn => {
      unlistenFn = fn;
    }).catch(err => {
      console.error("PetOverlay: Failed to setup listener:", err);
    });

    return () => {
      if (unlistenFn) {
        unlistenFn();
      }
    };
  }, []);

  return (
    <div className="w-full h-full flex items-center justify-center bg-transparent">
      {/* Debug indicator */}
      <div className="absolute top-2 left-2 text-xs font-bold px-2 py-1 rounded" style={{
        backgroundColor: isAlarmed ? '#ef4444' : '#8b5cf6',
        color: 'white'
      }}>
        {isAlarmed ? '🚨 ALERT!' : '✓ Safe'}
      </div>
      
      <svg
        width="150"
        height="150"
        viewBox="0 0 150 150"
        className={`transition-all duration-300 ${
          isAlarmed ? "animate-shake filter drop-shadow-[0_0_20px_rgba(239,68,68,0.8)]" : ""
        }`}
      >
        {/* Ghost body */}
        <path
          d="M 75 30 
             Q 50 30 40 50 
             Q 35 65 35 80 
             L 35 120 
             L 45 110 
             L 55 120 
             L 65 110 
             L 75 120 
             L 85 110 
             L 95 120 
             L 105 110 
             L 115 120 
             L 115 80 
             Q 115 65 110 50 
             Q 100 30 75 30 Z"
          fill={isAlarmed ? "#ef4444" : "#8b5cf6"}
          stroke={isAlarmed ? "#dc2626" : "#7c3aed"}
          strokeWidth="2"
          className="transition-colors duration-300"
        />
        
        {/* Left eye */}
        <circle
          cx="60"
          cy="65"
          r="8"
          fill={isAlarmed ? "#fef3c7" : "#ffffff"}
          className="transition-colors duration-300"
        />
        <circle
          cx="62"
          cy="65"
          r="4"
          fill="#1f2937"
        />
        
        {/* Right eye */}
        <circle
          cx="90"
          cy="65"
          r="8"
          fill={isAlarmed ? "#fef3c7" : "#ffffff"}
          className="transition-colors duration-300"
        />
        <circle
          cx="92"
          cy="65"
          r="4"
          fill="#1f2937"
        />
        
        {/* Mouth */}
        <path
          d={isAlarmed 
            ? "M 60 85 Q 75 75 90 85" 
            : "M 60 85 Q 75 95 90 85"
          }
          stroke="#1f2937"
          strokeWidth="3"
          fill="none"
          strokeLinecap="round"
          className="transition-all duration-300"
        />
        
        {/* Alert indicator */}
        {isAlarmed && (
          <>
            <circle
              cx="75"
              cy="20"
              r="5"
              fill="#ef4444"
              className="animate-ping"
            />
            <text
              x="75"
              y="145"
              textAnchor="middle"
              fill="#ef4444"
              fontSize="12"
              fontWeight="bold"
            >
              THREAT!
            </text>
          </>
        )}
      </svg>
    </div>
  );
}

export default PetOverlay;
