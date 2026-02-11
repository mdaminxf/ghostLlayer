# Ghost Layer - Ephemeral Containment Architecture

## Overview
Industrial-grade security suite with VHDX-based sandboxing, behavioral monitoring, and AI-powered threat analysis.

## Architecture Components

### 1. The Sandbox (engines/sandbox.rs)
**Purpose:** Ephemeral disk isolation using Windows VHDX technology

**Features:**
- Golden Image VHDX creation (base disk)
- Differencing VHDX (session-specific child disk)
- Mount/Unmount operations
- Session purge (complete data erasure)

**Key Functions:**
- `create_ephemeral_disk()` - Creates a differencing disk linked to golden image
- `mount_ghost_layer()` - Mounts the sandbox as a virtual drive
- `purge_session()` - Destroys all session data and resets

**Security Model:**
- All user activity happens in the differencing disk
- Golden image remains pristine
- Purge operation = instant reset to clean state
- No persistent malware possible

### 2. The Sentinel (sentinel.rs)
**Purpose:** Real-time threat detection and behavioral monitoring

**Detection Methods:**
- Shannon Entropy Analysis (threshold: 7.5)
- Process name pattern matching
- File system tripwires
- API call monitoring (stub)

**Monitored Locations:**
- `C:\Ghost_Secrets` - File system tripwire
- All running processes
- High-entropy file writes

### 3. The Analyst (engines/analyst.rs)
**Purpose:** AI-powered threat explanation and risk assessment

**Features:**
- Google Gemini API integration
- Natural language threat explanations
- Risk level assessment (LOW/MEDIUM/HIGH/CRITICAL)
- Actionable recommendations

**Functions:**
- `explain_threat()` - Full AI analysis via Gemini
- `quick_assess()` - Instant fallback assessment

### 4. The Console (React Dashboard)
**Purpose:** User interface for security operations

**Features:**
- Real-time threat log
- System health monitoring
- Sandbox status indicator
- PURGE button (session reset)
- Process whitelist management
- AI explanation integration

### 5. The Pet (Animated Ghost Overlay)
**Purpose:** Visual threat alerting

**Behavior:**
- Normal: Purple ghost, smiling
- Threat detected: Red ghost, shaking
- Always-on-top transparent window

## Data Flow

```
File Write → Sentinel (Entropy Check) → emit("threat-alert") → Dashboard + Pet
Process Start → Sentinel (Pattern Match) → emit("threat-alert") → Dashboard + Pet
User Action → Dashboard → Rust Command → Sandbox/Analyst → Response
```

## Security Capabilities

### ✅ Currently Implemented
- High entropy file detection (encrypted/packed malware)
- Suspicious process detection (known hacking tools)
- Real-time event streaming
- SQLite-based whitelist
- AI threat explanations
- VHDX sandbox infrastructure

### ⚠️ Limitations
- No network traffic monitoring (phishing sites)
- No data leak detection
- No 0-day exploit detection
- No behavioral sandboxing (execution analysis)
- VHDX mounting requires admin privileges
- Windows-only (VHDX is Windows-specific)

## Usage

### Starting the System
```bash
npm run tauri dev
```

### Testing Threat Detection
```powershell
# Create high-entropy test file
powershell -ExecutionPolicy Bypass -File simple-test.ps1
```

### Purging the Ghost Layer
1. Click "🔥 PURGE GHOST LAYER" button in dashboard
2. Confirm the action
3. All session data is erased
4. New session ID generated

### AI Threat Analysis
1. Enter Google Gemini API key in dashboard
2. Click "AI Explain" on any threat log
3. Receive user-friendly explanation and recommendations

## Technical Stack

**Backend:**
- Rust (Core security engine)
- Tauri 2.0 (Desktop framework)
- Windows API (VHDX operations)
- SQLite (Persistence)
- Tokio (Async runtime)

**Frontend:**
- React + TypeScript
- Tailwind CSS
- Tauri API (IPC)

**AI:**
- Google Gemini Pro API

## File Structure

```
ghost-layer/
├── src-tauri/
│   ├── src/
│   │   ├── engines/
│   │   │   ├── sandbox.rs    # VHDX hypervisor
│   │   │   └── analyst.rs    # AI bridge
│   │   ├── sentinel.rs       # Threat detection
│   │   ├── commands.rs       # Tauri commands
│   │   ├── db.rs            # SQLite layer
│   │   └── lib.rs           # App initialization
│   └── Cargo.toml
├── src/
│   ├── components/
│   │   ├── Dashboard.tsx    # Main console
│   │   └── PetOverlay.tsx   # Ghost pet
│   └── App.tsx
└── README.md
```

## Future Enhancements

1. **Network Monitoring**
   - DNS query analysis
   - HTTP/HTTPS traffic inspection
   - Phishing site detection

2. **Behavioral Analysis**
   - API hooking (CreateRemoteThread, WriteProcessMemory)
   - Registry monitoring
   - Privilege escalation detection

3. **Advanced Sandboxing**
   - Automatic file execution in sandbox
   - Commit/Discard workflow
   - Network isolation

4. **Machine Learning**
   - Local ML models for offline detection
   - Behavioral anomaly detection
   - Zero-day heuristics

## Security Notes

⚠️ **This is an educational/demonstration project**

For production security, use:
- Windows Defender
- Malwarebytes
- CrowdStrike
- Other professional antivirus solutions

The Ghost Layer demonstrates security concepts but is not a replacement for commercial antivirus software.
