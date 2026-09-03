# RedVapt — AI-Powered Penetration Testing Platform
<img width="300" height="300" alt="RedVapt logo" src="https://github.com/user-attachments/assets/12d781d1-b37f-497e-93db-fc5c91663734" />

RedVapt is an autonomous AI-guided penetration testing platform that combines multi-source CLI reconnaissance with a Model Context Protocol (MCP) architecture, a ReAct-style LLM exploitation agent, and comprehensive HTML report generation.

---

## Project Structure

```
RedVapt/
├── client/                         # Frontend — Vite + React + TypeScript
│   ├── src/
│   │   ├── main.tsx                # Application entry point
│   │   ├── App.tsx                 # Root component + routing
│   │   ├── pages/                  # AIScanner (SSE stream), Reports, etc.
│   │   └── components/             # UI Components
│
├── server/                         # Backend — Node.js + Express (ESM)
│   ├── src/
│   │   ├── server.js               # entry point
│   │   ├── core/
│   │   │   ├── scanner/            # Orchestrator, ReconAgent, ReAct Agent
│   │   │   └── reports/            # Report generators and stores
│   │   ├── engine/
│   │   │   ├── mcp/                # MCP Servers (recon, web, jsintel, vuln)
│   │   │   ├── vuln/               # Unified Vuln Engine & Templates
│   │   │   ├── graph/              # Asset Graph Store & Scoring
│   │   │   └── llm/                # OpenRouter Multi-model Fallback Router
│   │   └── utils/                  # Shared parsers, DB, and intelligence builders
│   └── data/
│       └── reports/                # Generated reports
│
├── .env                            # Environment variables
└── README.md
```

---

## Quick Start

### Prerequisites
- Node.js ≥ 18
- Security tools: `subfinder`, `httpx`, `nmap`, `katana`, `gau`, `waybackurls`, `ffuf`, `paramspider`
- Python tools: `LinkFinder`

### 1. Install Dependencies

```bash
# Install client and server dependencies
npm run install:all
```

### 2. Configure Environment

Copy `.env.example` to `.env` (if not already present) and fill in your OpenRouter API key:

```bash
OPENROUTER_API_KEY=your_openrouter_key
```

### 3. Start Development

```bash
# Start both client and server together
npm run dev
```

The application will be available at:
- **Frontend:** http://localhost:3000
- **Backend:** http://localhost:3001

---



## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Server health check |
| `GET` | `/api/recon?target=<domain>` | Run full scan (SSE stream) |
| `GET` | `/api/reports` | List all reports |
| `GET` | `/api/reports/:id/download` | Download HTML report |

---

**Policy:** No Exploit, No Report — Every finding is backed by hard evidence.
