# RedVapt — AI-Powered Penetration Testing Platform

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

## Architecture (MCP)

The scan pipeline now operates using the **Model Context Protocol (MCP)**:

1. **Recon (MCP)** — Isolated tool execution via specialized MCP servers.
2. **Graph Construction** — Builds a relationship map of discovered assets.
3. **Intelligence Scoring** — Prioritizes attack surfaces using a scoring engine.
4. **Unified Vuln Scan** — Declarative vulnerability templates with a strict 4-step verification pipeline.
5. **ReAct Loop** — Autonomous reasoning and acting to exploit confirmed signals.
6. **Reporting** — Professional HTML/JSON reports with hard evidence.

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
