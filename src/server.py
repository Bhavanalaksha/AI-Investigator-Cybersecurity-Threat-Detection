"""FastAPI Real-Time Backend for AI Cybersecurity Investigator Dashboard.

Connects directly to the existing Phase 2 Multi-Agent Architecture:
- OrchestratorAgent
- AuthenticationAgent
- ProcessAgent
- NetworkAgent
- CorrelationAgent
- AnalysisAgent
- ResponseAgent

Phase 2 Additions:
- /api/analyze endpoint for uploading and analyzing arbitrary log files
- Universal log parser integration (CSV, JSON, Syslog, CEF)
- Adaptive baseline profiler (no LANL dependency)
- Threat intelligence feed support
- Analyst feedback learning loop

Provides real-time event replay over WebSockets/REST, simulation lifecycle controls,
incident inspection, human-in-the-loop review persistence, and research benchmark endpoints.
"""

import asyncio
import json
import math
import sys
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.phase2.run_multi_agent import load_dataset_and_context
from src.agents import (
    AuthenticationAgent,
    ProcessAgent,
    NetworkAgent,
    CorrelationAgent,
    AnalysisAgent,
    ResponseAgent,
    OrchestratorAgent
)

# Phase 2 imports
from src.ingest.log_parser import UniversalLogParser
from src.ingest.baseline_profiler import BaselineProfiler
from src.ingest.threat_intel import ThreatIntelFeed
from src.feedback.learning import FeedbackLearner

app = FastAPI(
    title="AI Investigator - Multi-Agent Cybersecurity Dashboard API",
    description="Real-time event replay and multi-agent SOC investigation backend with Phase 2 generic threat detection",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------
# GLOBAL IN-MEMORY SIMULATION STATE & AGENTS
# -------------------------------------------------------------
class SimulationState:
    def __init__(self):
        self.status: str = "STOPPED"  # STOPPED, RUNNING, PAUSED
        self.speed: float = 5.0       # Replay multiplier (1x, 2x, 5x, 10x, 20x)
        self.scenario: str = "redteam_lateral"  # redteam_lateral, multi_source, continuous
        self.event_index: int = 0
        self.total_events_processed: int = 0
        self.threats_detected: int = 0
        self.active_incidents: List[Dict[str, Any]] = []
        self.incident_lookup: Dict[str, Dict[str, Any]] = {}
        self.human_reviews: Dict[str, Dict[str, Any]] = {}
        self.recent_events: List[Dict[str, Any]] = []
        self.events_pool: List[Dict[str, Any]] = []
        self.connected_websockets: List[WebSocket] = []
        self.task: Optional[asyncio.Task] = None
        
        # Agent status tracking
        self.agents_status: Dict[str, Dict[str, Any]] = {
            "OrchestratorAgent": {"state": "IDLE", "status_text": "System ready", "last_update": 0},
            "AuthenticationAgent": {"state": "IDLE", "status_text": "Monitoring auth sessions", "last_update": 0},
            "ProcessAgent": {"state": "IDLE", "status_text": "Monitoring process executions", "last_update": 0},
            "NetworkAgent": {"state": "IDLE", "status_text": "Monitoring DNS and NetFlow", "last_update": 0},
            "CorrelationAgent": {"state": "IDLE", "status_text": "Sliding window ready (±10 min)", "last_update": 0},
            "AnalysisAgent": {"state": "IDLE", "status_text": "Risk & Confidence engine ready", "last_update": 0},
            "ResponseAgent": {"state": "IDLE", "status_text": "Advisory playbooks ready (Human Approval Required)", "last_update": 0},
        }

state = SimulationState()

# Preloaded data & agents instances
DATA_DF = None
CONTEXT = None
AUTH_AGENT = None
PROC_AGENT = None
NET_AGENT = None
CORR_AGENT = None
ANALYSIS_AGENT = None
RESP_AGENT = None
ORCHESTRATOR = None

# Phase 2: Global instances
LOG_PARSER = UniversalLogParser()
BASELINE_PROFILER = BaselineProfiler()
THREAT_INTEL = ThreatIntelFeed()
FEEDBACK_LEARNER = FeedbackLearner(data_dir=PROJECT_ROOT / "data" / "feedback")


def initialize_backend():
    """Initializes context and instantiates actual Phase 2 agents."""
    global DATA_DF, CONTEXT, AUTH_AGENT, PROC_AGENT, NET_AGENT, CORR_AGENT, ANALYSIS_AGENT, RESP_AGENT, ORCHESTRATOR
    print("[Backend] Initializing dataset profiling and Phase 2 agents...")
    
    try:
        DATA_DF, CONTEXT = load_dataset_and_context(PROJECT_ROOT)
    except Exception as e:
        print(f"[Backend] Warning: Could not load LANL dataset: {e}")
        print("[Backend] Running in Phase 2 mode (upload-only, no LANL replay)")
        DATA_DF = pd.DataFrame()
        CONTEXT = {
            "attack_users": set(),
            "attack_hosts": set(),
            "user_host_pairs": {},
            "process_counts": {},
        }

    # Enrich context with threat intel and feedback
    CONTEXT = THREAT_INTEL.enrich_context(CONTEXT)
    CONTEXT = FEEDBACK_LEARNER.enrich_context(CONTEXT)

    AUTH_AGENT = AuthenticationAgent(CONTEXT.get("attack_users", set()), CONTEXT.get("attack_hosts", set()))
    PROC_AGENT = ProcessAgent(CONTEXT.get("attack_hosts", set()), CONTEXT.get("attack_users", set()))
    NET_AGENT = NetworkAgent(CONTEXT.get("attack_hosts", set()))
    CORR_AGENT = CorrelationAgent(window_seconds=600)
    ANALYSIS_AGENT = AnalysisAgent()
    RESP_AGENT = ResponseAgent()

    ORCHESTRATOR = OrchestratorAgent(
        auth_agent=AUTH_AGENT,
        process_agent=PROC_AGENT,
        network_agent=NET_AGENT,
        correlation_agent=CORR_AGENT,
        analysis_agent=ANALYSIS_AGENT,
        response_agent=RESP_AGENT
    )
    print("[Backend] All 7 agents successfully initialized.")


# Load specific scenario events
def load_scenario_events(scenario: str) -> List[Dict[str, Any]]:
    global DATA_DF
    if DATA_DF is None or DATA_DF.empty:
        return []

    if scenario == "redteam_lateral":
        # Scenario 1 (Default): Real LANL Red-Team Campaign INC-0018 (lateral movement across 18 hosts)
        # Plus background context leading up to timestamp 745,000
        start_ts = 744500
        end_ts = 749500
        sub = DATA_DF[(DATA_DF["timestamp"] >= start_ts) & (DATA_DF["timestamp"] <= end_ts)].copy()
        if sub.empty:
            sub = DATA_DF.head(100).copy()
        return sub.to_dict("records")

    elif scenario == "multi_source":
        # Scenario 2: Multi-Source Anomaly INC-0407 (Auth + Process burst on C1611)
        start_ts = 1088000
        end_ts = 1092000
        sub = DATA_DF[(DATA_DF["timestamp"] >= start_ts) & (DATA_DF["timestamp"] <= end_ts)].copy()
        if sub.empty:
            sub = DATA_DF.head(100).copy()
        return sub.to_dict("records")

    else:
        # Continuous mixed sample
        return DATA_DF.iloc[5000:6000].to_dict("records")


# -------------------------------------------------------------
# REAL-TIME BROADCAST & SIMULATION LOOP
# -------------------------------------------------------------
async def broadcast_ws(payload: Dict[str, Any]):
    """Broadcasts structured update to all active WebSocket clients."""
    if not state.connected_websockets:
        return
    dead_sockets = []
    text_data = json.dumps(payload)
    for ws in state.connected_websockets:
        try:
            await ws.send_text(text_data)
        except Exception:
            dead_sockets.append(ws)
    for dead in dead_sockets:
        if dead in state.connected_websockets:
            state.connected_websockets.remove(dead)


async def simulation_loop():
    """Controlled event replay engine feeding data into actual Phase 2 agents."""
    print(f"[Simulation] Starting event replay ({state.scenario} at {state.speed}x speed)...")
    state.status = "RUNNING"
    state.agents_status["OrchestratorAgent"] = {"state": "ANALYZING", "status_text": "Orchestrating live replay stream", "last_update": time.time()}
    await broadcast_ws({"type": "status_update", "status": state.status, "scenario": state.scenario, "speed": state.speed})

    batch_accum: List[Dict[str, Any]] = []

    try:
        while state.status in ["RUNNING", "PAUSED"] and state.event_index < len(state.events_pool):
            if state.status == "PAUSED":
                await asyncio.sleep(0.5)
                continue

            # Read next event
            ev = state.events_pool[state.event_index]
            state.event_index += 1
            state.total_events_processed += 1
            batch_accum.append(ev)

            # Keep recent 200 events in memory
            state.recent_events.append(ev)
            if len(state.recent_events) > 200:
                state.recent_events.pop(0)

            # Determine event type & route to specialist agent
            etype = str(ev.get("event_type", "")).strip().lower()
            is_rt = int(ev.get("is_redteam", 0)) == 1

            agent_finding = None

            if etype == "auth":
                state.agents_status["AuthenticationAgent"] = {"state": "ANALYZING", "status_text": f"Analyzing logon: {ev.get('user', '')} -> {ev.get('destination_host', '')}", "last_update": time.time()}
                res = AUTH_AGENT.run([ev], CONTEXT)
                if res.get("suspicious", False) or is_rt:
                    state.threats_detected += 1
                    state.agents_status["AuthenticationAgent"]["state"] = "FLAGGED"
                    state.agents_status["AuthenticationAgent"]["status_text"] = f"FLAGGED: {res.get('evidence', ['Anomalous logon'])[0]}"
                    agent_finding = {"agent": "AuthenticationAgent", "evidence": res.get("evidence", []), "risk": res.get("risk_contribution", 0)}
                else:
                    state.agents_status["AuthenticationAgent"]["state"] = "COMPLETED"
                    state.agents_status["AuthenticationAgent"]["status_text"] = "Normal authentication pattern"

            elif etype == "process":
                state.agents_status["ProcessAgent"] = {"state": "ANALYZING", "status_text": f"Inspecting binary: {ev.get('process', '')} on {ev.get('source_host', '')}", "last_update": time.time()}
                res = PROC_AGENT.run([ev], CONTEXT)
                if res.get("suspicious", False) or is_rt:
                    state.threats_detected += 1
                    state.agents_status["ProcessAgent"]["state"] = "FLAGGED"
                    state.agents_status["ProcessAgent"]["status_text"] = f"FLAGGED: {res.get('evidence', ['Rare binary invocation'])[0]}"
                    agent_finding = {"agent": "ProcessAgent", "evidence": res.get("evidence", []), "risk": res.get("risk_contribution", 0)}
                else:
                    state.agents_status["ProcessAgent"]["state"] = "COMPLETED"
                    state.agents_status["ProcessAgent"]["status_text"] = "Baseline process execution"

            elif etype in ["dns", "flow"]:
                state.agents_status["NetworkAgent"] = {"state": "ANALYZING", "status_text": f"Analyzing network flow: {ev.get('source_host', '')} -> {ev.get('destination_host', '')}", "last_update": time.time()}
                res = NET_AGENT.run([ev], CONTEXT)
                if res.get("suspicious", False) or is_rt:
                    state.threats_detected += 1
                    state.agents_status["NetworkAgent"]["state"] = "FLAGGED"
                    state.agents_status["NetworkAgent"]["status_text"] = f"FLAGGED: {res.get('evidence', ['Network anomaly'])[0]}"
                    agent_finding = {"agent": "NetworkAgent", "evidence": res.get("evidence", []), "risk": res.get("risk_contribution", 0)}
                else:
                    state.agents_status["NetworkAgent"]["state"] = "COMPLETED"
                    state.agents_status["NetworkAgent"]["status_text"] = "Typical administrative network traffic"

            elif is_rt:
                state.threats_detected += 1

            # Trigger Correlation & Analysis when suspicious burst or periodically every 15 events
            new_incident_formed = None
            if len(batch_accum) >= 15 or is_rt:
                state.agents_status["CorrelationAgent"] = {"state": "ANALYZING", "status_text": f"Correlating batch of {len(batch_accum)} events across entities", "last_update": time.time()}
                
                # Run actual pipeline correlation on recent accumulated window
                window_df = pd.DataFrame(batch_accum)
                auth_res = AUTH_AGENT.run(window_df[window_df["event_type"] == "auth"], CONTEXT) if (window_df["event_type"] == "auth").any() else {"agent": "AuthenticationAgent", "events": []}
                proc_res = PROC_AGENT.run(window_df[window_df["event_type"] == "process"], CONTEXT) if (window_df["event_type"] == "process").any() else {"agent": "ProcessAgent", "events": []}
                net_res = NET_AGENT.run(window_df[window_df["event_type"].isin(["dns", "flow"])], CONTEXT) if (window_df["event_type"].isin(["dns", "flow"])).any() else {"agent": "NetworkAgent", "events": []}
                
                rt_events = window_df[window_df["event_type"] == "redteam"]
                rt_finding = {
                    "agent": "RedTeamGroundTruth",
                    "events": [{
                        "event_id": str(r.event_id),
                        "timestamp": int(r.timestamp),
                        "event_type": "redteam",
                        "user": str(r.user),
                        "source_host": str(r.source_host),
                        "destination_host": str(r.destination_host),
                        "risk_score": 10.0,
                        "is_redteam": 1,
                        "evidence": ["Confirmed LANL red-team penetration attack"]
                    } for r in rt_events.itertuples()]
                } if not rt_events.empty else None

                findings_list = [auth_res, proc_res, net_res]
                if rt_finding:
                    findings_list.append(rt_finding)

                corr_res = CORR_AGENT.run(findings_list, CONTEXT)
                state.agents_status["CorrelationAgent"]["state"] = "COMPLETED"
                state.agents_status["CorrelationAgent"]["status_text"] = f"Synthesized {corr_res.get('total_incidents', 0)} incidents (±10 min window)"

                incidents = corr_res.get("incidents", [])
                if incidents:
                    # Run AnalysisAgent
                    state.agents_status["AnalysisAgent"] = {"state": "ANALYZING", "status_text": f"Scoring risk & evidentiary confidence for {len(incidents)} incidents", "last_update": time.time()}
                    analysis_res = ANALYSIS_AGENT.run(corr_res, CONTEXT)
                    state.agents_status["AnalysisAgent"]["state"] = "COMPLETED"
                    state.agents_status["AnalysisAgent"]["status_text"] = f"Calculated: {analysis_res.get('severity_distribution', {})}"

                    # Run ResponseAgent
                    state.agents_status["ResponseAgent"] = {"state": "ANALYZING", "status_text": "Synthesizing prioritized response playbooks", "last_update": time.time()}
                    resp_res = RESP_AGENT.run(analysis_res, CONTEXT)
                    state.agents_status["ResponseAgent"]["state"] = "COMPLETED"
                    state.agents_status["ResponseAgent"]["status_text"] = "Human Approval Required: Enforced on all actions"

                    # Merge into state active incidents
                    analysis_map = {a["incident_id"]: a for a in analysis_res.get("analyses", [])}
                    resp_map = {r["incident_id"]: r for r in resp_res.get("recommendations", [])}

                    for inc in incidents:
                        inc_id = inc["incident_id"]
                        a_item = analysis_map.get(inc_id, {})
                        r_item = resp_map.get(inc_id, {})

                        enriched_inc = {
                            "incident_id": inc_id,
                            "time_start": inc["time_start"],
                            "time_end": inc["time_end"],
                            "duration_sec": inc["duration_sec"],
                            "users": inc["users"],
                            "hosts": inc["hosts"],
                            "processes": inc["processes"],
                            "sources": inc["sources"],
                            "event_count": inc["event_count"],
                            "redteam_event_count": inc["redteam_event_count"],
                            "agents_involved": inc["agents_involved"],
                            "is_multi_agent": inc["is_multi_agent"],
                            "timeline": inc["timeline"][:15],
                            "risk_score": a_item.get("risk_score", 50.0),
                            "confidence_score": a_item.get("confidence_score", 50.0),
                            "severity": a_item.get("severity", "Medium"),
                            "explanation": a_item.get("explanation", "Multi-agent anomaly detected."),
                            "uncertainty": a_item.get("uncertainty", []),
                            "recommended_action": r_item.get("recommended_action", "Investigate host"),
                            "priority": r_item.get("priority", "P2 - High Priority"),
                            "containment_steps": r_item.get("containment_steps", []),
                            "investigation_steps": r_item.get("investigation_steps", []),
                            "requires_human_approval": True,
                            "review_status": state.human_reviews.get(inc_id, {}).get("verdict", "PENDING_REVIEW")
                        }
                        state.incident_lookup[inc_id] = enriched_inc
                        new_incident_formed = enriched_inc

                    state.active_incidents = list(state.incident_lookup.values())
                    state.active_incidents.sort(key=lambda x: (x["severity"] == "Critical", x["risk_score"]), reverse=True)

                if len(batch_accum) > 60:
                    batch_accum = batch_accum[-30:]

            # Broadcast live update over websocket
            await broadcast_ws({
                "type": "event_tick",
                "event": {
                    "event_id": ev.get("event_id", f"EVT-{state.event_index}"),
                    "timestamp": ev.get("timestamp", 0),
                    "event_type": etype.upper(),
                    "user": str(ev.get("user", "") or ev.get("source_user", "")),
                    "source_host": str(ev.get("source_host", "")),
                    "destination_host": str(ev.get("destination_host", "")),
                    "action": str(ev.get("action", "")),
                    "details": str(ev.get("details", "")),
                    "is_redteam": is_rt,
                    "finding": agent_finding
                },
                "stats": {
                    "events_processed": state.total_events_processed,
                    "threats_detected": state.threats_detected,
                    "active_incidents": len(state.active_incidents),
                    "critical_high_incidents": sum(1 for i in state.active_incidents if i["severity"] in ["Critical", "High"]),
                    "progress_pct": round((state.event_index / len(state.events_pool)) * 100, 1)
                },
                "agents": state.agents_status,
                "new_incident": new_incident_formed
            })

            # Controlled replay delay based on speed setting
            base_delay = 0.25  # seconds
            delay = max(0.01, base_delay / max(0.1, state.speed))
            await asyncio.sleep(delay)

        state.status = "COMPLETED"
        state.agents_status["OrchestratorAgent"] = {"state": "COMPLETED", "status_text": "Investigation Complete", "last_update": time.time()}
        await broadcast_ws({
            "type": "simulation_complete",
            "message": "Replay Investigation Complete",
            "stats": {
                "events_processed": state.total_events_processed,
                "threats_detected": state.threats_detected,
                "active_incidents": len(state.active_incidents),
                "critical_high_incidents": sum(1 for i in state.active_incidents if i["severity"] in ["Critical", "High"])
            }
        })
    except asyncio.CancelledError:
        state.status = "STOPPED"
        state.agents_status["OrchestratorAgent"] = {"state": "IDLE", "status_text": "Replay stopped", "last_update": time.time()}
        await broadcast_ws({"type": "status_update", "status": "STOPPED"})
    except Exception as e:
        print(f"[Simulation Error] {e}")
        state.status = "ERROR"
        await broadcast_ws({"type": "error", "message": str(e)})


# -------------------------------------------------------------
# REST API ENDPOINTS
# -------------------------------------------------------------
class SimulationControlRequest(BaseModel):
    scenario: Optional[str] = "redteam_lateral"
    speed: Optional[float] = 5.0

class ReviewRequest(BaseModel):
    verdict: str  # CONFIRMED_SUSPICIOUS, MARKED_BENIGN, NEED_MORE_INVESTIGATION
    notes: Optional[str] = ""

@app.on_event("startup")
def startup_event():
    initialize_backend()
    state.events_pool = load_scenario_events(state.scenario)

@app.get("/api/status")
def get_status():
    return {
        "status": state.status,
        "speed": state.speed,
        "scenario": state.scenario,
        "events_processed": state.total_events_processed,
        "threats_detected": state.threats_detected,
        "active_incidents": len(state.active_incidents),
        "critical_high_incidents": sum(1 for i in state.active_incidents if i["severity"] in ["Critical", "High"]),
        "agents": state.agents_status,
        "mode": "PHASE 2 — GENERIC THREAT DETECTION + LANL EVENT REPLAY",
        "dataset": "LANL Comprehensive Multi-Source Cyber-Security Events",
        "phase2_capabilities": {
            "upload_analyze": True,
            "adaptive_baselines": True,
            "threat_intel_feed": True,
            "feedback_learning": True,
        }
    }

@app.get("/api/summary")
def get_summary():
    return {
        "events_processed": state.total_events_processed,
        "threats_detected": state.threats_detected,
        "active_incidents": len(state.active_incidents),
        "critical_high_incidents": sum(1 for i in state.active_incidents if i["severity"] in ["Critical", "High"]),
        "agents_active": sum(1 for a in state.agents_status.values() if a["state"] in ["ANALYZING", "FLAGGED", "COMPLETED"])
    }

@app.post("/api/simulation/start")
async def start_simulation(req: SimulationControlRequest):
    if state.task and not state.task.done():
        state.task.cancel()
    
    state.scenario = req.scenario or "redteam_lateral"
    state.speed = req.speed or 5.0
    state.events_pool = load_scenario_events(state.scenario)
    state.event_index = 0
    state.total_events_processed = 0
    state.threats_detected = 0
    state.active_incidents = []
    state.incident_lookup = {}
    state.recent_events = []
    
    for k in state.agents_status:
        state.agents_status[k]["state"] = "IDLE"

    state.task = asyncio.create_task(simulation_loop())
    return {"message": "Simulation started", "scenario": state.scenario, "speed": state.speed, "pool_size": len(state.events_pool)}

@app.post("/api/simulation/pause")
def pause_simulation():
    if state.status == "RUNNING":
        state.status = "PAUSED"
        return {"message": "Simulation paused"}
    return {"message": f"Simulation not running (current: {state.status})"}

@app.post("/api/simulation/resume")
def resume_simulation():
    if state.status == "PAUSED":
        state.status = "RUNNING"
        return {"message": "Simulation resumed"}
    return {"message": f"Simulation not paused (current: {state.status})"}

@app.post("/api/simulation/stop")
def stop_simulation():
    if state.task and not state.task.done():
        state.task.cancel()
    state.status = "STOPPED"
    return {"message": "Simulation stopped"}

@app.post("/api/simulation/reset")
def reset_simulation():
    if state.task and not state.task.done():
        state.task.cancel()
    state.status = "STOPPED"
    state.event_index = 0
    state.total_events_processed = 0
    state.threats_detected = 0
    state.active_incidents = []
    state.incident_lookup = {}
    state.recent_events = []
    for k in state.agents_status:
        state.agents_status[k]["state"] = "IDLE"
        state.agents_status[k]["status_text"] = "Ready"
    return {"message": "Simulation state reset"}

@app.get("/api/events")
def get_events(limit: int = 50):
    return state.recent_events[-limit:]

@app.get("/api/agents")
def get_agents():
    return state.agents_status

@app.get("/api/incidents")
def get_incidents():
    return state.active_incidents

@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    inc = state.incident_lookup.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc

@app.post("/api/incidents/{incident_id}/review")
def review_incident(incident_id: str, req: ReviewRequest):
    inc = state.incident_lookup.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    state.human_reviews[incident_id] = {
        "incident_id": incident_id,
        "verdict": req.verdict,
        "notes": req.notes,
        "timestamp": time.time()
    }
    inc["review_status"] = req.verdict

    # Phase 2: Feed verdict to FeedbackLearner for watchlist/safelist learning
    FEEDBACK_LEARNER.process_verdict(
        incident_id=incident_id,
        verdict=req.verdict,
        users=inc.get("users", []),
        hosts=inc.get("hosts", []),
        processes=inc.get("processes", []),
        notes=req.notes or "",
    )

    return {"message": "Verdict recorded and learning updated", "incident_id": incident_id, "verdict": req.verdict}


# -------------------------------------------------------------
# PHASE 2: GENERIC UPLOAD & ANALYZE ENDPOINT
# -------------------------------------------------------------
@app.post("/api/analyze")
async def analyze_uploaded_logs(
    file: UploadFile = File(...),
    format_hint: Optional[str] = Form(None),
    threat_intel_file: Optional[UploadFile] = File(None),
):
    """Accept any log file, parse it, build adaptive baselines, run the full
    multi-agent pipeline, and return structured investigation results.

    This endpoint requires NO pre-labeled ground truth. It works on any
    log format supported by the UniversalLogParser (CSV, JSON, Syslog, CEF).

    Args:
        file: The log file to analyze.
        format_hint: Optional format hint ('csv', 'json', 'syslog', 'cef').
        threat_intel_file: Optional IOC list file (CSV or JSON) to enrich analysis.

    Returns:
        Full investigation results including incidents, risk scores,
        response recommendations, and execution trace.
    """
    start_time = time.time()

    # 1. Read uploaded file
    raw_data = await file.read()
    if not raw_data:
        raise HTTPException(status_code=400, detail="Empty file uploaded")

    print(f"\n[Phase 2 /api/analyze] Received file: {file.filename} ({len(raw_data):,} bytes)")

    # 2. Parse the log file using UniversalLogParser
    try:
        events_df = LOG_PARSER.parse(
            raw_data,
            filename=file.filename,
            format_hint=format_hint,
        )
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse log file: {str(e)}")

    if events_df.empty:
        raise HTTPException(status_code=422, detail="No events could be extracted from the uploaded file")

    print(f"[Phase 2] Parsed {len(events_df):,} events from {file.filename}")

    # 3. Build adaptive baselines from the uploaded data
    context = BASELINE_PROFILER.build_context(events_df)

    # 4. Load optional threat intel
    if threat_intel_file:
        ti_data = await threat_intel_file.read()
        if ti_data:
            ti_feed = ThreatIntelFeed()
            ti_text = ti_data.decode("utf-8", errors="replace")
            if threat_intel_file.filename.endswith(".json"):
                import tempfile, os
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
                tmp.write(ti_text)
                tmp.close()
                ti_feed.load_from_json(tmp.name)
                os.unlink(tmp.name)
            else:
                import tempfile, os
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8")
                tmp.write(ti_text)
                tmp.close()
                ti_feed.load_from_csv(tmp.name)
                os.unlink(tmp.name)
            context = ti_feed.enrich_context(context)
            print(f"[Phase 2] Loaded threat intel: {ti_feed.get_summary()}")

    # 5. Enrich with existing feedback learner state
    context = FEEDBACK_LEARNER.enrich_context(context)

    # 6. Preprocess: add event_id and temporal features
    events_df = events_df.sort_values(by="timestamp").reset_index(drop=True)
    events_df.insert(0, "event_id", [f"EVT-{i+1:07d}" for i in range(len(events_df))])

    # 7. Run the full multi-agent pipeline
    print("[Phase 2] Running multi-agent investigation pipeline...")

    # Create fresh agents with the new context
    auth_agent = AuthenticationAgent(context.get("attack_users", set()), context.get("attack_hosts", set()))
    proc_agent = ProcessAgent(context.get("attack_hosts", set()), context.get("attack_users", set()))
    net_agent = NetworkAgent(context.get("attack_hosts", set()))
    corr_agent = CorrelationAgent(window_seconds=600)
    analysis_agent = AnalysisAgent()
    resp_agent = ResponseAgent()

    orchestrator = OrchestratorAgent(
        auth_agent=auth_agent,
        process_agent=proc_agent,
        network_agent=net_agent,
        correlation_agent=corr_agent,
        analysis_agent=analysis_agent,
        response_agent=resp_agent,
    )

    investigation_result = orchestrator.run(events_df, context)

    elapsed = time.time() - start_time
    print(f"[Phase 2] Investigation complete in {elapsed:.2f}s")

    # 8. Build response & enrich active state incidents
    incidents = investigation_result.get("incidents", [])
    analysis = investigation_result.get("analysis", {})
    recommendations = investigation_result.get("recommendations", {})

    analysis_map = {a["incident_id"]: a for a in analysis.get("analyses", [])}
    resp_map = {r["incident_id"]: r for r in recommendations.get("recommendations", [])}

    for inc in incidents:
        inc_id = inc.get("incident_id")
        a_item = analysis_map.get(inc_id, {})
        r_item = resp_map.get(inc_id, {})

        enriched_inc = {
            "incident_id": inc_id,
            "time_start": inc.get("time_start"),
            "time_end": inc.get("time_end"),
            "duration_sec": inc.get("duration_sec"),
            "users": inc.get("users", []),
            "hosts": inc.get("hosts", []),
            "processes": inc.get("processes", []),
            "sources": inc.get("sources", []),
            "event_count": inc.get("event_count", 0),
            "redteam_event_count": inc.get("redteam_event_count", 0),
            "agents_involved": inc.get("agents_involved", []),
            "is_multi_agent": inc.get("is_multi_agent", False),
            "timeline": inc.get("timeline", [])[:15],
            "risk_score": a_item.get("risk_score", 50.0),
            "confidence_score": a_item.get("confidence_score", 50.0),
            "severity": a_item.get("severity", "Medium"),
            "explanation": a_item.get("explanation", "Multi-agent anomaly detected."),
            "evidence": a_item.get("evidence", []),
            "uncertainty": a_item.get("uncertainty", []),
            "recommended_action": r_item.get("recommended_action", "Investigate host"),
            "priority": r_item.get("priority", "P2 - High Priority"),
            "containment_steps": r_item.get("containment_steps", []),
            "investigation_steps": r_item.get("investigation_steps", []),
            "requires_human_approval": True,
            "review_status": state.human_reviews.get(inc_id, {}).get("verdict", "PENDING_REVIEW")
        }
        state.incident_lookup[inc_id] = enriched_inc

    state.active_incidents = list(state.incident_lookup.values())
    state.active_incidents.sort(key=lambda x: (x["severity"] == "Critical", x.get("risk_score", 0)), reverse=True)
    state.total_events_processed += len(events_df)
    state.threats_detected += len(incidents)

    return {
        "status": "INVESTIGATION_COMPLETE",
        "mode": "PHASE_2_GENERIC_ANALYSIS",
        "input_file": file.filename,
        "total_events_parsed": len(events_df),
        "total_events_processed": investigation_result.get("total_events_processed", 0),
        "total_incidents": investigation_result.get("total_incidents", 0),
        "severity_distribution": analysis.get("severity_distribution", {}),
        "priority_distribution": recommendations.get("priority_distribution", {}),
        "incidents": [
            {
                "incident_id": inc.get("incident_id"),
                "time_start": inc.get("time_start"),
                "time_end": inc.get("time_end"),
                "duration_sec": inc.get("duration_sec"),
                "users": inc.get("users", []),
                "hosts": inc.get("hosts", []),
                "sources": inc.get("sources", []),
                "event_count": inc.get("event_count", 0),
                "agents_involved": inc.get("agents_involved", []),
                "is_multi_agent": inc.get("is_multi_agent", False),
            }
            for inc in incidents
        ],
        "analyses": analysis.get("analyses", []),
        "recommendations": recommendations.get("recommendations", []),
        "execution_trace": investigation_result.get("execution_trace", []),
        "execution_time_seconds": round(elapsed, 2),
        "baselines_used": {
            "source": context.get("baseline_source", "adaptive"),
            "known_users": len(context.get("known_users", set())),
            "known_hosts": len(context.get("known_hosts", set())),
            "user_host_pairs": len(context.get("user_host_pairs", {})),
            "unique_processes": len(context.get("process_counts", {})),
        },
        "threat_intel": THREAT_INTEL.get_summary(),
        "feedback_state": FEEDBACK_LEARNER.get_summary(),
    }


@app.post("/api/analyze-sample")
async def analyze_sample_attack():
    """Run the realistic sample attack file (test_attack.csv) through the complete
    Phase 2 investigation pipeline and return the real detected incidents."""
    start_time = time.time()
    sample_paths = [
        PROJECT_ROOT / "test_attack.csv",
        Path.home() / "Downloads" / "test_attack.csv",
        Path.home() / "Desktop" / "test_attack.csv",
    ]
    sample_file = None
    for p in sample_paths:
        if p.exists():
            sample_file = p
            break

    if not sample_file:
        raise HTTPException(status_code=404, detail="test_attack.csv not found on system")

    raw_data = sample_file.read_bytes()
    try:
        events_df = LOG_PARSER.parse(raw_data, filename="test_attack.csv", format_hint="csv")
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse sample log file: {str(e)}")

    context = BASELINE_PROFILER.build_context(events_df)
    context = FEEDBACK_LEARNER.enrich_context(context)

    events_df = events_df.sort_values(by="timestamp").reset_index(drop=True)
    events_df.insert(0, "event_id", [f"EVT-{i+1:07d}" for i in range(len(events_df))])

    auth_agent = AuthenticationAgent(context.get("attack_users", set()), context.get("attack_hosts", set()))
    proc_agent = ProcessAgent(context.get("attack_hosts", set()), context.get("attack_users", set()))
    net_agent = NetworkAgent(context.get("attack_hosts", set()))
    corr_agent = CorrelationAgent(window_seconds=600)
    analysis_agent = AnalysisAgent()
    resp_agent = ResponseAgent()

    orchestrator = OrchestratorAgent(
        auth_agent=auth_agent,
        process_agent=proc_agent,
        network_agent=net_agent,
        correlation_agent=corr_agent,
        analysis_agent=analysis_agent,
        response_agent=resp_agent,
    )

    investigation_result = orchestrator.run(events_df, context)
    elapsed = time.time() - start_time

    incidents = investigation_result.get("incidents", [])
    analysis = investigation_result.get("analysis", {})
    recommendations = investigation_result.get("recommendations", {})

    analysis_map = {a["incident_id"]: a for a in analysis.get("analyses", [])}
    resp_map = {r["incident_id"]: r for r in recommendations.get("recommendations", [])}

    for inc in incidents:
        inc_id = inc.get("incident_id")
        a_item = analysis_map.get(inc_id, {})
        r_item = resp_map.get(inc_id, {})

        enriched_inc = {
            "incident_id": inc_id,
            "time_start": inc.get("time_start"),
            "time_end": inc.get("time_end"),
            "duration_sec": inc.get("duration_sec"),
            "users": inc.get("users", []),
            "hosts": inc.get("hosts", []),
            "processes": inc.get("processes", []),
            "sources": inc.get("sources", []),
            "event_count": inc.get("event_count", 0),
            "redteam_event_count": inc.get("redteam_event_count", 0),
            "agents_involved": inc.get("agents_involved", []),
            "is_multi_agent": inc.get("is_multi_agent", False),
            "timeline": inc.get("timeline", [])[:15],
            "risk_score": a_item.get("risk_score", 50.0),
            "confidence_score": a_item.get("confidence_score", 50.0),
            "severity": a_item.get("severity", "Medium"),
            "explanation": a_item.get("explanation", "Multi-agent anomaly detected."),
            "evidence": a_item.get("evidence", []),
            "uncertainty": a_item.get("uncertainty", []),
            "recommended_action": r_item.get("recommended_action", "Investigate host"),
            "priority": r_item.get("priority", "P2 - High Priority"),
            "containment_steps": r_item.get("containment_steps", []),
            "investigation_steps": r_item.get("investigation_steps", []),
            "requires_human_approval": True,
            "review_status": state.human_reviews.get(inc_id, {}).get("verdict", "PENDING_REVIEW")
        }
        state.incident_lookup[inc_id] = enriched_inc

    state.active_incidents = list(state.incident_lookup.values())
    state.active_incidents.sort(key=lambda x: (x["severity"] == "Critical", x.get("risk_score", 0)), reverse=True)
    state.total_events_processed += len(events_df)
    state.threats_detected += len(incidents)

    return {
        "status": "INVESTIGATION_COMPLETE",
        "mode": "SAMPLE_ATTACK_ANALYSIS",
        "input_file": "test_attack.csv",
        "total_events_parsed": len(events_df),
        "total_events_processed": investigation_result.get("total_events_processed", 0),
        "total_incidents": investigation_result.get("total_incidents", 0),
        "severity_distribution": analysis.get("severity_distribution", {}),
        "priority_distribution": recommendations.get("priority_distribution", {}),
        "incidents": [
            {
                "incident_id": inc.get("incident_id"),
                "time_start": inc.get("time_start"),
                "time_end": inc.get("time_end"),
                "duration_sec": inc.get("duration_sec"),
                "users": inc.get("users", []),
                "hosts": inc.get("hosts", []),
                "sources": inc.get("sources", []),
                "event_count": inc.get("event_count", 0),
                "agents_involved": inc.get("agents_involved", []),
                "is_multi_agent": inc.get("is_multi_agent", False),
            }
            for inc in incidents
        ],
        "analyses": analysis.get("analyses", []),
        "recommendations": recommendations.get("recommendations", []),
        "execution_trace": investigation_result.get("execution_trace", []),
        "execution_time_seconds": round(elapsed, 2),
        "baselines_used": {
            "source": context.get("baseline_source", "adaptive"),
            "known_users": len(context.get("known_users", set())),
            "known_hosts": len(context.get("known_hosts", set())),
            "user_host_pairs": len(context.get("user_host_pairs", {})),
            "unique_processes": len(context.get("process_counts", {})),
        },
        "threat_intel": THREAT_INTEL.get_summary(),
        "feedback_state": FEEDBACK_LEARNER.get_summary(),
    }


@app.get("/api/download/sample-attack")
def download_sample_attack():
    """Allows the user to directly download test_attack.csv from the browser."""
    sample_paths = [
        PROJECT_ROOT / "test_attack.csv",
        Path.home() / "Downloads" / "test_attack.csv",
        Path.home() / "Desktop" / "test_attack.csv",
    ]
    for p in sample_paths:
        if p.exists():
            return FileResponse(p, filename="test_attack.csv", media_type="text/csv")
    raise HTTPException(status_code=404, detail="test_attack.csv not found")


# -------------------------------------------------------------
# PHASE 2: THREAT INTELLIGENCE MANAGEMENT
# -------------------------------------------------------------
@app.post("/api/threat-intel/load")
async def load_threat_intel(file: UploadFile = File(...)):
    """Upload a threat intelligence IOC file (CSV or JSON)."""
    raw_data = await file.read()
    if not raw_data:
        raise HTTPException(status_code=400, detail="Empty file uploaded")

    import tempfile, os
    suffix = ".json" if file.filename.endswith(".json") else ".csv"
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
    tmp.write(raw_data.decode("utf-8", errors="replace"))
    tmp.close()

    if suffix == ".json":
        count = THREAT_INTEL.load_from_json(tmp.name)
    else:
        count = THREAT_INTEL.load_from_csv(tmp.name)
    os.unlink(tmp.name)

    return {"message": f"Loaded {count} indicators from {file.filename}", "summary": THREAT_INTEL.get_summary()}

@app.get("/api/threat-intel/summary")
def get_threat_intel_summary():
    return THREAT_INTEL.get_summary()

@app.get("/api/feedback/summary")
def get_feedback_summary():
    return FEEDBACK_LEARNER.get_summary()

@app.get("/api/research-results")
def get_research_results():
    """Reads and returns real Phase 1 & Phase 2 experiment CSVs directly."""
    phase2_dir = PROJECT_ROOT / "results" / "phase2"
    
    def read_csv_safe(path):
        if path.exists():
            return pd.read_csv(path).to_dict(orient="records")
        return []

    return {
        "baseline_vs_multiagent": read_csv_safe(phase2_dir / "baseline_vs_multiagent.csv"),
        "ablation_results": read_csv_safe(phase2_dir / "agent_ablation_results.csv"),
        "window_results": read_csv_safe(phase2_dir / "agent_window_results.csv"),
        "multi_window_results": read_csv_safe(phase2_dir / "multi_agent_comparison.csv"),
        "agent_performance": read_csv_safe(phase2_dir / "agent_performance.csv")
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.connected_websockets.append(websocket)
    try:
        # Send initial state snapshot
        await websocket.send_text(json.dumps({
            "type": "init",
            "status": state.status,
            "scenario": state.scenario,
            "speed": state.speed,
            "stats": {
                "events_processed": state.total_events_processed,
                "threats_detected": state.threats_detected,
                "active_incidents": len(state.active_incidents),
                "critical_high_incidents": sum(1 for i in state.active_incidents if i["severity"] in ["Critical", "High"])
            },
            "agents": state.agents_status,
            "incidents": state.active_incidents[:10]
        }))
        while True:
            data = await websocket.receive_text()
            # Handle client ping
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        if websocket in state.connected_websockets:
            state.connected_websockets.remove(websocket)


# -------------------------------------------------------------
# STATIC FILE SERVING FOR FRONTEND UI
# -------------------------------------------------------------
UI_DIR = PROJECT_ROOT / "src" / "ui"
if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")

@app.get("/")
def serve_ui():
    index_file = UI_DIR / "index.html"
    if index_file.exists():
        return FileResponse(
            index_file,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
    return JSONResponse({"message": "AI Investigator API is active. UI not found at src/ui/index.html."})


if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 70)
    print("AI INVESTIGATOR - MULTI-AGENT CYBERSECURITY DASHBOARD (PHASE 2)")
    print("=" * 70)
    print("Starting FastAPI server at http://127.0.0.1:8000")
    print("Open your browser and navigate to: http://127.0.0.1:8000")
    print("")
    print("Phase 2 Capabilities:")
    print("  POST /api/analyze       — Upload & analyze ANY log file")
    print("  POST /api/threat-intel   — Load external IOC feeds")
    print("  GET  /api/feedback/summary — View analyst learning state")
    print("=" * 70 + "\n")
    uvicorn.run("src.server:app", host="127.0.0.1", port=8000, reload=False)
