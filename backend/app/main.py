import os
import asyncio
import logging
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List, Optional

from .database import engine, get_db, Base
from .models import ThreatLog, ThreatScan, HoneypotLog
from .schemas import ScanRequest, ThreatLogResponse, ThreatScanResponse, HoneypotLogSchema, ImageExtractionResponse
from .websocket_manager import manager
from .playwright_sandbox import sandbox, SCREENSHOT_DIR
from .gemini_engine import gemini_engine
from .honeypot_agent import honeypot_agent

# Initialize database tables
Base.metadata.create_all(bind=engine)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("deceptiguard.main")

app = FastAPI(
    title="DeceptiGuard Cyber Intelligence & Honeypot Platform API",
    description="Autonomous zero-day phishing detection, OCR screenshot text extraction, 6-factor multilingual analysis, and active Playwright decoy honeypot countermeasure engine.",
    version="2.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    return {
        "status": "ONLINE",
        "system": "DeceptiGuard Cyber Intelligence Platform",
        "version": "2.0.0",
        "engine": "Zero-Trust Sandbox + Gemini 3.7 Flash Multimodal AI"
    }


@app.post("/api/v1/extract-from-image", response_model=ImageExtractionResponse)
async def extract_from_image(file: UploadFile = File(...)):
    """
    Extracts visible text and segregates suspicious URLs from uploaded screenshot images (emails, SMS, DMs, pages)
    using Gemini Multimodal Vision OCR.
    """
    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded image is empty")

        extraction_result = await gemini_engine.extract_text_and_urls_from_image(content, filename=file.filename or "upload.png")
        return extraction_result
    except Exception as e:
        logger.error(f"Image extraction error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Image text extraction failed: {str(e)}")


async def run_scan_pipeline(scan_id: str, target_url: str, context_message: Optional[str], db_session_factory):
    """
    Executes the comprehensive 7-stage DeceptiGuard scanning & countermeasure pipeline:
    1. INITIALIZING (15%) - Sandbox Container Provisioning
    2. SANDBOX_BROWSING (35%) - Isolated DOM De-cloaking & Telemetry
    3. SCREENSHOT_CAPTURED (55%) - High-Res Viewport Screenshot Captured
    4. FACTOR_ANALYSIS (75%) - 6-Factor Multilingual Gemini Analysis (Message Suspicion, URL Domain, URL Legitness, Brand Spoofing, Malicious Intent, Deceptive Claims)
    5. HONEYPOT_SYNTHESIS (85%) - Decoy Credential Synthesis
    6. HONEYPOT_INJECTION (92%) - Playwright Tarpitting & Countermeasure Injection
    7. COMPLETED (100%) - Intelligence Dossier Assembled
    """
    db = db_session_factory()
    try:
        scan_record = db.query(ThreatLog).filter(ThreatLog.id == scan_id).first()
        if not scan_record:
            return

        scan_record.status = "PROCESSING"
        db.commit()

        # STEP 1: INITIALIZING (15%)
        await manager.broadcast(scan_id, "INITIALIZING", 15, "Provisioning Zero-Trust isolated Chromium sandbox environment...", {"url": target_url})
        await asyncio.sleep(0.4)

        # STEP 2: SANDBOX_BROWSING (35%)
        await manager.broadcast(scan_id, "SANDBOX_BROWSING", 35, "Executing sandboxed DOM de-cloaking, tracking redirect chains & enumerating form fields...", {})
        sandbox_res = await sandbox.execute_scan(scan_id, target_url)
        
        scan_record.final_url = sandbox_res["final_url"]
        scan_record.screenshot_filename = sandbox_res["screenshot_filename"]
        scan_record.technical_indicators = sandbox_res["technical_indicators"]
        db.commit()

        # STEP 3: SCREENSHOT_CAPTURED (55%)
        await manager.broadcast(
            scan_id, 
            "SCREENSHOT_CAPTURED", 
            55, 
            "High-resolution 1280x800 sandbox viewport screenshot captured & DOM telemetry parsed.", 
            {
                "screenshot_url": f"/storage/screenshots/{sandbox_res['screenshot_filename']}",
                "page_title": sandbox_res["page_title"],
                "forms_count": sandbox_res["technical_indicators"]["forms_detected"]
            }
        )
        await asyncio.sleep(0.4)

        # STEP 4: FACTOR_ANALYSIS (75%)
        await manager.broadcast(scan_id, "AI_MULTIMODAL_ANALYSIS", 75, "Evaluating 6 Threat Factors (Message Suspicion, URL Domain, URL Legitness, Brand Spoofing, Malicious Intent, Deceptive Claims) in detected language...", {})
        ai_res = await gemini_engine.analyze_threat(
            target_url=target_url,
            final_url=sandbox_res["final_url"],
            page_title=sandbox_res["page_title"],
            dom_text=sandbox_res["dom_text"],
            context_message=context_message,
            screenshot_path=sandbox_res["screenshot_path"],
            technical_indicators=sandbox_res["technical_indicators"]
        )

        scan_record.threat_level = ai_res.get("threat_level", "SAFE")
        scan_record.risk_score = ai_res.get("risk_score", 0.0)
        scan_record.target_brand = ai_res.get("target_brand")
        scan_record.detected_language = ai_res.get("detected_language", "English")
        scan_record.summary = ai_res.get("summary")
        
        # Save 6 Factors
        scan_record.factor_message_suspicion = ai_res.get("factor_message_suspicion")
        scan_record.factor_url_domain_name = ai_res.get("factor_url_domain_name")
        scan_record.factor_url_legitness = ai_res.get("factor_url_legitness")
        scan_record.factor_brand_spoofing = ai_res.get("factor_brand_spoofing")
        scan_record.factor_malicious_intent = ai_res.get("factor_malicious_intent")
        scan_record.factor_deceptive_claims = ai_res.get("factor_deceptive_claims")
        
        scan_record.visual_analysis = ai_res.get("visual_analysis")
        scan_record.linguistic_analysis = ai_res.get("linguistic_analysis")
        db.commit()

        # Trigger Active Decoy Honeypot if MALICIOUS or threat score >= 66
        if scan_record.threat_level == "MALICIOUS" and sandbox_res["technical_indicators"]["forms_detected"] > 0:
            # STEP 5: HONEYPOT_SYNTHESIS (85%)
            await manager.broadcast(scan_id, "HONEYPOT_SYNTHESIS", 85, f"Target flagged as {scan_record.threat_level} ({scan_record.risk_score}% Risk). Synthesizing deceptive decoy credentials matching {scan_record.target_brand or 'Target Portal'}...", {})
            decoy_creds = gemini_engine.generate_decoy_credentials(scan_record.target_brand)
            await asyncio.sleep(0.5)

            # STEP 6: HONEYPOT_INJECTION (92%)
            await manager.broadcast(scan_id, "HONEYPOT_INJECTION", 92, "Deploying automated Playwright decoy injector with keystroke delay emulation...", {"decoy_username": decoy_creds["username"]})
            honeypot_res = await honeypot_agent.inject_decoy(
                target_url=sandbox_res["final_url"],
                decoy_credentials=decoy_creds,
                forms_metadata=sandbox_res["technical_indicators"]["forms"]
            )

            # Save Honeypot Log
            log_record = HoneypotLog(
                threat_id=scan_id,
                target_url=sandbox_res["final_url"],
                form_action=honeypot_res.get("form_action"),
                form_method=honeypot_res.get("form_method", "POST"),
                credentials_injected=honeypot_res.get("credentials_injected"),
                status=honeypot_res.get("status", "SUCCESS"),
                http_status=honeypot_res.get("http_status"),
                redirect_url=honeypot_res.get("redirect_url"),
                attacker_resource_wasted_seconds=honeypot_res.get("attacker_resource_wasted_seconds", 0.0),
                notes=honeypot_res.get("notes")
            )
            db.add(log_record)
            scan_record.honeypot_triggered = True
            db.commit()
        else:
            await manager.broadcast(scan_id, "HONEYPOT_SYNTHESIS", 85, "Target evaluated as safe or passive. No active honeypot injection needed.", {})

        # STEP 7: COMPLETED (100%)
        scan_record.status = "COMPLETED"
        db.commit()

        # Send full detail payload
        db.refresh(scan_record)
        response_data = ThreatLogResponse.from_orm(scan_record).dict()
        response_data["created_at"] = response_data["created_at"].isoformat()
        response_data["updated_at"] = response_data["updated_at"].isoformat()
        if "honeypot_logs" in response_data:
            for log in response_data["honeypot_logs"]:
                log["created_at"] = log["created_at"].isoformat()

        await manager.broadcast(
            scan_id, 
            "COMPLETED", 
            100, 
            "Intelligence dossier assembled & 6-factor evaluation complete.", 
            response_data
        )

    except Exception as e:
        logger.error(f"Pipeline error for job {scan_id}: {e}", exc_info=True)
        if scan_record:
            scan_record.status = "FAILED"
            db.commit()
        await manager.broadcast(scan_id, "FAILED", 0, f"Analysis pipeline failed: {str(e)}", {})
    finally:
        db.close()


@app.post("/api/v1/scan", response_model=ThreatLogResponse)
async def initiate_scan(payload: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Creates a scan record and launches the background analysis pipeline.
    """
    scan = ThreatLog(
        url=payload.url,
        context_message=payload.context_message,
        status="PENDING"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Launch async pipeline task
    from .database import SessionLocal
    background_tasks.add_task(run_scan_pipeline, scan.id, payload.url, payload.context_message, SessionLocal)

    return scan


@app.get("/api/v1/scans", response_model=List[ThreatLogResponse])
def list_scans(limit: int = 20, db: Session = Depends(get_db)):
    return db.query(ThreatLog).order_by(ThreatLog.created_at.desc()).limit(limit).all()


@app.get("/api/v1/scans/{scan_id}", response_model=ThreatLogResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ThreatLog).filter(ThreatLog.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Threat scan not found")
    return scan


@app.websocket("/api/v1/ws/scan/{job_id}")
async def websocket_endpoint(websocket: WebSocket, job_id: str):
    """
    WebSocket route streaming real-time pipeline execution updates across all factors.
    """
    await manager.connect(websocket, job_id)
    try:
        while True:
            # Keep socket alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, job_id)


# Mount static directories
app.mount("/storage/screenshots", StaticFiles(directory=SCREENSHOT_DIR), name="screenshots")

frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend"))
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

