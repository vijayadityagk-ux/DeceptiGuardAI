import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, Boolean, JSON, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from .database import Base

def generate_uuid():
    return str(uuid.uuid4())

class ThreatLog(Base):
    __tablename__ = "threat_scans"

    id = Column(String, primary_key=True, default=generate_uuid)
    url = Column(Text, nullable=False)
    final_url = Column(Text, nullable=True)
    context_message = Column(Text, nullable=True)
    detected_language = Column(String, default="English")
    
    threat_level = Column(String, default="SAFE")  # SAFE (0-30), SUSPICIOUS (31-65), MALICIOUS (66-100)
    risk_score = Column(Float, default=0.0)        # 0.0 to 100.0
    target_brand = Column(String, nullable=True)
    summary = Column(Text, nullable=True)
    
    # 6 Individual Factor Analysis Results
    factor_message_suspicion = Column(JSON, nullable=True)
    factor_url_domain_name = Column(JSON, nullable=True)
    factor_url_legitness = Column(JSON, nullable=True)
    factor_brand_spoofing = Column(JSON, nullable=True)
    factor_malicious_intent = Column(JSON, nullable=True)
    factor_deceptive_claims = Column(JSON, nullable=True)
    
    # Raw Analysis & Telemetry
    linguistic_analysis = Column(JSON, nullable=True)
    visual_analysis = Column(JSON, nullable=True)
    technical_indicators = Column(JSON, nullable=True)
    
    screenshot_filename = Column(String, nullable=True)
    status = Column(String, default="PENDING")     # PENDING, PROCESSING, COMPLETED, FAILED
    honeypot_triggered = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    honeypot_logs = relationship("HoneypotLog", back_populates="threat_scan", cascade="all, delete-orphan")


# Alias ThreatScan to ThreatLog for compatibility
ThreatScan = ThreatLog


class HoneypotLog(Base):
    __tablename__ = "honeypot_logs"

    id = Column(String, primary_key=True, default=generate_uuid)
    threat_id = Column(String, ForeignKey("threat_scans.id"), nullable=False)
    target_url = Column(Text, nullable=False)
    form_action = Column(Text, nullable=True)
    form_method = Column(String, default="POST")
    
    credentials_injected = Column(JSON, nullable=True)
    status = Column(String, default="SUCCESS")     # SUCCESS, FAILED, IN_PROGRESS
    http_status = Column(String, nullable=True)
    redirect_url = Column(Text, nullable=True)
    
    attacker_resource_wasted_seconds = Column(Float, default=0.0)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    threat_scan = relationship("ThreatLog", back_populates="honeypot_logs")

