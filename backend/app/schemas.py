from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict
from datetime import datetime

# OCR Image Extraction Response
class ImageExtractionResponse(BaseModel):
    raw_text: str = Field(..., description="Full text extracted via OCR from the uploaded image")
    extracted_urls: List[str] = Field(default_factory=list, description="All URLs segregated from the image")
    primary_url: Optional[str] = Field(None, description="Primary suspicious target URL isolated for scanning")
    extracted_message: Optional[str] = Field(None, description="Extracted lure message or email body content")
    detected_language: str = Field(default="English", description="Auto-detected language of the text")
    confidence: float = Field(default=0.95, description="OCR extraction confidence score")

# Scan Request Payload
class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect")
    context_message: Optional[str] = Field(None, description="Accompanying email or SMS lure message text")

# Factor Detail Schema for each of the 6 factors
class FactorDetail(BaseModel):
    factor_name: str
    rating: str = "SAFE"  # SAFE, SUSPICIOUS, MALICIOUS, CRITICAL
    score: float = 0.0    # 0.0 to 100.0
    title: str = ""
    explanation: str = ""
    highlight_badge: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

# 6 Factor Analysis Schema
class SixFactorAnalysis(BaseModel):
    message_suspicion: FactorDetail
    url_domain_name: FactorDetail
    url_legitness: FactorDetail
    brand_spoofing: FactorDetail
    malicious_intent: FactorDetail
    deceptive_claims: FactorDetail

# Visual Analysis Schema
class VisualAnalysis(BaseModel):
    is_brand_spoofing: bool = False
    impersonated_brand: Optional[str] = None
    brand_confidence_score: float = 0.0
    visual_anomalies: List[str] = []
    fake_login_detected: bool = False
    logo_and_layout_assessment: Optional[str] = None

# Linguistic Analysis Schema
class LinguisticAnalysis(BaseModel):
    urgency_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    deceptive_claims: List[str] = []
    suspicious_requests: List[str] = []
    intent_summary: Optional[str] = None
    contributing_factors: List[str] = []

# Technical Indicators
class FormInput(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None
    type: Optional[str] = None
    placeholder: Optional[str] = None
    autocomplete: Optional[str] = None
    label: Optional[str] = None

class FormElement(BaseModel):
    action: Optional[str] = None
    method: Optional[str] = "POST"
    inputs: List[FormInput] = []

class TechnicalIndicators(BaseModel):
    has_https: bool = True
    redirect_count: int = 0
    redirect_chain: List[str] = []
    forms_detected: int = 0
    password_fields_detected: int = 0
    email_fields_detected: int = 0
    obfuscation_tokens_found: List[str] = []
    forms: List[FormElement] = []

# Honeypot Log Schema
class HoneypotLogSchema(BaseModel):
    id: str
    threat_id: str
    target_url: str
    form_action: Optional[str]
    form_method: Optional[str]
    credentials_injected: Optional[Dict[str, Any]]
    status: str
    http_status: Optional[str]
    redirect_url: Optional[str]
    attacker_resource_wasted_seconds: float
    notes: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

# Threat Log / Scan Detail Response
class ThreatLogResponse(BaseModel):
    id: str
    url: str
    final_url: Optional[str] = None
    context_message: Optional[str] = None
    detected_language: str = "English"
    
    threat_level: str = "SAFE"  # SAFE (0-30), SUSPICIOUS (31-65), MALICIOUS (66-100)
    risk_score: float = 0.0     # 0.0 to 100.0
    target_brand: Optional[str] = None
    summary: Optional[str] = None
    
    # 6 Individual Factors
    factor_message_suspicion: Optional[Dict[str, Any]] = None
    factor_url_domain_name: Optional[Dict[str, Any]] = None
    factor_url_legitness: Optional[Dict[str, Any]] = None
    factor_brand_spoofing: Optional[Dict[str, Any]] = None
    factor_malicious_intent: Optional[Dict[str, Any]] = None
    factor_deceptive_claims: Optional[Dict[str, Any]] = None
    
    # Raw Analysis Details
    linguistic_analysis: Optional[Dict[str, Any]] = None
    visual_analysis: Optional[Dict[str, Any]] = None
    technical_indicators: Optional[Dict[str, Any]] = None
    screenshot_filename: Optional[str] = None
    status: str = "COMPLETED"
    honeypot_triggered: bool = False
    created_at: datetime
    updated_at: datetime
    honeypot_logs: List[HoneypotLogSchema] = []

    class Config:
        from_attributes = True

# Alias for backwards compatibility
ThreatScanResponse = ThreatLogResponse

# WebSocket Pipeline Event
class WebSocketEvent(BaseModel):
    job_id: str
    step: str
    progress_percent: int
    message: str
    timestamp: str
    payload: Dict[str, Any] = {}

