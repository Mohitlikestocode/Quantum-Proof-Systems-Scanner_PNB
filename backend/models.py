from pydantic import BaseModel, Field
from typing import List, Optional, Literal

class HostInfo(BaseModel):
    provider: str
    type: str

class Vulnerability(BaseModel):
    type: str
    severity: str

class MobileApp(BaseModel):
    platform: str
    name: str
    risk_score: Optional[int] = None

class SubdomainInfo(BaseModel):
    subdomain: str
    status: str
    is_active: bool
    connection_successful: bool
    tls_versions: List[str] = Field(default_factory=list)
    cipher_suite: Optional[str] = None
    key_size: Optional[int] = None
    certificate_issuer: Optional[str] = None
    expiry_date: Optional[str] = None
    days_to_expiry: Optional[int] = None
    algorithm: Optional[str] = None
    response_time_ms: Optional[int] = None
    has_vulnerabilities: bool = False
    certificate_valid: bool = False
    ssl_rating: Optional[str] = None

class RiskScore(BaseModel):
    score: int
    score_pre_overrides: Optional[int] = None
    total_penalty: Optional[float] = None
    risk_level: str
    status: str
    label: str
    category: Optional[str] = None
    formula_version: Optional[str] = None
    weights: Optional[dict] = None
    components: Optional[dict] = None
    adjustments: Optional[List[str]] = None
    baseline_score: Optional[int] = None
    improvement: Optional[str] = None

class ScanResult(BaseModel):
    tls_version: str
    cipher_suite: str
    key_size: int
    certificate_issuer: str
    expiry_date: str
    algorithm: str
    days_to_expiry: int
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    
    # Subdomain discovery fields
    all_subdomains_detailed: List[SubdomainInfo] = Field(default_factory=list)
    active_subdomains: List[SubdomainInfo] = Field(default_factory=list)
    inactive_subdomains: List[SubdomainInfo] = Field(default_factory=list)
    pqc_ready_subdomains: List[SubdomainInfo] = Field(default_factory=list)
    standard_subdomains: List[SubdomainInfo] = Field(default_factory=list)
    critical_subdomains: List[SubdomainInfo] = Field(default_factory=list)
    
    # Metadata
    vulnerabilities: List[dict] = Field(default_factory=list)
    hosting: Optional[dict] = None
    mobile_info: Optional[dict] = None
    subdomains_discovery: Optional[dict] = None
    subdomains_info: Optional[dict] = None
    scan_timestamp: Optional[str] = None
    full_scan: Optional[bool] = None

class Asset(BaseModel):
    id: str
    type: str
    name: str 
    detection_date: str
    status: str
    vendor: str
    region: str
    ip_address: Optional[str] = None
    risk: Optional[RiskScore] = None
    scan_result: Optional[ScanResult] = None
    metadata: dict = Field(default_factory=dict)
    
    # Module additions
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    hosting: Optional[HostInfo] = None
    mobile_apps: List[MobileApp] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)
    is_active: bool = True

# Action-Based Chatbot Models
class ChatCommand(BaseModel):
    action: str
    parameters: dict
    explanation: str
