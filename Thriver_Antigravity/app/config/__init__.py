import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict

class Settings(BaseSettings):
    PROJECT_NAME: str = "RISKIQX CYBER INCIDENT PRIORITIZATION & SOC INTELLIGENCE PLATFORM"
    PROJECT_SHORT_NAME: str = "RiskIQX"
    API_V1_STR: str = "/api/v1"
    
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:////tmp/riskiqx.db" if os.getenv("VERCEL") else "sqlite:///./riskiqx.db")
    
    # Default Scoring Weights (Must sum to 1.0)
    DEFAULT_WEIGHT_SEVERITY: float = 0.25
    DEFAULT_WEIGHT_ASSET: float = 0.20
    DEFAULT_WEIGHT_USERS: float = 0.15
    DEFAULT_WEIGHT_DATA: float = 0.15
    DEFAULT_WEIGHT_CONFIDENCE: float = 0.15
    DEFAULT_WEIGHT_IMPACT: float = 0.10
    
    # Priority Score Thresholds (0 - 100)
    THRESHOLD_CRITICAL: float = 90.0
    THRESHOLD_HIGH: float = 75.0
    THRESHOLD_MEDIUM: float = 50.0
    THRESHOLD_LOW: float = 25.0
    
    # SLA Hours Configuration
    SLA_CRITICAL_HOURS: float = 0.25  # 15 mins
    SLA_HIGH_HOURS: float = 0.50      # 30 mins
    SLA_MEDIUM_HOURS: float = 4.0     # 4 hours
    SLA_LOW_HOURS: float = 24.0       # 24 hours
    
    # Correlation & Deduplication Sliding Windows (seconds)
    DEDUPLICATION_WINDOW_SECONDS: int = 300   # 5 mins
    CORRELATION_WINDOW_SECONDS: int = 3600    # 1 hour
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
