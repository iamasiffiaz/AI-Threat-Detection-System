"""
Pydantic schemas for anomaly detection results and LLM explanations.
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class AnomalyResponse(BaseModel):
    id: int
    log_entry_id: int
    anomaly_score: float
    model_name: str
    feature_vector: Optional[dict]
    source_ip: Optional[str]
    event_type: Optional[str]
    explanation: Optional[str]
    detected_at: datetime

    model_config = {"from_attributes": True}


class AnomalyDetectionRequest(BaseModel):
    log_entry_ids: List[int] = Field(..., min_length=1, max_length=1000)


class LLMExplanationRequest(BaseModel):
    anomaly_id: Optional[int] = None
    alert_id: Optional[int] = None
    context: str = Field(..., description="Contextual information for the LLM to analyze")


class LLMExplanationResponse(BaseModel):
    explanation: str
    attack_type: str
    confidence: str
    mitigation_steps: List[str]
    references: List[str] = []


class AnomalyTrend(BaseModel):
    timestamp: datetime
    count: int
    avg_score: float


class ModelInfo(BaseModel):
    model_name: str
    algorithm: str
    trained_at: Optional[datetime]
    training_samples: int
    threshold: float
    is_trained: bool
