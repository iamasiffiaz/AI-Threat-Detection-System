"""
Application configuration management using Pydantic Settings.
All settings are loaded from environment variables with sensible defaults.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import List


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "AI Threat Detection System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"

    # API
    API_V1_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/threat_detection"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_CACHE_TTL: int = 300  # 5 minutes

    # JWT Authentication
    SECRET_KEY: str = "super-secret-key-change-in-production-min-32-chars"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Ollama LLM
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"
    OLLAMA_TIMEOUT: int = 60

    # ML Model
    ANOMALY_THRESHOLD: float = 0.6
    MODEL_RETRAIN_INTERVAL_HOURS: int = 24
    MIN_TRAINING_SAMPLES: int = 100

    # Alert Settings
    ALERT_COOLDOWN_SECONDS: int = 300
    MAX_ALERTS_PER_IP_PER_HOUR: int = 10

    # Rule Engine
    FAILED_LOGIN_THRESHOLD: int = 5
    PORT_SCAN_THRESHOLD: int = 20
    TRAFFIC_SPIKE_MULTIPLIER: float = 3.0

    # File Upload
    MAX_UPLOAD_SIZE_MB: int = 50
    ALLOWED_UPLOAD_EXTENSIONS: List[str] = [".csv", ".json", ".log", ".txt"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
