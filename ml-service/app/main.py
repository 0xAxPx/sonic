"""
ML Model Service - FastAPI Application
Serves predictions for network threat detection
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import joblib
import numpy as np
from datetime import datetime
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Threat Detector ML Service",
    description="Machine Learning service for network threat detection",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global model variable
model = None
model_version = "v1.0"
model_loaded_at = None

# Feature names (41 features from NSL-KDD dataset)
FEATURE_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]


class NetworkTrafficFeatures(BaseModel):
    """Model for network traffic features"""
    duration: float = Field(..., description="Connection duration in seconds")
    protocol_type: str = Field(..., description="Protocol type (tcp, udp, icmp)")
    service: str = Field(..., description="Network service (http, ftp, smtp, etc.)")
    flag: str = Field(..., description="Connection status flag")
    src_bytes: int = Field(..., ge=0, description="Bytes sent from source")
    dst_bytes: int = Field(..., ge=0, description="Bytes sent to destination")
    land: int = Field(..., ge=0, le=1, description="1 if connection is from/to same host/port")
    wrong_fragment: int = Field(..., ge=0, description="Number of wrong fragments")
    urgent: int = Field(..., ge=0, description="Number of urgent packets")
    hot: int = Field(..., ge=0, description="Number of hot indicators")
    num_failed_logins: int = Field(..., ge=0, description="Number of failed login attempts")
    logged_in: int = Field(..., ge=0, le=1, description="1 if successfully logged in")
    num_compromised: int = Field(..., ge=0, description="Number of compromised conditions")
    root_shell: int = Field(..., ge=0, le=1, description="1 if root shell obtained")
    su_attempted: int = Field(..., ge=0, le=1, description="1 if su root attempted")
    num_root: int = Field(..., ge=0, description="Number of root accesses")
    num_file_creations: int = Field(..., ge=0, description="Number of file creation operations")
    num_shells: int = Field(..., ge=0, description="Number of shell prompts")
    num_access_files: int = Field(..., ge=0, description="Number of access control file operations")
    num_outbound_cmds: int = Field(..., ge=0, description="Number of outbound commands")
    is_host_login: int = Field(..., ge=0, le=1, description="1 if login belongs to host list")
    is_guest_login: int = Field(..., ge=0, le=1, description="1 if guest login")
    count: int = Field(..., ge=0, description="Connections to same host in past 2 seconds")
    srv_count: int = Field(..., ge=0, description="Connections to same service in past 2 seconds")
    serror_rate: float = Field(..., ge=0, le=1, description="% of connections with SYN errors")
    srv_serror_rate: float = Field(..., ge=0, le=1, description="% of connections to same service with SYN errors")
    rerror_rate: float = Field(..., ge=0, le=1, description="% of connections with REJ errors")
    srv_rerror_rate: float = Field(..., ge=0, le=1, description="% of connections to same service with REJ errors")
    same_srv_rate: float = Field(..., ge=0, le=1, description="% of connections to same service")
    diff_srv_rate: float = Field(..., ge=0, le=1, description="% of connections to different services")
    srv_diff_host_rate: float = Field(..., ge=0, le=1, description="% of connections to different hosts")
    dst_host_count: int = Field(..., ge=0, description="Count of connections to destination host")
    dst_host_srv_count: int = Field(..., ge=0, description="Count of connections to destination service")
    dst_host_same_srv_rate: float = Field(..., ge=0, le=1, description="% of same service connections to dst host")
    dst_host_diff_srv_rate: float = Field(..., ge=0, le=1, description="% of different service connections to dst host")
    dst_host_same_src_port_rate: float = Field(..., ge=0, le=1, description="% of same source port to dst host")
    dst_host_srv_diff_host_rate: float = Field(..., ge=0, le=1, description="% of different hosts to dst service")
    dst_host_serror_rate: float = Field(..., ge=0, le=1, description="% of SYN errors to dst host")
    dst_host_srv_serror_rate: float = Field(..., ge=0, le=1, description="% of SYN errors to dst service")
    dst_host_rerror_rate: float = Field(..., ge=0, le=1, description="% of REJ errors to dst host")
    dst_host_srv_rerror_rate: float = Field(..., ge=0, le=1, description="% of REJ errors to dst service")


class PredictionResponse(BaseModel):
    """Response model for predictions"""
    prediction: str = Field(..., description="Prediction: 'normal' or 'malicious'")
    confidence: float = Field(..., description="Confidence score (0-1)")
    threat_type: Optional[str] = Field(None, description="Type of threat if malicious")
    model_version: str = Field(..., description="Model version used")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class BatchPredictionRequest(BaseModel):
    """Request model for batch predictions"""
    features: List[NetworkTrafficFeatures]


class BatchPredictionResponse(BaseModel):
    """Response model for batch predictions"""
    predictions: List[PredictionResponse]
    total_processed: int
    processing_time_ms: float


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    model_loaded: bool
    model_version: Optional[str]
    model_loaded_at: Optional[datetime]
    uptime_seconds: float


def load_model():
    """Load the trained ML model"""
    global model, model_loaded_at
    
    model_path = os.getenv("MODEL_PATH", "/app/model/rf_model.pkl")
    
    try:
        if os.path.exists(model_path):
            model = joblib.load(model_path)
            model_loaded_at = datetime.utcnow()
            logger.info(f"Model loaded successfully from {model_path}")
            return True
        else:
            logger.warning(f"Model file not found at {model_path}")
            logger.info("Model will need to be trained first")
            return False
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return False


def preprocess_features(features: NetworkTrafficFeatures) -> np.ndarray:
    """
    Convert NetworkTrafficFeatures to numpy array
    In production, you'd also handle categorical encoding here
    """
    # For now, this is a simplified version
    # In real implementation, encode categorical variables (protocol_type, service, flag)
    feature_dict = features.dict()
    
    # Extract numeric features (excluding categorical for now - will need encoding)
    numeric_features = [
        features.duration, features.src_bytes, features.dst_bytes,
        features.land, features.wrong_fragment, features.urgent, features.hot,
        features.num_failed_logins, features.logged_in, features.num_compromised,
        features.root_shell, features.su_attempted, features.num_root,
        features.num_file_creations, features.num_shells, features.num_access_files,
        features.num_outbound_cmds, features.is_host_login, features.is_guest_login,
        features.count, features.srv_count, features.serror_rate,
        features.srv_serror_rate, features.rerror_rate, features.srv_rerror_rate,
        features.same_srv_rate, features.diff_srv_rate, features.srv_diff_host_rate,
        features.dst_host_count, features.dst_host_srv_count,
        features.dst_host_same_srv_rate, features.dst_host_diff_srv_rate,
        features.dst_host_same_src_port_rate, features.dst_host_srv_diff_host_rate,
        features.dst_host_serror_rate, features.dst_host_srv_serror_rate,
        features.dst_host_rerror_rate, features.dst_host_srv_rerror_rate
    ]
    
    # TODO: Add categorical encoding for protocol_type, service, flag
    # For now, using placeholder values
    
    return np.array(numeric_features).reshape(1, -1)


@app.on_event("startup")
async def startup_event():
    """Load model on startup"""
    logger.info("Starting ML Service...")
    load_model()


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    import time
    uptime = time.time() - (model_loaded_at.timestamp() if model_loaded_at else time.time())
    
    return HealthResponse(
        status="healthy" if model is not None else "degraded",
        model_loaded=model is not None,
        model_version=model_version if model is not None else None,
        model_loaded_at=model_loaded_at,
        uptime_seconds=uptime
    )


@app.post("/predict", response_model=PredictionResponse)
async def predict(features: NetworkTrafficFeatures):
    """
    Make a single prediction
    """
    if model is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please train and load the model first."
        )
    
    try:
        # Preprocess features
        feature_array = preprocess_features(features)
        
        # Make prediction
        prediction = model.predict(feature_array)[0]
        confidence = float(np.max(model.predict_proba(feature_array)))
        
        # Map prediction to label
        prediction_label = "malicious" if prediction == 1 else "normal"
        threat_type = "unknown" if prediction == 1 else None
        
        return PredictionResponse(
            prediction=prediction_label,
            confidence=confidence,
            threat_type=threat_type,
            model_version=model_version
        )
        
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")


@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(request: BatchPredictionRequest):
    """
    Make batch predictions
    """
    if model is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please train and load the model first."
        )
    
    import time
    start_time = time.time()
    
    predictions = []
    
    try:
        for features in request.features:
            feature_array = preprocess_features(features)
            prediction = model.predict(feature_array)[0]
            confidence = float(np.max(model.predict_proba(feature_array)))
            
            prediction_label = "malicious" if prediction == 1 else "normal"
            threat_type = "unknown" if prediction == 1 else None
            
            predictions.append(PredictionResponse(
                prediction=prediction_label,
                confidence=confidence,
                threat_type=threat_type,
                model_version=model_version
            ))
        
        processing_time = (time.time() - start_time) * 1000  # Convert to ms
        
        return BatchPredictionResponse(
            predictions=predictions,
            total_processed=len(predictions),
            processing_time_ms=processing_time
        )
        
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        raise HTTPException(status_code=500, detail=f"Batch prediction failed: {str(e)}")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Threat Detector ML Service",
        "version": "1.0.0",
        "model_version": model_version,
        "model_loaded": model is not None,
        "endpoints": {
            "health": "/health",
            "predict": "/predict",
            "batch_predict": "/predict/batch",
            "docs": "/docs"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)