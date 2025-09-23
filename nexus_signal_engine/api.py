"""REST API for Nexus Signal Engine."""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uvicorn

app = FastAPI(
    title="Nexus Signal Engine API",
    description="Enterprise API for Nexus Signal Engine",
    version="1.0.0"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class MessageInput(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)
    context: Optional[Dict[str, Any]] = None

class AnalysisResult(BaseModel):
    is_safe: bool
    risk_score: float
    risk_factors: List[str]
    analysis_id: str

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_message(
    message: MessageInput,
    background_tasks: BackgroundTasks,
    token: str = Depends(oauth2_scheme)
):
    """Analyze a message for potential risks."""
    try:
        # Initialize engine with proper context
        from nexus_signal_engine import NexisSignalEngine
        engine = NexisSignalEngine()
        
        # Process the message
        result = engine.evaluate_message_safety(message.text)
        
        # Add to background processing queue
        background_tasks.add_task(engine._backup_database)
        
        return {
            "is_safe": result[0],
            "risk_score": result[1]["risk_score"],
            "risk_factors": result[1]["risk_factors"],
            "analysis_id": result[1].get("hash", "N/A")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

def start_server():
    """Start the API server."""
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    start_server()