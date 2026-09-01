from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.config import settings

router = APIRouter(tags=["Health"])

@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    return {
        "status": "HEALTHY",
        "project": settings.PROJECT_NAME,
        "short_name": settings.PROJECT_SHORT_NAME,
        "database": "CONNECTED"
    }
