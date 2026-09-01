from fastapi import APIRouter
from app.api.v1 import health, events, detections, incidents, cases, config, analytics, simulator

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(events.router)
api_router.include_router(detections.router)
api_router.include_router(incidents.router)
api_router.include_router(cases.router)
api_router.include_router(config.router)
api_router.include_router(analytics.router)
api_router.include_router(simulator.router)
