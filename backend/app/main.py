from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import health, network, scans, devices, findings, reports
from app.database.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database on startup."""
    init_db()
    yield


app = FastAPI(
    title="Wi-Fi/LAN Security Analyzer",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api")
app.include_router(network.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(devices.router, prefix="/api")
app.include_router(findings.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
