from fastapi import APIRouter
from app.services.nmap_service import check_nmap_available

router = APIRouter()


@router.get("/health")
async def health_check():
    return {
        "status": "ok",
        "nmap_available": check_nmap_available(),
        "version": "1.0.0",
    }
