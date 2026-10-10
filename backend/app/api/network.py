from fastapi import APIRouter
from app.services.network_service import get_network_interfaces
from app.schemas.network import InterfacesResponse, NetworkInterface

router = APIRouter()


@router.get("/network/interfaces", response_model=InterfacesResponse)
async def list_interfaces():
    raw = get_network_interfaces()
    interfaces = [NetworkInterface(**item) for item in raw]
    return InterfacesResponse(interfaces=interfaces)
