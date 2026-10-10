import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """
    Fixture that redirects DB_PATH to a temporary directory so tests
    never touch the real analyzer.db. Calls init_db() to create schema.
    """
    import app.database.db as db_module
    from app.database.db import init_db

    test_db = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_PATH", test_db)
    init_db()
    return test_db
