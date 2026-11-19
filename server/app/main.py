import asyncio
import contextlib
import logging

from fastapi import FastAPI

from .admin.bind import BindState
from .api.routes import Notifier, router
from .auth import NonceCache
from .config import MAX_BODY, ENVELOPE_SIZE, Settings
from .db.store import Store
from .limits.rate import Limiter
from .limits.validation import BodyLimit

log = logging.getLogger("noc")


def create_app(settings: Settings, bind: BindState | None = None) -> FastAPI:
    store = Store(settings.db_path, settings.db_key_hex, ENVELOPE_SIZE)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async def cleaner():
            while True:
                await asyncio.sleep(settings.cleanup_interval_s)
                n = store.purge_expired()
                if n:
                    log.info("purged %d expired packets", n)
        task = asyncio.create_task(cleaner())
        yield
        task.cancel()
        store.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings, app.state.store = settings, store
    app.state.nonces, app.state.notifier = NonceCache(), Notifier()
    app.state.bind = bind or BindState()
    app.state.put_limit = Limiter(settings.put_rate_per_min)
    app.state.prekey_limit = Limiter(settings.prekey_rate_per_min)
    app.add_middleware(BodyLimit, max_body=MAX_BODY)
    app.include_router(router)
    return app
