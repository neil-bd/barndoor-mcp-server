# app.py
"""
ASGI entrypoint (Starlette) for FastMCP Streamable HTTP + CORS.

Run:
  uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}
"""

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route, Mount

from server import mcp

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],          # tighten later if you want
        allow_methods=["*"],
        allow_headers=["*"],          # must allow X-Barndoor-* headers
        expose_headers=["Mcp-Session-Id"],
    )
]

# Build the FastMCP ASGI app mounted at /mcp
mcp_app = mcp.http_app(path="/mcp", middleware=middleware)


async def health(_request):
    return PlainTextResponse("ok")


# ✅ IMPORTANT: forward FastMCP lifespan so its session manager initializes
app = Starlette(
    routes=[
        Route("/health", health, methods=["GET"]),
        Mount("/", app=mcp_app),
    ],
    lifespan=mcp_app.lifespan,
)
