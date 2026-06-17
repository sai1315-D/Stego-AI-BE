from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api import auth, scan, dashboard, settings as api_settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Backend AI-Powered Multi-Format Steganography Detection Engine with digital signal processing (DSP) and statistical features analysis.",
    version="1.0.0"
)

# CORS configuration to allow connections from Flutter Android emulator / mobile clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import os
from fastapi import Response
from fastapi.staticfiles import StaticFiles

# Register routers
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(dashboard.router)
app.include_router(api_settings.router)

# Mount React static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
assets_dir = os.path.join(static_dir, "assets")
os.makedirs(assets_dir, exist_ok=True)

app.mount("/assets", StaticFiles(directory=assets_dir), name="static_assets")

@app.get("/{fallback_path:path}")
async def catch_all(fallback_path: str):
    # Exclude API endpoints or docs to allow default FastAPI 404s
    if fallback_path.startswith(("auth/", "dashboard", "scan-history", "threat-reports", "settings", "docs", "openapi.json")):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Not Found")
        
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        try:
            with open(index_path, "r", encoding="utf-8") as f:
                content = f.read()
            return Response(content=content, media_type="text/html")
        except Exception:
            pass
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "api_docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

