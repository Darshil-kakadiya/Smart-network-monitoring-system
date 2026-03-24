from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI(title="Real-Time Hotspot Monitor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure directories exist
os.makedirs("static/js", exist_ok=True)
os.makedirs("static/css", exist_ok=True)
os.makedirs("templates", exist_ok=True)

# Mount static and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Global states managed by main.py
devices_state = []
usage_state = {}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the frontend dashboard."""
    # We will provide a simple index.html fallback if it doesn't exist
    if not os.path.exists("templates/index.html"):
        return HTMLResponse("<h1>Dashboard UI not fully built yet.</h1>")
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/devices")
def get_devices():
    """Returns the list of currently connected devices."""
    return devices_state

@app.get("/usage")
def get_usage():
    """Returns the cumulative bandwidth usage per IP (in bytes)."""
    return usage_state
