from fastapi import FastAPI
from app.routes.analyze import router as analyze_router

app = FastAPI(
    title="OpenAPI Security Analyzer",
    description="Static security analysis tool for OpenAPI specifications",
    version="1.0.0"
)

app.include_router(analyze_router)

@app.get("/")
def health():
    return {"status": "running"}
