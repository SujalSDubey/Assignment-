from fastapi import APIRouter, Body
from app.services.parser import parse_spec
from app.services.validator import validate_spec
from app.services.scorer import run_security_checks
from app.services.scorer import calculate_security_score
from fastapi import UploadFile, File, HTTPException
from app.services.fetcher import fetch_spec_from_url
from app.utils.helpers import group_findings



router = APIRouter(prefix="/analyze", tags=["Analyzer"])


@router.post("/")
async def analyze_spec(
    spec_text: str = Body(..., media_type="text/plain")
):
    spec = parse_spec(None, spec_text)
    validate_spec(spec)
    findings = run_security_checks(spec)

    score = calculate_security_score(findings)

    return {
        "total_issues": len(findings),
        "security_score": score,
        "findings": findings
    }




@router.post("/file")
async def analyze_spec_file(
    file: UploadFile = File(...)
):
    try:
        if not file.filename.endswith((".yaml", ".yml", ".json")):
            raise HTTPException(
                status_code=400,
                detail="Only .yaml, .yml, or .json files are supported"
            )

        spec = parse_spec(file, None)
        validate_spec(spec)

        findings = run_security_checks(spec)
        score = calculate_security_score(findings)

        return {
            "filename": file.filename,
            "total_issues": len(findings),
            "security_score": score,
            "findings": findings
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")
    



@router.post("/url")
async def analyze_spec_url(url: str):
    try:
        # Fetch spec from URL
        spec_text = fetch_spec_from_url(url)

        # Parse & validate
        spec = parse_spec(None, spec_text)
        validate_spec(spec)

        # Analyze
        findings = run_security_checks(spec)
        score = calculate_security_score(findings)

        grouped = group_findings(findings)

        return {
            "total_issues": len(findings),
            "grouped_issues": len(grouped),
            "security_score": score,
            "findings": grouped
        }


    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")

