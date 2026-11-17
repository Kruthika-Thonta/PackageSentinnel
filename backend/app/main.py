
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional

from backend.app.modules.package_extractor import extract_packages
from backend.app.modules.package_verifier import verify_packages
from backend.app.modules.package_similarity import analyze_packages
from backend.app.modules.package_security import analyze_multiple_packages
from backend.app.modules.risk_engine import calculate_multiple_package_risks
from backend.app.services.analysis_service import analyze_source_code


app = FastAPI(
    title="PackageSentinel API",
    description="An LLM-aware framework for detecting "
                "hallucinated and potentially unsafe "
                "software dependencies.",
    version="1.0.0"
)


# Request model for source code
class CodeRequest(BaseModel):
    code: str


# Request model for individual packages
class PackageRequest(BaseModel):
    package_name: str
    requested_version: Optional[str] = None


# Request model for multiple packages
class VerifyRequest(BaseModel):
    packages: List[PackageRequest]

class SimilarityRequest(BaseModel):
    packages: List[str]

class SecurityRequest(BaseModel):
    packages: List[str]

class RiskAssessmentRequest(BaseModel):
    packages: List[dict]


@app.get("/")
def home():
    return {
        "message": "Welcome to PackageSentinel",
        "status": "Running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "application": "PackageSentinel"
    }


# Package extraction API
@app.post("/extract-packages")
def extract_package_api(request: CodeRequest):

    result = extract_packages(request.code)

    return result


# Package registry verification API
@app.post("/verify-packages")
def verify_package_api(request: VerifyRequest):

    package_list = [
        package.dict()
        for package in request.packages
    ]

    result = verify_packages(package_list)

    return result

# Package similarity detection API
@app.post("/analyze-similarity")
def analyze_similarity_api(request: SimilarityRequest):

    result = analyze_packages(request.packages)

    return result

# Package security analysis API
@app.post("/analyze-security")
def analyze_security_api(request: SecurityRequest):

    result = analyze_multiple_packages(request.packages)

    return result

# Risk assessment API
@app.post("/assess-risk")
def assess_risk_api(request: RiskAssessmentRequest):

    result = calculate_multiple_package_risks(
        request.packages
    )

    return result

# Complete PackageSentinel analysis API

@app.post("/analyze-code")
def analyze_code_api(request: CodeRequest):

    result = analyze_source_code(request.code)

    return result