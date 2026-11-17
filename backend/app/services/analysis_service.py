
from backend.app.modules.package_extractor import extract_packages

from backend.app.modules.package_verifier import verify_package

from backend.app.modules.package_similarity import analyze_similarity

from backend.app.modules.package_security import analyze_package_security

from backend.app.modules.risk_engine import calculate_package_risk


def analyze_source_code(source_code):
    """
    Complete PackageSentinel analysis pipeline.

    Extract -> Verify -> Analyze -> Score -> Report
    """

    # -----------------------------------
    # STEP 1: Extract packages
    # -----------------------------------

    extraction = extract_packages(source_code)

    if not extraction.get("success"):

        return {
            "success": False,
            "message": "Unable to parse submitted Python code",
            "error": extraction.get("error"),
            "results": []
        }

    extracted_packages = extraction.get("packages", [])

    standard_library = []
    external_packages = []

    for package in extracted_packages:

        if package["type"] == "standard_library":
            standard_library.append(package)

        else:
            external_packages.append(package)

    analysis_results = []

    # -----------------------------------
    # STEP 2: Verify and analyze packages
    # -----------------------------------

    for package in external_packages:

        package_name = package["package_name"]

        # Registry verification

        verification = verify_package(package_name)

        # Similarity detection

        similarity = analyze_similarity(package_name)

        # Security analysis

        security = {
            "package_name": package_name,
            "analysis_success": False,
            "findings": [],
            "dependencies": [],
            "message": "Security analysis not completed"
        }

        if verification.get("exists") is True:

            distribution_name = verification.get(
                "distribution_name",
                package_name
            )

            security = analyze_package_security(
                distribution_name
            )

        # -----------------------------------
        # STEP 3: Risk assessment
        # -----------------------------------

        risk = calculate_package_risk(
            verification=verification,
            similarity=similarity,
            security=security
        )

        # -----------------------------------
        # STEP 4: Combine package results
        # -----------------------------------

        analysis_results.append({

            "package_name": package_name,

            "line_number": package["line_number"],

            "verification": verification,

            "similarity": similarity,

            "security": security,

            "risk_assessment": risk

        })

    # -----------------------------------
    # STEP 5: Generate summary
    # -----------------------------------

    risk_summary = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

    for result in analysis_results:

        risk_level = result["risk_assessment"]["risk_level"]

        risk_summary[risk_level] += 1

    return {

        "success": True,

        "message": "PackageSentinel analysis completed",

        "summary": {

            "total_extracted": len(extracted_packages),

            "external_packages": len(external_packages),

            "standard_library_modules": len(standard_library),

            "successfully_verified": sum(
                1 for item in analysis_results
                if item["verification"].get("exists") is True
            ),

            "not_found_packages": sum(
                1 for item in analysis_results
                if item["verification"].get("exists") is False
            ),

            "verification_incomplete": sum(
                1 for item in analysis_results
                if item["verification"].get("exists") is None
            ),

            "risk_distribution": risk_summary

        },

        "standard_library_modules": standard_library,

        "package_results": analysis_results

    }
