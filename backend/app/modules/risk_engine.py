
def calculate_package_risk(
    verification,
    similarity,
    security
):
    """
    Calculate an explainable risk score
    using verification, similarity and
    security analysis results.
    """

    score = 0
    evidence = []

    package_name = (
        verification.get("package_name")
        or similarity.get("package_name")
        or security.get("package_name")
        or "Unknown"
    )

    # 1. Package existence verification

    if verification.get("exists") is False:
        score += 50

        evidence.append({
            "category": "package_existence",
            "points": 50,
            "description": "Package was not found on PyPI"
        })

    # 2. Version verification

    if verification.get("version_valid") is False:
        score += 25

        evidence.append({
            "category": "version_validation",
            "points": 25,
            "description": (
                "Requested package version "
                "was not found on PyPI"
            )
        })

    # 3. Similarity analysis

    matches = similarity.get("matches", [])

    if matches:
        highest_score = max(
            match.get("similarity_score", 0)
            for match in matches
        )

        if highest_score >= 90:
            points = 25
        elif highest_score >= 80:
            points = 15
        elif highest_score >= 75:
            points = 5
        else:
            points = 0

        if points > 0:
            score += points

            evidence.append({
                "category": "name_similarity",
                "points": points,
                "similarity_score": highest_score,
                "description": (
                    "Package name closely resembles "
                    "a known package"
                )
            })

    # 4. Security findings

    security_findings = security.get("findings", [])

    severity_points = {
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 3,
        "INFO": 0
    }

    security_score = 0
    security_score_limit = 20

    for finding in security_findings:
        severity = finding.get(
            "severity", "INFO"
        ).upper()

        base_points = severity_points.get(
            severity, 0
        )

        # Do not allow security findings to contribute
        # more than 20 points in total.
        remaining_points = (
            security_score_limit - security_score
        )

        points = min(base_points, remaining_points)

        if points > 0:
            security_score += points

            evidence.append({
                "category": "security_analysis",
                "points": points,
                "severity": severity,
                "description": finding.get(
                    "description",
                    "Security indicator detected"
                )
            })

    # Add the capped security contribution.
    score += security_score

    # 5. Final risk calculation

    final_score = min(score, 100)

    if final_score >= 70:
        risk_level = "CRITICAL"
    elif final_score >= 40:
        risk_level = "HIGH"
    elif final_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # 6. Explainability

    if evidence:
        explanation = [
            item["description"]
            for item in evidence
        ]
    else:
        explanation = [
            "No significant risk indicators "
            "were identified in the available analysis."
        ]

    return {
        "package_name": package_name,
        "risk_score": final_score,
        "risk_level": risk_level,
        "evidence": evidence,
        "explanation": explanation
    }


def calculate_multiple_package_risks(packages):

    results = []

    for package in packages:
        result = calculate_package_risk(
            verification=package.get(
                "verification", {}
            ),
            similarity=package.get(
                "similarity", {}
            ),
            security=package.get(
                "security", {}
            )
        )

        results.append(result)

    return {
        "success": True,
        "total_packages": len(results),
        "risk_assessments": results
    }
