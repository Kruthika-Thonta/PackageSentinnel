
import requests
from datetime import datetime, timezone
from packaging.requirements import Requirement, InvalidRequirement
from urllib.parse import urlparse


PYPI_API_URL = "https://pypi.org/pypi/{}/json"


def analyze_package_security(package_name):
    """
    Perform static metadata and dependency analysis
    using the official PyPI JSON API.
    """

    findings = []
    dependencies = []

    try:
        response = requests.get(
            PYPI_API_URL.format(package_name),
            timeout=10
        )

        if response.status_code == 404:
            return {
                "package_name": package_name,
                "analysis_success": False,
                "message": "Package not found on PyPI",
                "findings": [],
                "dependencies": []
            }

        response.raise_for_status()

        data = response.json()
        info = data.get("info", {})
        releases = data.get("releases", {})

        # 1. Metadata inspection

        if not info.get("author") and not info.get("maintainer"):
            findings.append({
                "category": "metadata",
                "severity": "INFO",
                "description": (
                    "Author and maintainer information is missing"
                )
            })

        project_urls = info.get("project_urls") or {}

        if not project_urls and not info.get("home_page"):
            findings.append({
                "category": "metadata",
                "severity": "LOW",
                "description": (
                    "No project homepage or project URLs are provided"
                )
            })

        if not info.get("description"):
            findings.append({
                "category": "metadata",
                "severity": "LOW",
                "description": "Package description is missing"
            })

        if not info.get("classifiers"):
            findings.append({
                "category": "metadata",
                "severity": "INFO",
                "description": "No package classifiers are provided"
            })

        # 2. Project URL inspection

        urls = list(project_urls.values())

        if info.get("home_page"):
            urls.append(info["home_page"])

        for url in urls:

            if not isinstance(url, str):
                continue

            parsed_url = urlparse(url)

            if (
                parsed_url.scheme not in ("http", "https")
                or not parsed_url.netloc
            ):
                findings.append({
                    "category": "project_url",
                    "severity": "MEDIUM",
                    "description": (
                        "A project URL uses an unusual or invalid URL format"
                    )
                })

        # 3. Release history analysis

        release_count = len([
            version
            for version, files in releases.items()
            if files
        ])

        if release_count == 0:
            findings.append({
                "category": "release_history",
                "severity": "LOW",
                "description": "No release files were found"
            })

        upload_dates = []

        for files in releases.values():

            for file_info in files:

                upload_time = (
                    file_info.get("upload_time_iso_8601")
                    or file_info.get("upload_time")
                )

                if not upload_time:
                    continue

                try:
                    normalized_time = upload_time.replace(
                        "Z", "+00:00"
                    )

                    parsed_time = datetime.fromisoformat(
                        normalized_time
                    )

                    if parsed_time.tzinfo is None:
                        parsed_time = parsed_time.replace(
                            tzinfo=timezone.utc
                        )

                    upload_dates.append(parsed_time)

                except (ValueError, TypeError):
                    continue

        first_release_date = None
        latest_release_date = None

        if upload_dates:

            first_release_date = min(upload_dates)
            latest_release_date = max(upload_dates)

            package_age_days = (
                datetime.now(timezone.utc)
                - first_release_date
            ).days

            if package_age_days <= 30:
                findings.append({
                    "category": "release_history",
                    "severity": "INFO",
                    "description": (
                        "The package's first recorded upload "
                        "was within the last 30 days"
                    )
                })

        # 4. Dependency analysis

        requires_dist = info.get("requires_dist") or []

        for dependency in requires_dist:

            try:
                requirement = Requirement(dependency)

                environment_marker = (
                    str(requirement.marker)
                    if requirement.marker
                    else None
                )

                requested_extras = sorted(
                    requirement.extras
                )

                # A dependency is considered optional here
                # only when its marker explicitly references
                # an extra. Other markers may describe OS,
                # Python version, or platform conditions.

                is_optional = (
                    environment_marker is not None
                    and "extra" in environment_marker.lower()
                )

                dependencies.append({
                    "name": requirement.name,
                    "version_specifier": str(
                        requirement.specifier
                    ),
                    "requested_extras": requested_extras,
                    "environment_marker": environment_marker,
                    "is_optional": is_optional
                })

            except InvalidRequirement:
                findings.append({
                    "category": "dependency",
                    "severity": "LOW",
                    "description": (
                        "An invalid dependency declaration "
                        "was encountered"
                    )
                })

        # Keep every declaration because the same package
        # can have different version constraints or markers.

        dependency_count = len(dependencies)

        unique_dependency_count = len({
            dependency["name"].lower().replace("_", "-")
            for dependency in dependencies
        })

        if unique_dependency_count > 20:
            findings.append({
                "category": "dependency",
                "severity": "INFO",
                "description": (
                    "Package declares more than 20 unique dependencies"
                )
            })

        # 5. Return analysis results

        return {
            "package_name": package_name,
            "analysis_success": True,
            "latest_version": info.get("version"),
            "author": info.get("author"),
            "maintainer": info.get("maintainer"),
            "summary": info.get("summary"),
            "project_urls": project_urls,
            "release_count": release_count,
            "first_release_date": (
                first_release_date.isoformat()
                if first_release_date else None
            ),
            "latest_release_date": (
                latest_release_date.isoformat()
                if latest_release_date else None
            ),
            "dependency_count": dependency_count,
            "unique_dependency_count": unique_dependency_count,
            "dependencies": dependencies,
            "findings": findings,
            "message": "Static security analysis completed"
        }

    except requests.exceptions.Timeout:
        return {
            "package_name": package_name,
            "analysis_success": False,
            "message": "PyPI request timed out",
            "findings": [],
            "dependencies": []
        }

    except requests.exceptions.RequestException as error:
        return {
            "package_name": package_name,
            "analysis_success": False,
            "message": "Registry request failed: " + str(error),
            "findings": [],
            "dependencies": []
        }


def analyze_multiple_packages(packages):
    """
    Perform security analysis on multiple packages.
    """

    results = []

    for package in packages:

        result = analyze_package_security(package)

        results.append(result)

    successful = sum(
        1 for result in results
        if result["analysis_success"]
    )

    return {
        "success": True,
        "total_packages": len(results),
        "successfully_analyzed": successful,
        "security_results": results
    }
