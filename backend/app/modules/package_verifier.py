
import requests
from packaging.version import Version, InvalidVersion
from urllib.parse import quote


# Maps Python import names to their PyPI distribution names.
PACKAGE_NAME_MAPPING = {
    "sklearn": "scikit-learn",
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "bs4": "beautifulsoup4",
    "yaml": "PyYAML",
    "dotenv": "python-dotenv",
    "Crypto": "pycryptodome",
}


def get_distribution_name(import_name):
    """
    Convert a Python import name into its
    corresponding PyPI distribution name.
    """

    return PACKAGE_NAME_MAPPING.get(
        import_name,
        import_name
    )


def verify_package(package_name, requested_version=None):
    """
    Verify package existence and version availability
    using the official PyPI JSON API.
    """

    distribution_name = get_distribution_name(
        package_name
    )

    encoded_name = quote(distribution_name, safe="")

    api_url = (
        f"https://pypi.org/pypi/{encoded_name}/json"
    )

    try:
        response = requests.get(
            api_url,
            timeout=10
        )

        if response.status_code == 404:
            return {
                "package_name": package_name,
                "distribution_name": distribution_name,
                "exists": False,
                "version_valid": None,
                "latest_version": None,
                "requested_version": requested_version,
                "message": "Package not found on PyPI"
            }

        response.raise_for_status()

        data = response.json()

        latest_version = data["info"]["version"]
        available_versions = list(
            data.get("releases", {}).keys()
        )

        version_valid = None

        if requested_version is not None:

            try:
                requested = Version(requested_version)

                version_valid = any(
                    Version(version) == requested
                    for version in available_versions
                    if is_valid_version(version)
                )

            except InvalidVersion:
                version_valid = False

        return {
            "package_name": package_name,
            "distribution_name": distribution_name,
            "exists": True,
            "version_valid": version_valid,
            "latest_version": latest_version,
            "requested_version": requested_version,
            "description": data["info"].get("summary"),
            "homepage": data["info"].get("home_page"),
            "project_urls": data["info"].get("project_urls"),
            "available_versions_count": len(
                available_versions
            ),
            "message": "Package found on PyPI"
        }

    except requests.exceptions.Timeout:
        return {
            "package_name": package_name,
            "exists": None,
            "version_valid": None,
            "message": "PyPI request timed out"
        }

    except requests.exceptions.RequestException as error:
        return {
            "package_name": package_name,
            "exists": None,
            "version_valid": None,
            "message": f"Registry request failed: {str(error)}"
        }

    except (KeyError, ValueError) as error:
        return {
            "package_name": package_name,
            "exists": None,
            "version_valid": None,
            "message": f"Invalid registry response: {str(error)}"
        }


def is_valid_version(version):
    """
    Check whether a version string is valid.
    """

    try:
        Version(version)
        return True

    except InvalidVersion:
        return False


def verify_packages(packages):
    """
    Verify multiple packages against PyPI.
    """

    results = []

    for package in packages:

        result = verify_package(
            package["package_name"],
            package.get("requested_version")
        )

        results.append(result)

    return {
        "success": True,
        "total_packages": len(results),
        "verified_packages": results
    }
