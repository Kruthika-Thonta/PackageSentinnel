
import re
from rapidfuzz import fuzz, process


# Common PyPI distribution names.
KNOWN_PACKAGES = [
    "requests",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "seaborn",
    "scikit-learn",
    "tensorflow",
    "torch",
    "keras",
    "flask",
    "django",
    "fastapi",
    "streamlit",
    "uvicorn",
    "pydantic",
    "sqlalchemy",
    "beautifulsoup4",
    "selenium",
    "opencv-python",
    "pillow",
    "pytest",
    "httpx",
    "aiohttp",
    "redis",
    "celery",
    "cryptography",
    "paramiko",
    "boto3",
    "botocore",
    "transformers",
    "nltk",
    "spacy",
    "sympy",
    "networkx",
    "plotly",
    "dash",
    "gradio",
    "openpyxl",
    "python-dotenv",
    "packaging",
    "rapidfuzz",
    "pyyaml",
    "psycopg2",
    "pymongo",
    "mysql-connector-python",
    "requests-oauthlib",
    "python-dateutil",
    "tqdm",
    "joblib"
]


# Python import names that differ from PyPI distribution names.
IMPORT_NAME_MAPPING = {
    "sklearn": "scikit-learn",
    "PIL": "pillow",
    "cv2": "opencv-python",
    "yaml": "pyyaml",
    "dotenv": "python-dotenv",
    "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil"
}


def normalize_package_name(name):
    """
    Normalize package names according to
    Python package naming conventions.
    """

    return re.sub(r"[-_.]+", "-", name).lower()


def get_canonical_package_name(package_name):
    """
    Convert a Python import name into its
    corresponding PyPI distribution name
    when a known mapping exists.
    """

    mapped_name = IMPORT_NAME_MAPPING.get(
        package_name,
        package_name
    )

    return normalize_package_name(mapped_name)


def analyze_similarity(package_name, threshold=75):
    """
    Compare a package name against known packages
    and identify potentially suspicious similarities.
    """

    normalized_name = normalize_package_name(
        package_name
    )

    canonical_name = get_canonical_package_name(
        package_name
    )

    normalized_known = {
        normalize_package_name(name): name
        for name in KNOWN_PACKAGES
    }

    # Recognize known import aliases and exact
    # distribution names as legitimate packages.

    if canonical_name in normalized_known:

        return {
            "package_name": package_name,
            "canonical_package_name": canonical_name,
            "is_known_reference": True,
            "potential_typosquat": False,
            "risk_level": "LOW",
            "matches": [],
            "message": (
                "Known package or import alias "
                "recognized"
            )
        }

    # Compare unknown names against known packages.

    results = process.extract(
        normalized_name,
        list(normalized_known.keys()),
        scorer=fuzz.ratio,
        limit=5,
        score_cutoff=threshold
    )

    matches = []

    for candidate, score, index in results:

        original_name = normalized_known[candidate]

        matches.append({
            "similar_package": original_name,
            "similarity_score": round(score, 2)
        })

    highest_score = (
        matches[0]["similarity_score"]
        if matches else 0
    )

    # Determine similarity-based risk level.

    if highest_score >= 90:
        risk_level = "HIGH"

    elif highest_score >= 80:
        risk_level = "MEDIUM"

    elif highest_score >= threshold:
        risk_level = "LOW"

    else:
        risk_level = "NONE"

    return {
        "package_name": package_name,
        "canonical_package_name": canonical_name,
        "is_known_reference": False,
        "potential_typosquat": highest_score >= 80,
        "risk_level": risk_level,
        "matches": matches,
        "message": (
            "Similar package names detected"
            if matches
            else "No significant similarity detected"
        )
    }


def analyze_packages(packages):
    """
    Analyze multiple package names.
    """

    results = []

    for package in packages:

        result = analyze_similarity(package)

        results.append(result)

    return {
        "success": True,
        "total_packages": len(results),
        "similarity_results": results
    }
