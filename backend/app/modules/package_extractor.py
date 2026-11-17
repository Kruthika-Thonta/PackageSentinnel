import ast
import sys


def get_standard_library():

    # Python 3.10 and above
    if hasattr(sys, "stdlib_module_names"):
        return sys.stdlib_module_names

    # Python versions below 3.10
    from stdlib_list import stdlib_list

    version = (
        f"{sys.version_info.major}."
        f"{sys.version_info.minor}"
    )

    return set(stdlib_list(version))


def extract_packages(source_code: str):

    try:
        tree = ast.parse(source_code)

    except SyntaxError as error:
        return {
            "success": False,
            "error": str(error),
            "packages": []
        }

    packages = {}

    standard_library = get_standard_library()

    for node in ast.walk(tree):

        if isinstance(node, ast.Import):

            for alias in node.names:

                module_name = alias.name.split(".")[0]

                packages[module_name] = {
                    "package_name": module_name,
                    "line_number": node.lineno,
                    "type": (
                        "standard_library"
                        if module_name in standard_library
                        else "external"
                    )
                }

        elif isinstance(node, ast.ImportFrom):

            if node.module is not None and node.level == 0:

                module_name = node.module.split(".")[0]

                packages[module_name] = {
                    "package_name": module_name,
                    "line_number": node.lineno,
                    "type": (
                        "standard_library"
                        if module_name in standard_library
                        else "external"
                    )
                }

    return {
        "success": True,
        "total_packages": len(packages),
        "packages": list(packages.values())
    }