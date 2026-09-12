from pathlib import Path
import re
import sys
import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent

MATRIX_FILE = ROOT_DIR / "security" / "rbac-matrix.yaml"
TERRAFORM_DIR = ROOT_DIR / "terraform"


def load_matrix():
    with open(MATRIX_FILE, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_terraform():
    content = ""

    for tf_file in TERRAFORM_DIR.glob("*.tf"):
        content += "\n" + tf_file.read_text(encoding="utf-8")

    return content


def find_role_assignment(terraform_text, assignment_name):
    pattern = rf'resource\s+"azurerm_role_assignment"\s+"{re.escape(assignment_name)}"\s*\{{(.*?)\n\}}'

    match = re.search(
        pattern,
        terraform_text,
        re.DOTALL
    )

    if not match:
        return None

    return match.group(1)


def extract_attribute(block, attribute):
    pattern = rf'{re.escape(attribute)}\s*=\s*(.+)'

    match = re.search(pattern, block)

    if not match:
        return None

    value = match.group(1).strip()

    # Remove surrounding quotes
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]

    return value


def validate_assignment(terraform_text, requirement):
    assignment_name = requirement["assignment_name"]
    expected_source = requirement["source"]
    expected_target = requirement["target"]
    expected_role = requirement["role"]

    block = find_role_assignment(
        terraform_text,
        assignment_name
    )

    if block is None:
        return False, f"Role assignment '{assignment_name}' not found"

    actual_principal = extract_attribute(
        block,
        "principal_id"
    )

    actual_scope = extract_attribute(
        block,
        "scope"
    )

    actual_role = extract_attribute(
        block,
        "role_definition_name"
    )

    expected_principal = f"{expected_source}.principal_id"
    expected_scope = f"{expected_target}.id"

    errors = []

    if actual_principal != expected_principal:
        errors.append(
            f"principal_id expected '{expected_principal}' "
            f"but found '{actual_principal}'"
        )

    if actual_scope != expected_scope:
        errors.append(
            f"scope expected '{expected_scope}' "
            f"but found '{actual_scope}'"
        )

    if actual_role != expected_role:
        errors.append(
            f"role expected '{expected_role}' "
            f"but found '{actual_role}'"
        )

    if errors:
        return False, "; ".join(errors)

    return True, "Valid"


def main():
    matrix = load_matrix()
    terraform_text = load_terraform()

    requirements = matrix["assignments"]

    print()
    print("RBAC Matrix Validation")
    print("=" * 60)

    failed = 0

    for requirement in requirements:
        success, message = validate_assignment(
            terraform_text,
            requirement
        )

        if success:
            print(
                f"PASS  {requirement['id']}: "
                f"{requirement['source']} "
                f"-> {requirement['target']} "
                f"-> {requirement['role']}"
            )
        else:
            failed += 1

            print()
            print(f"FAIL  {requirement['id']}")
            print(f"      {message}")

    print()
    print("=" * 60)

    if failed:
        print(f"RBAC validation FAILED: {failed} requirement(s) failed")
        sys.exit(1)

    print(f"RBAC validation PASSED: {len(requirements)} requirement(s) validated")


if __name__ == "__main__":
    main()