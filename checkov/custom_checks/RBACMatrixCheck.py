"""
Custom Checkov policy for enforcing the security-owned RBAC matrix.

Flow:
1. Checkov scans Terraform.
2. This policy runs for every azurerm_role_assignment.
3. The Terraform assignment name is matched against security/rbac-matrix.yaml.
4. Source identity, target resource, and RBAC role are compared.
5. Any deviation returns FAILED and causes the CI/CD security check to fail.

No Azure deployment or Azure API call is required.
"""

from pathlib import Path
from typing import Any

import yaml

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class RBACMatrixCheck(BaseResourceCheck):
    """Validate Terraform RBAC assignments against the approved RBAC matrix."""

    def __init__(self) -> None:
        super().__init__(
            name="Ensure Terraform RBAC assignments comply with security RBAC matrix",
            id="CKV_CUSTOM_AZURE_RBAC_001",
            categories=(CheckCategories.IAM,),
            supported_resources=("azurerm_role_assignment",),
        )

        self.matrix = self._load_matrix()

    @staticmethod
    def _load_matrix() -> dict[str, Any]:
        """Load the security-owned RBAC baseline from the repository."""

        repo_root = Path(__file__).resolve().parents[2]
        matrix_file = repo_root / "security" / "rbac-matrix.yaml"

        if not matrix_file.exists():
            raise FileNotFoundError(
                f"RBAC matrix was not found: {matrix_file}"
            )

        with matrix_file.open("r", encoding="utf-8") as file:
            return yaml.safe_load(file)

    @staticmethod
    def _first_value(conf: dict[str, Any], key: str) -> Any:
        """
        Checkov represents many Terraform attributes as lists.
        Return the first value in a consistent form.
        """

        value = conf.get(key)

        if isinstance(value, list):
            return value[0] if value else None

        return value

    def _find_requirement(
        self,
        assignment_name: str,
    ) -> dict[str, Any] | None:
        """Find the security requirement controlling this Terraform assignment."""

        for requirement in self.matrix.get("assignments", []):
            if requirement.get("assignment_name") == assignment_name:
                return requirement

        return None

    def scan_resource_conf(
        self,
        conf: dict[str, Any],
    ) -> CheckResult:
        """
        Checkov invokes this method for every azurerm_role_assignment.

        Example Checkov address:
            azurerm_role_assignment.apim_keyvault
        """

        address = self._first_value(conf, "__address__")

        if not address:
            return CheckResult.UNKNOWN

        assignment_name = str(address).split(".")[-1]

        requirement = self._find_requirement(assignment_name)

        # Assignments not included in the matrix are currently outside the
        # scope of this specific control.
        if requirement is None:
            return CheckResult.PASSED

        actual_role = self._first_value(
            conf,
            "role_definition_name",
        )

        actual_scope = self._first_value(
            conf,
            "scope",
        )

        actual_principal = self._first_value(
            conf,
            "principal_id",
        )

        expected_role = requirement["role"]
        expected_scope = f"{requirement['target']}.id"
        expected_principal = f"{requirement['source']}.principal_id"

        if (
            actual_role != expected_role
            or actual_scope != expected_scope
            or actual_principal != expected_principal
        ):
            return CheckResult.FAILED

        return CheckResult.PASSED

    def get_evaluated_keys(self):
        """Terraform attributes evaluated by this custom Checkov policy."""

        return [
            "role_definition_name",
            "scope",
            "principal_id",
        ]


# Register the custom policy with Checkov.
check = RBACMatrixCheck()