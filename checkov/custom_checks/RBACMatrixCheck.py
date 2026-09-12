from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class RBACMatrixCheck(BaseResourceCheck):

    def __init__(self) -> None:
        name = "Ensure Terraform RBAC assignments comply with security RBAC matrix"
        check_id = "CKV_CUSTOM_AZURE_RBAC_001"

        supported_resources = (
            "azurerm_role_assignment",
        )

        categories = (
            CheckCategories.IAM,
        )

        super().__init__(
            name=name,
            id=check_id,
            categories=categories,
            supported_resources=supported_resources,
        )

        self.matrix = self._load_matrix()

    def _load_matrix(self) -> dict[str, Any]:
        """
        Repository layout expected:

        repo/
        ├── security/
        │   └── rbac-matrix.yaml
        └── checkov/
            └── custom_checks/
                └── RBACMatrixCheck.py
        """

        current_file = Path(__file__).resolve()

        repo_root = current_file.parent.parent.parent
        matrix_file = repo_root / "security" / "rbac-matrix.yaml"

        if not matrix_file.exists():
            raise FileNotFoundError(
                f"RBAC matrix not found: {matrix_file}"
            )

        with matrix_file.open("r", encoding="utf-8") as file:
            return yaml.safe_load(file)

    @staticmethod
    def _first_value(conf: dict[str, Any], key: str) -> Any:
        value = conf.get(key)

        if isinstance(value, list):
            if not value:
                return None
            return value[0]

        return value

    def _find_requirement(
        self,
        assignment_name: str,
    ) -> dict[str, Any] | None:

        for requirement in self.matrix.get("assignments", []):
            if requirement.get("assignment_name") == assignment_name:
                return requirement

        return None

    def scan_resource_conf(
        self,
        conf: dict[str, list[Any]],
    ) -> CheckResult:

        #
        # Checkov normally exposes Terraform resource address
        # in __address__.
        #
        # Example:
        # azurerm_role_assignment.apim_keyvault
        #

        address = self._first_value(conf, "__address__")

        if not address:
            return CheckResult.UNKNOWN

        assignment_name = str(address).split(".")[-1]

        requirement = self._find_requirement(
            assignment_name
        )

        #
        # If the role assignment isn't part of the controlled
        # RBAC matrix, this policy does not enforce it.
        #
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

        expected_scope = (
            f"{requirement['target']}.id"
        )

        expected_principal = (
            f"{requirement['source']}.principal_id"
        )

        errors = []

        if actual_role != expected_role:
            errors.append(
                f"Expected role '{expected_role}', "
                f"found '{actual_role}'"
            )

        if actual_scope != expected_scope:
            errors.append(
                f"Expected scope '{expected_scope}', "
                f"found '{actual_scope}'"
            )

        if actual_principal != expected_principal:
            errors.append(
                f"Expected principal '{expected_principal}', "
                f"found '{actual_principal}'"
            )

        if errors:
            self.details = errors
            return CheckResult.FAILED

        return CheckResult.PASSED

    def get_evaluated_keys(self):
        return [
            "role_definition_name",
            "scope",
            "principal_id",
        ]


check = RBACMatrixCheck()