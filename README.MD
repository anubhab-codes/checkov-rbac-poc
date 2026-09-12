# Terraform RBAC Enforcement with Checkov

This POC demonstrates how a security-owned RBAC matrix can be enforced against Terraform using a custom Checkov policy during CI/CD.

## Project Structure

```text
checkov-rbac-poc/
│
├── terraform/
│   ├── main.tf
│   └── providers.tf
│
├── security/
│   └── rbac-matrix.yaml
│
├── checkov/
│   └── custom_checks/
│       ├── __init__.py
│       └── RBACMatrixCheck.py
│
├── .github/
│   └── workflows/
│       └── rbac-validation.yml
│
├── .gitignore
└── README.md
```

## Key Files

### `security/rbac-matrix.yaml`

The security-owned source of truth for approved RBAC assignments.

Each entry defines:

* **Source** — identity receiving access
* **Target** — resource being accessed
* **Role** — approved Azure RBAC role

Example:

```yaml
- id: APIM_KEYVAULT
  description: APIM identity must access the team Key Vault
  assignment_name: apim_keyvault
  source: azurerm_user_assigned_identity.apim_identity
  target: azurerm_key_vault.team_kv
  role: Key Vault Secrets User
```

### `checkov/custom_checks/RBACMatrixCheck.py`

Custom Checkov policy that reads the RBAC matrix and validates the corresponding `azurerm_role_assignment` resources in Terraform.

For each controlled assignment, it verifies:

```text
Source identity + Target resource + RBAC role
```

If Terraform does not match the approved matrix, the Checkov check fails.

### `checkov/custom_checks/__init__.py`

Loads the custom Python checks so they can be discovered by Checkov.

### `.github/workflows/rbac-validation.yml`

Runs the custom Checkov policy automatically on GitHub push and pull requests.

A Checkov failure causes the workflow to fail.

## How It Works

```text
Security RBAC Matrix
        ↓
Custom Checkov Policy
        ↓
Terraform RBAC Assignments
        ↓
Compare Source + Target + Role
        ↓
     PASS / FAIL
```

The validation is performed against Terraform before deployment. No Azure deployment or connection to Azure is required.