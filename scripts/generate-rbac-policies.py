import os
import yaml


MATRIX_FILE = "security/rbac-matrix.yaml"
OUTPUT_DIR = "checkov/generated"


def load_matrix():
    with open(MATRIX_FILE, "r") as file:
        return yaml.safe_load(file)


def generate_policy(requirement, policy_number):
    requirement_id = requirement["id"]
    description = requirement["description"]
    source_type = requirement["source_type"]
    target_type = requirement["target_type"]
    role = requirement["role"]

    policy = {
        "metadata": {
            "id": f"CKV2_CUSTOM_AZURE_{policy_number}",
            "name": description,
            "category": "IAM",
            "severity": "HIGH"
        },

        "definition": {
            "and": [

                # Apply the check to role assignments
                {
                    "cond_type": "filter",
                    "attribute": "resource_type",
                    "operator": "within",
                    "value": [
                        "azurerm_role_assignment"
                    ]
                },

                # Correct RBAC role
                {
                    "cond_type": "attribute",
                    "resource_types": [
                        "azurerm_role_assignment"
                    ],
                    "attribute": "role_definition_name",
                    "operator": "equals",
                    "value": role
                },

                # Role assignment connects to expected source identity
                {
                    "cond_type": "connection",
                    "resource_types": [
                        "azurerm_role_assignment"
                    ],
                    "connected_resource_types": [
                        source_type
                    ],
                    "operator": "exists"
                },

                # Role assignment connects to expected target
                {
                    "cond_type": "connection",
                    "resource_types": [
                        "azurerm_role_assignment"
                    ],
                    "connected_resource_types": [
                        target_type
                    ],
                    "operator": "exists"
                }
            ]
        }
    }

    return policy


def main():

    matrix = load_matrix()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Remove old generated YAML
    for filename in os.listdir(OUTPUT_DIR):
        if filename.endswith(".yaml"):
            os.remove(os.path.join(OUTPUT_DIR, filename))

    assignments = matrix["assignments"]

    print(f"Found {len(assignments)} RBAC requirements")

    for index, requirement in enumerate(assignments, start=1):

        policy = generate_policy(requirement, 1000 + index)

        filename = (
            requirement["id"]
            .lower()
            .replace("_", "-")
            + ".yaml"
        )

        output_path = os.path.join(OUTPUT_DIR, filename)

        with open(output_path, "w") as file:
            yaml.dump(
                policy,
                file,
                sort_keys=False,
                default_flow_style=False
            )

        print(
            f"Generated {output_path} "
            f"for {requirement['id']}"
        )


if __name__ == "__main__":
    main()