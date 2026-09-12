resource "azurerm_resource_group" "demo" {
  name     = "rg-checkov-demo"
  location = "West Europe"
}

# --------------------------------------------------
# Identities
# --------------------------------------------------

resource "azurerm_user_assigned_identity" "apim_identity" {
  name                = "uami-apim"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
}

resource "azurerm_user_assigned_identity" "search_identity" {
  name                = "uami-search"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
}

resource "azurerm_user_assigned_identity" "app_identity" {
  name                = "uami-app"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
}

# --------------------------------------------------
# Resources
# --------------------------------------------------

resource "azurerm_cognitive_account" "content_safety" {
  name                = "checkov-content-safety-demo"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name

  kind     = "ContentSafety"
  sku_name = "S0"
}

resource "azurerm_key_vault" "team_kv" {
  name                = "kv-checkov-demo"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  tenant_id           = "11111111-1111-1111-1111-111111111111"

  sku_name = "standard"
}

resource "azurerm_storage_account" "documents" {
  name                     = "stcheckovdemo123"
  resource_group_name      = azurerm_resource_group.demo.name
  location                 = azurerm_resource_group.demo.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# --------------------------------------------------
# RBAC
# --------------------------------------------------

# APIM -> Content Safety
resource "azurerm_role_assignment" "apim_content_safety" {
  scope = azurerm_cognitive_account.content_safety.id

  role_definition_name = "Cognitive Services User"

  principal_id = azurerm_user_assigned_identity.apim_identity.principal_id
}

# APIM -> Key Vault
resource "azurerm_role_assignment" "apim_keyvault" {
  scope = azurerm_key_vault.team_kv.id

  role_definition_name = "Key Vault Secrets User"

  principal_id = azurerm_user_assigned_identity.apim_identity.principal_id
}

# Search -> Storage
resource "azurerm_role_assignment" "search_storage" {
  scope = azurerm_storage_account.documents.id

  role_definition_name = "Storage Blob Data Reader"

  principal_id = azurerm_user_assigned_identity.search_identity.principal_id
}

resource "azurerm_role_assignment" "app_keyvault" {
  scope                = azurerm_key_vault.team_kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app_identity.principal_id
}

resource "azurerm_role_assignment" "app_storage" {
  scope                = azurerm_storage_account.documents.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.app_identity.principal_id
}