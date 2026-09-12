resource "azurerm_resource_group" "demo" {
  name     = "rg-checkov-demo"
  location = "West Europe"
}

resource "azurerm_user_assigned_identity" "apim_identity" {
  name                = "uami-apim"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
}

resource "azurerm_cognitive_account" "content_safety" {
  name                = "checkov-content-safety-demo"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name

  kind     = "ContentSafety"
  sku_name = "S0"
}

resource "azurerm_role_assignment" "apim_content_safety" {
  scope = azurerm_cognitive_account.content_safety.id

  role_definition_name = "Cognitive Services User"

  principal_id = azurerm_user_assigned_identity.apim_identity.principal_id
}