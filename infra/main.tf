# Demo de Ominous Security en Cloudflare Pages, gestionada con Terraform (igual que el CV).
# Estado remoto en HCP Terraform (plan gratuito). Organización y workspace llegan por
# variables de entorno: TF_CLOUD_ORGANIZATION y TF_WORKSPACE (ver .github/workflows/ci.yml).
terraform {
  required_version = ">= 1.6"
  cloud {}
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

# El token se lee de la variable de entorno CLOUDFLARE_API_TOKEN.
provider "cloudflare" {}

variable "cloudflare_account_id" {
  type        = string
  description = "ID de la cuenta de Cloudflare"
}

variable "project_name" {
  type    = string
  default = "ominous-security"
}

# Proyecto de Pages en modo "direct upload": GitHub Actions genera dist/ y lo sube con Wrangler.
resource "cloudflare_pages_project" "demo" {
  account_id        = var.cloudflare_account_id
  name              = var.project_name
  production_branch = "main"
}

output "url" {
  value = "https://${cloudflare_pages_project.demo.subdomain}"
}

output "project_name" {
  value = cloudflare_pages_project.demo.name
}
