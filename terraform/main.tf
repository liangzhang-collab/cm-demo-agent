/**
 * Terraform Infrastructure as Code (IaC) for CodeMender Enterprise Agent.
 * Provisions Google Cloud Run, Secret Manager, Cloud Storage, and IAM configurations.
 */

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# 1. Google Cloud Secret Manager for Secure API Keys
resource "google_secret_manager_secret" "gemini_api_key" {
  secret_id = "codemender-gemini-api-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "auth_token" {
  secret_id = "codemender-auth-token"
  replication {
    auto {}
  }
}

# 2. Cloud Storage Bucket for Reports & Golden Benchmark Artifacts
resource "google_storage_bucket" "codemender_artifacts" {
  name          = "${var.gcp_project_id}-codemender-artifacts"
  location      = var.gcp_region
  force_destroy = false
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }
}

# 3. Google Cloud Run Service for ADK Agent Orchestration
resource "google_cloud_run_v2_service" "codemender_agent_service" {
  name     = "codemender-agent-service"
  location = var.gcp_region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    containers {
      image = var.container_image

      resources {
        limits = {
          cpu    = "2"
          memory = "4Gi"
        }
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "MODEL_TIER_PRO"
        value = var.model_tier_pro
      }
      env {
        name  = "MODEL_TIER_FLASH"
        value = var.model_tier_flash
      }
    }
  }
}
