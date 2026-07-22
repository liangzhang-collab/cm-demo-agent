variable "gcp_project_id" {
  description = "Target Google Cloud Project ID"
  type        = string
  default     = "codemender-enterprise-prod"
}

variable "gcp_region" {
  description = "Google Cloud Region for deployment"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment stage"
  type        = string
  default     = "production"
}

variable "container_image" {
  description = "Container image URL for CodeMender ADK Agent"
  type        = string
  default     = "gcr.io/codemender-enterprise-prod/agent:latest"
}

variable "model_tier_pro" {
  description = "Pro reasoning model name"
  type        = string
  default     = "gemini-2.5-pro"
}

variable "model_tier_flash" {
  description = "Flash fast scanning model name"
  type        = string
  default     = "gemini-2.5-flash"
}
