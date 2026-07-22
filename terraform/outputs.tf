output "cloud_run_service_uri" {
  description = "URI of deployed CodeMender Cloud Run service"
  value       = google_cloud_run_v2_service.codemender_agent_service.uri
}

output "artifacts_bucket_name" {
  description = "GCS bucket name for security reports and benchmarks"
  value       = google_storage_bucket.codemender_artifacts.name
}

output "gemini_secret_id" {
  description = "Secret Manager secret ID for Gemini API key"
  value       = google_secret_manager_secret.gemini_api_key.secret_id
}
