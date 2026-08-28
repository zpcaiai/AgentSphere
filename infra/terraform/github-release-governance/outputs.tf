output "ruleset_id" {
  description = "Repository ruleset protecting the default release branch."
  value       = github_repository_ruleset.default_branch_release.ruleset_id
}

output "candidate_environment" {
  description = "Protected environment for immutable candidate construction."
  value       = github_repository_environment.production_candidate.environment
}

output "production_environment" {
  description = "Protected environment for final production deployment."
  value       = github_repository_environment.production.environment
}

output "evidence_environment" {
  description = "Protected environment for production evidence intake."
  value       = github_repository_environment.production_evidence.environment
}

output "assurance_environment" {
  description = "Protected environment for independent closure signing."
  value       = github_repository_environment.production_assurance.environment
}

output "protected_environment_variable_contracts" {
  description = "Exact non-secret variable names required by each protected release environment."
  value = {
    production_candidate = sort(tolist(local.candidate_environment_variable_names))
    production_evidence  = sort(tolist(local.evidence_environment_variable_names))
    production_assurance = sort(tolist(local.assurance_environment_variable_names))
    production           = sort(tolist(local.production_environment_variable_names))
  }
}
