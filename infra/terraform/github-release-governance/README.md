# GitHub release governance

This module creates the repository-side controls required by the production
release workflows:

- signed, linear, non-deletable and non-force-push default-branch history;
- code-owner review, independent last-pusher approval, resolved conversations,
  and the complete CI status set;
- protected `production-candidate`, `production-evidence`,
  `production-assurance`, and `production` environments with no administrator
  bypass and no self-approval;
- separate reviewer sets for candidate construction, evidence admission,
  independent signing assurance, and final deployment.
- exact protected environment variable contracts for all four workflows,
  managed as `github_actions_environment_variable` resources.

It deliberately does not infer reviewer identities. Supply numeric GitHub user
or team IDs from the organization authority and review the Terraform plan
before applying it with a repository-administration token. At least one
production reviewer is mandatory; use two reviewers from independent
organizations when the assurance policy requires that separation.

All four `*_environment_variables` maps are required and their key sets must
exactly match the corresponding workflow. Missing variables and undeclared
extras fail Terraform planning. Values are limited to non-secret paths,
digests, digest-pinned images, URLs and public verification material. Put
credentials and private keys in the environment's secret manager or OIDC/Vault
broker; do not place them in these Terraform maps or state.

The ruleset requires code-owner review but this module cannot safely invent an
organization team. Commit the organization-approved `.github/CODEOWNERS` file
through the ordinary reviewed process and configure its exact SHA-256 as the
protected `AGENT_TRUST_CODEOWNERS_SHA256` candidate-environment variable. The
release-candidate workflow rejects a missing or different committed policy.

Example:

```hcl
provider "github" {
  owner = "example-organization"
}

module "agenttrust_release_governance" {
  source = "./infra/terraform/github-release-governance"

  repository                    = "AgentSphere"
  candidate_reviewer_team_ids   = [123456]
  evidence_reviewer_team_ids    = [234567]
  assurance_reviewer_team_ids   = [345678]
  production_reviewer_team_ids  = [123456, 789012]

  candidate_environment_variables  = local.production_candidate_variables
  evidence_environment_variables   = local.production_evidence_variables
  assurance_environment_variables  = local.production_assurance_variables
  production_environment_variables = local.production_release_variables
}
```

Running `terraform plan` is configuration validation, not evidence that the
rules are active. Export the applied ruleset/environment state through the
production evidence qualification flow for the exact release scope.
