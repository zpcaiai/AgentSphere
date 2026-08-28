resource "github_repository_ruleset" "default_branch_release" {
  name        = "agenttrust-production-release"
  repository  = var.repository
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }

  rules {
    deletion                = true
    non_fast_forward        = true
    required_linear_history = true
    required_signatures     = true

    pull_request {
      dismiss_stale_reviews_on_push     = true
      require_code_owner_review         = true
      require_last_push_approval        = true
      required_approving_review_count   = var.required_pull_request_approvals
      required_review_thread_resolution = true
    }

    required_status_checks {
      strict_required_status_checks_policy = true
      do_not_enforce_on_create             = false

      dynamic "required_check" {
        for_each = var.required_status_checks
        content {
          context = required_check.value
        }
      }
    }
  }
}

resource "github_repository_environment" "production_candidate" {
  repository          = var.repository
  environment         = "production-candidate"
  prevent_self_review = true
  can_admins_bypass   = false

  reviewers {
    users = var.candidate_reviewer_user_ids
    teams = var.candidate_reviewer_team_ids
  }

  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }

  lifecycle {
    precondition {
      condition = (
        length(var.candidate_reviewer_user_ids) +
        length(var.candidate_reviewer_team_ids) > 0
      )
      error_message = "production-candidate must have at least one explicitly configured human reviewer."
    }
    precondition {
      condition = (
        toset(keys(var.candidate_environment_variables)) ==
        local.candidate_environment_variable_names
      )
      error_message = "production-candidate variables must exactly match the release-candidate workflow contract; missing and extra names fail closed."
    }
  }
}

resource "github_repository_environment" "production" {
  repository          = var.repository
  environment         = "production"
  prevent_self_review = true
  can_admins_bypass   = false

  reviewers {
    users = var.production_reviewer_user_ids
    teams = var.production_reviewer_team_ids
  }

  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }

  lifecycle {
    precondition {
      condition = (
        length(var.production_reviewer_user_ids) +
        length(var.production_reviewer_team_ids) > 0
      )
      error_message = "production must have at least one explicitly configured human reviewer."
    }
    precondition {
      condition = (
        toset(keys(var.production_environment_variables)) ==
        local.production_environment_variable_names
      )
      error_message = "production variables must exactly match the production-release workflow contract; missing and extra names fail closed."
    }
  }
}

resource "github_repository_environment" "production_evidence" {
  repository          = var.repository
  environment         = "production-evidence"
  prevent_self_review = true
  can_admins_bypass   = false

  reviewers {
    users = var.evidence_reviewer_user_ids
    teams = var.evidence_reviewer_team_ids
  }

  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }

  lifecycle {
    precondition {
      condition = (
        length(var.evidence_reviewer_user_ids) +
        length(var.evidence_reviewer_team_ids) > 0
      )
      error_message = "production-evidence must have at least one explicitly configured human reviewer."
    }
    precondition {
      condition = (
        toset(keys(var.evidence_environment_variables)) ==
        local.evidence_environment_variable_names
      )
      error_message = "production-evidence variables must exactly match the evidence-intake workflow contract; missing and extra names fail closed."
    }
  }
}

resource "github_repository_environment" "production_assurance" {
  repository          = var.repository
  environment         = "production-assurance"
  prevent_self_review = true
  can_admins_bypass   = false

  reviewers {
    users = var.assurance_reviewer_user_ids
    teams = var.assurance_reviewer_team_ids
  }

  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }

  lifecycle {
    precondition {
      condition = (
        length(var.assurance_reviewer_user_ids) +
        length(var.assurance_reviewer_team_ids) > 0
      )
      error_message = "production-assurance must have at least one explicitly configured independent reviewer."
    }
    precondition {
      condition = (
        toset(keys(var.assurance_environment_variables)) ==
        local.assurance_environment_variable_names
      )
      error_message = "production-assurance variables must exactly match the assurance workflow contract; missing and extra names fail closed."
    }
  }
}
