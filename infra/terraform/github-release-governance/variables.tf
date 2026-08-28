variable "repository" {
  description = "GitHub repository name without the owner."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{1,100}$", var.repository))
    error_message = "repository must be a valid GitHub repository name."
  }
}

variable "candidate_reviewer_user_ids" {
  description = "Numeric GitHub user IDs allowed to approve production-candidate deployments."
  type        = set(number)
  default     = []
}

variable "candidate_reviewer_team_ids" {
  description = "Numeric GitHub team IDs allowed to approve production-candidate deployments."
  type        = set(number)
  default     = []
}

variable "production_reviewer_user_ids" {
  description = "Numeric GitHub user IDs allowed to approve production deployments."
  type        = set(number)
  default     = []
}

variable "production_reviewer_team_ids" {
  description = "Numeric GitHub team IDs allowed to approve production deployments."
  type        = set(number)
  default     = []
}

variable "evidence_reviewer_user_ids" {
  description = "Numeric GitHub user IDs allowed to release externally collected production evidence."
  type        = set(number)
  default     = []
}

variable "evidence_reviewer_team_ids" {
  description = "Numeric GitHub team IDs allowed to release externally collected production evidence."
  type        = set(number)
  default     = []
}

variable "assurance_reviewer_user_ids" {
  description = "Numeric GitHub user IDs allowed to invoke independent production assurance signing."
  type        = set(number)
  default     = []
}

variable "assurance_reviewer_team_ids" {
  description = "Numeric GitHub team IDs allowed to invoke independent production assurance signing."
  type        = set(number)
  default     = []
}

variable "required_status_checks" {
  description = "Checks that must pass on the immutable release commit before merge."
  type        = set(string)
  default = [
    "contracts-and-rust",
    "migrations",
    "policy",
  ]

  validation {
    condition = (
      length(var.required_status_checks) >= 3 &&
      alltrue([for check in var.required_status_checks : can(regex("^[A-Za-z0-9_. /:-]{1,100}$", check))])
    )
    error_message = "required_status_checks must contain at least three valid check contexts."
  }
}

variable "required_pull_request_approvals" {
  description = "Independent approvals required to merge to the default branch."
  type        = number
  default     = 2

  validation {
    condition     = var.required_pull_request_approvals >= 2 && var.required_pull_request_approvals <= 6
    error_message = "production changes require between two and six approvals."
  }
}

variable "candidate_environment_variables" {
  description = "Complete non-secret protected variable map consumed by release-candidate.yml. Values must be organization-provisioned paths, digests, URLs, public keys, or digest-pinned images."
  type        = map(string)

  validation {
    condition = alltrue([
      for key, value in var.candidate_environment_variables :
      can(regex("^AGENT_TRUST_[A-Z0-9_]+$", key)) && length(trimspace(value)) > 0
    ])
    error_message = "candidate_environment_variables must contain only non-empty AGENT_TRUST_* values."
  }
}

variable "evidence_environment_variables" {
  description = "Complete non-secret protected variable map consumed by production-evidence-intake.yml."
  type        = map(string)

  validation {
    condition = alltrue([
      for key, value in var.evidence_environment_variables :
      can(regex("^AGENT_TRUST_[A-Z0-9_]+$", key)) && length(trimspace(value)) > 0
    ])
    error_message = "evidence_environment_variables must contain only non-empty AGENT_TRUST_* values."
  }
}

variable "assurance_environment_variables" {
  description = "Complete non-secret protected variable map consumed by production-assurance.yml."
  type        = map(string)

  validation {
    condition = alltrue([
      for key, value in var.assurance_environment_variables :
      can(regex("^AGENT_TRUST_[A-Z0-9_]+$", key)) && length(trimspace(value)) > 0
    ])
    error_message = "assurance_environment_variables must contain only non-empty AGENT_TRUST_* values."
  }
}

variable "production_environment_variables" {
  description = "Complete non-secret protected variable map consumed by production-release.yml."
  type        = map(string)

  validation {
    condition = alltrue([
      for key, value in var.production_environment_variables :
      can(regex("^AGENT_TRUST_[A-Z0-9_]+$", key)) && length(trimspace(value)) > 0
    ])
    error_message = "production_environment_variables must contain only non-empty AGENT_TRUST_* values."
  }
}
