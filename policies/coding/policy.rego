package agenttrust.coding

import rego.v1

protected_path(path) if { startswith(path, ".env") }
protected_path(path) if { startswith(path, ".git/") }
protected_path(path) if { startswith(path, ".github/workflows/") }
protected_path(path) if { contains(lower(path), "private_key") }

safe_branch if {
  startswith(input.arguments.branch, "agent/")
  input.arguments.branch != "main"
  input.arguments.branch != "master"
}

allow_patch if {
  input.intent.operation == "apply_patch"
  safe_branch
  input.arguments.changed_files <= 50
  input.arguments.deleted_lines <= 2000
  every path in input.arguments.paths { not protected_path(path) }
}

requires_approval if { input.intent.operation in {"push", "deploy", "create_pr"} }

