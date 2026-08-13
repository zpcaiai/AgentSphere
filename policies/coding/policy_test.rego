package agenttrust.coding_test

import data.agenttrust.coding
import rego.v1

test_task_branch_patch_allowed if { coding.allow_patch with input as {"intent":{"operation":"apply_patch"},"arguments":{"branch":"agent/task-1","changed_files":2,"deleted_lines":5,"paths":["src/lib.rs"]}} }
test_main_branch_denied if { not coding.allow_patch with input as {"intent":{"operation":"apply_patch"},"arguments":{"branch":"main","changed_files":2,"deleted_lines":5,"paths":["src/lib.rs"]}} }
test_workflow_path_denied if { not coding.allow_patch with input as {"intent":{"operation":"apply_patch"},"arguments":{"branch":"agent/task-1","changed_files":2,"deleted_lines":5,"paths":[".github/workflows/release.yml"]}} }

