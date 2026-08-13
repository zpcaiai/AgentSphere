package agenttrust.common_test

import data.agenttrust.common
import rego.v1

base := {"subject":{"tenant_id":"t","trust_level":"verified","roles":[]},"resource":{"tenant_id":"t","locator":"repo:a"},"tool":{"status":"ACTIVE"},"environment":{"deployment":"production"}}

test_matching_tenant_allowed if { common.allow with input as base }
test_cross_tenant_denied if { not common.allow with input as object.union(base, {"resource":{"tenant_id":"other","locator":"repo:a"}}) }
test_dev_identity_in_production_denied if { not common.allow with input as object.union(base, {"subject":{"tenant_id":"t","trust_level":"development","roles":[]}}) }

