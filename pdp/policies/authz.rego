package zt.authz

import rego.v1

default decision := {"allow": false, "admit": false, "tier": "revoke", "reason": "default-deny", "resources": []}

role := input.identity.role if { data.roles[input.identity.role] != null }

tier := "full" if { input.trust_score >= 80 }
tier := "restricted" if { input.trust_score >= 50; input.trust_score < 80 }
tier := "quarantine" if { input.trust_score >= 20; input.trust_score < 50 }
tier := "revoke" if { input.trust_score < 20 }

# Tunnel admission: a known identity with a valid, unrevoked certificate.
# The VPN is only an authenticated channel (docs/05 §1); posture does not gate
# it, otherwise a device could never send the posture report that admits it.
default admit := false

admit if {
  role
  input.identity.cert_valid
  not input.identity.revoked
}

# Resource access: admission plus device posture and the role's score floor.
allow if {
  admit
  input.device.posture_ok
  input.trust_score >= data.roles[role].min_score
}

decision := {"allow": true, "admit": true, "tier": tier, "reason": "policy-allow", "resources": data.roles[role].resources} if allow
decision := {"allow": false, "admit": admit, "tier": tier, "reason": "score-or-identity-deny", "resources": []} if {
  role
  not allow
}
