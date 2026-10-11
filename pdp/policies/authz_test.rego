package zt.authz

import rego.v1

test_employee_allowed if {
  result := decision with input as {"identity": {"role": "employee", "cert_valid": true, "revoked": false}, "device": {"posture_ok": true}, "trust_score": 80}
  result.allow
  result.admit
  result.tier == "full"
}

test_admin_below_threshold_denied if {
  result := decision with input as {"identity": {"role": "admin", "cert_valid": true, "revoked": false}, "device": {"posture_ok": true}, "trust_score": 70}
  not result.allow
  result.admit
}

test_revoked_always_denied if {
  result := decision with input as {"identity": {"role": "employee", "cert_valid": true, "revoked": true}, "device": {"posture_ok": true}, "trust_score": 100}
  not result.allow
  not result.admit
}

# A fresh device (no posture yet) is admitted to the tunnel but gets no access,
# so it can still reach the PDP to send its posture report.
test_unattested_device_admitted_without_access if {
  result := decision with input as {"identity": {"role": "employee", "cert_valid": true, "revoked": false}, "device": {"posture_ok": false}, "trust_score": 72}
  result.admit
  not result.allow
}

test_unknown_role_not_admitted if {
  result := decision with input as {"identity": {"role": "intruder", "cert_valid": true, "revoked": false}, "device": {"posture_ok": true}, "trust_score": 100}
  not result.admit
  not result.allow
}
