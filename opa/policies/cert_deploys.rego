package terraform.policies.cert_deploys

import input.plan as tfplan

deny[msg] {
  cert := tfplan.planned_values.root_module.resources[_].values.as3_json
  contains(cert, "BEGIN CERTIFICATE") 
  msg := sprintf("You are exposing the Certificates in  AS3 %v", [cert])
  privkey := tfplan.planned_values.root_module.resources[_].values.as3_json
  contains(privkey, "BEGIN RSA PRIVATE KEY")
  msg1 := sprintf("You are exposing the Private Key in  AS3 %v", [privkey])
}

