policy "check_open_as3_cert" {
  query = "data.terraform.policies.cert_deploys.deny"
  enforcement_level = "mandatory"
}
