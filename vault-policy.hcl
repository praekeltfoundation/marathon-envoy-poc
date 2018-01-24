# Get the marathon-acme certificate list
path "secret/marathon-acme/live" {
  capabilities = ["read"]
}

# Get marathon-acme certificates
path "secret/marathon-acme/certificates/*" {
  capabilities = ["read"]
}

# Issue certificates for ourself (the marathon-envoy-poc role)
path "pki/issue/marathon-envoy-poc" {
  capabilities = ["update"]
}
