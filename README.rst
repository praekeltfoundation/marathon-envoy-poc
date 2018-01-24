marathon-envoy-poc
==================

Proof of Concept Discovery Service (xDS) for the Envoy proxy. This sets up
Envoy as an "edge" proxy in an attempt to replace marathon-lb.

- Simple Flask app that queries Marathon
- Reuses *some* of the ``HAPROXY_`` labels from marathon-lb
- Implements the Envoy v2 API available in Envoy 1.5.0+
- REST-JSON implementation (production version should probably use gRPC)
- Will implement all four xDS APIs:

  - Cluster Discovery Service (CDS)
  - Endpoint Discovery Service (EDS)
  - Listener Discovery Service (LDS)
  - Route Discovery Service (RDS)


Usage
-----
To give this a try, you will need a running Marathon instance and Vault
instance. You can run the Flask app using the default Flask server::

  $ pip install -e .
    [...]
  $ python -m marathon_envoy_poc
  * Serving Flask app "marathon_envoy_poc"
  * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)

You can adjust the address for Marathon using the ``MARATHON`` environment
variable, and the address for Vault using the ``VAULT`` environment variable.
Several other configuration options can be set using environment variables. See
the ``config.py`` file for those options.

Envoy will need a CA certificate from Vault in order to validate the xDS's
certificate. You can fetch the CA cert using a command like this (this is an
un-authed Vault endpoint)::

  curl https://myvault.com:8200/v1/pki/ca/pem > vault-ca.pem

Envoy is then most easily run using Docker::

  docker run --rm -it -v "$(pwd)":/mep --net=host envoyproxy/envoy:latest \
    envoy -c /mep/bootstrap.yaml --service-node test --service-cluster test

This will use port 80/443 on your machine (or whatever ports the LDS tells
Envoy to listen on). If you'd rather keep Envoy more isolated while testing,
you can remove the ``--net=host`` argument and add ``-p 9901:9901`` so that
Envoy's admin interface is still available. You'll also need to update the
address for the ``xds_cluster`` in ``bootstrap.yaml`` so that Envoy can reach
the Flask app, wherever you are running it.

Vault setup
^^^^^^^^^^^
Setting up Vault takes quite a few steps. Firstly, you will need a Vault policy
for the xDS to use. Such a policy is provided in the ``vault-policy.hcl`` file.

The xDS uses the PKI backend to get certificates for TLS. This means a PKI role
must be created that the xDS will use when requesting certificates. By default
this role is called ``marathon-envoy-poc`` but can be adjusted in the config.

**Note:** This PKI system is currently only used for server-side certificates
in this proof-of-concept. This means that there is **no authentication of the**
**client** (Envoy).
