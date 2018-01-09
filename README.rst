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
