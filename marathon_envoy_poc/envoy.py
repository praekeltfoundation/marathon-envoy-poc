import binascii


def Duration(seconds, nanos=0):
    # https://developers.google.com/protocol-buffers/docs/reference/google.protobuf#duration
    return {
        "seconds": str(seconds),  # Int64Value
        "nanos": int(nanos),  # Int32Value
    }


def ApiConfigSource(cluster_name, refresh_delay, api_type="REST"):
    # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/base.proto#apiconfigsource
    return {
        "api_type": api_type,
        # NOTE: "Multiple cluster names may be provided. If > 1 cluster is
        # defined, clusters will be cycled through if any kind of failure
        # occurs." -- we probably don't need this for a PoC.
        "cluster_name": [cluster_name],
        "refresh_delay": Duration(refresh_delay),
    }


def Payload(data):
    # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/health_check.proto#envoy-api-msg-healthcheck-payload
    return {"text": binascii.hexlify(data).decode("utf-8")}


def HealthCheck(timeout, interval, tcp_send=b"\x00", tcp_receive=[]):
    # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/health_check.proto#healthcheck
    return {
        "timeout": Duration(timeout),
        "interval": Duration(interval),
        # TODO: Support more of these parameters
        # "interval_jitter": "{...}",
        # "unhealthy_threshold": "{...}",
        # "healthy_threshold": "{...}",
        # "reuse_connection": "{...}",
        # "http_health_check": "{...}",
        # TODO: Support more than TCP checks
        # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/health_check.proto#healthcheck-tcphealthcheck
        "tcp_health_check": {
            "send": Payload(tcp_send),
            "receive": [Payload(r) for r in tcp_receive]
        },
        # "redis_health_check": "{...}"
    }


def Any(type_url, data):
    # https://developers.google.com/protocol-buffers/docs/proto3#json
    res = {"@type": type_url}
    res.update(data)
    return res


def DiscoveryResponse(version_info, resources, type_url):
    # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/discovery.proto#discoveryresponse
    return {
        "version_info": version_info,
        "resources": [Any(type_url, r) for r in resources],
        "type_url": type_url,
    }


def Cluster(name, service_name, eds_config, connect_timeout, type="EDS",
            lb_policy="ROUND_ROBIN", health_checks=[]):
    # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/cds.proto#cluster
    return {
        "name": name,
        "type": type,
        "eds_cluster_config": {
            "eds_config": eds_config,
            "service_name": service_name,
        },
        "connect_timeout": Duration(connect_timeout),
        # "per_connection_buffer_limit_bytes": "{...}",
        "lb_policy": lb_policy,
        # "hosts": [],
        "health_checks": health_checks,
        # "max_requests_per_connection": "{...}",
        # "circuit_breakers": "{...}",
        # "tls_context": "{...}",
        # TODO: Support connecting to clusters with HTTP/2
        "http_protocol_options": {},
        # "http2_protocol_options": "{...}",
        # "dns_refresh_rate": "{...}",
        # "dns_lookup_family": "...",
        # "dns_resolvers": [],
        # "outlier_detection": "{...}",
        # "cleanup_interval": "{...}",
        # "upstream_bind_config": "{...}",
        # "lb_subset_config": "{...}",
        # "ring_hash_lb_config": "{...}",
        # "transport_socket": "{...}"
    }


def LbEndpoint(address, port, filter_metadata={}, load_balancing_weight=1):
    # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/eds.proto#envoy-api-msg-lbendpoint
    return {
        # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/base.proto.html#envoy-api-msg-endpoint
        "endpoint": {
            # FIXME: We only support socket addresses
            # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/address.proto.html#envoy-api-msg-address
            "address": {
                # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/address.proto.html#socketaddress
                "socket_address": {
                    "address": address,
                    "port_value": int(port),
                    "protocol": "TCP",
                }
            }
        },
        # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/base.proto.html#envoy-api-msg-metadata
        "metadata": {"filter_metadata": filter_metadata},
        "load_balancing_weight": load_balancing_weight,
    }


def LocalityLbEndpoints(locality, lb_endpoints):
    # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/eds.proto#localitylbendpoints
    return {
        "locality": locality,
        "lb_endpoints": lb_endpoints,
        # Optional: load_balancing_weight
        # Optional: priority
    }


def ClusterLoadAssignment(cluster_name, lb_endpoints):
    # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/eds.proto#clusterloadassignment
    return {
        "cluster_name": cluster_name,
        # TODO: More than one locality
        "endpoints": [LocalityLbEndpoints("default", lb_endpoints)],
        # TODO: Do we need this? I don't fully understand...
        # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/eds.proto#envoy-api-msg-clusterloadassignment-policy
        "policy": {
            "drop_overload": 0.0,
        },
    }
