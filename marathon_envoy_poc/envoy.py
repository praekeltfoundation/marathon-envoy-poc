import binascii


def Duration(seconds, nanos=0):
    # https://developers.google.com/protocol-buffers/docs/reference/google.protobuf#duration
    return {
        "seconds": str(seconds),  # Int64Value
        "nanos": nanos,  # Int32Value
    }


def Payload(data):
    # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/health_check.proto#envoy-api-msg-healthcheck-payload
    return {"text": binascii.hexlify(data).decode("utf-8")}


def TcpHealthCheck(send=b'', receive=[]):
    # https://www.envoyproxy.io/docs/envoy/v1.5.0/api-v2/health_check.proto#healthcheck-tcphealthcheck
    return {
        "send": Payload(send),
        "receive": [Payload(r) for r in receive],
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
