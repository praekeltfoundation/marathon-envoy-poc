import os

from flask import Flask, g, jsonify, request

from .envoy import (
    ClusterLoadAssignment, DiscoveryResponse, Duration, LbEndpoint,
    TcpHealthCheck)
from .marathon import (
    MarathonClient, get_number_of_app_ports, get_task_ip_and_ports,
    haproxy_port_labels)

# Don't name the flask app 'app' as is usually done as it's easy to mix up with
# a Marathon app
flask_app = Flask(__name__)
flask_app.config.from_object(
    os.environ.get("APP_CONFIG", "marathon_envoy_poc.config.DevConfig"))


TYPE_LDS = "type.googleapis.com/envoy.api.v2.Listener"
TYPE_RDS = "type.googleapis.com/envoy.api.v2.RouteConfiguration"
TYPE_CDS = "type.googleapis.com/envoy.api.v2.Cluster"
TYPE_EDS = "type.googleapis.com/envoy.api.v2.ClusterLoadAssignment"


def connect_marathon():
    client = MarathonClient(flask_app.config["MARATHON"])
    client.test()
    return client


def get_marathon():
    if not hasattr(g, "marathon"):
        g.marathon = connect_marathon()
    return g.marathon


def own_api_config_source():
    """
    The config to connect to this API. For specifying the EDS and RDS
    endpoints.
    """
    return {
        "api_config_source": {
            "api_type": "REST",
            "cluster_name": flask_app.config["CLUSTER_NAME"],
            "refresh_delay": Duration(flask_app.config["REFRESH_DELAY"]),
        }
    }


def should_consider_app(app):
    return any(get_app_port_labels(app))


def get_app_port_labels(app):
    """
    Get a list of port labels. e.g. at index 1 will be a dict of the HAPROXY
    labels relevant to port 1. Ports that do not have the correct GROUP label
    will have None instead of a dict.
    """
    # Mostly copied from marathon-acme
    labels = app["labels"]
    app_group = labels.get("HAPROXY_GROUP")

    # Iterate through the ports, checking for corresponding labels
    port_labels = []
    for port_index in range(get_number_of_app_ports(app)):
        # Get the port group label, defaulting to the app group label
        port_group = labels.get(
            "HAPROXY_{}_GROUP".format(port_index), app_group)

        if port_group == flask_app.config["HAPROXY_GROUP"]:
            port_labels.append(haproxy_port_labels(labels, port_index))
        else:
            port_labels.append(None)

    return port_labels


@flask_app.route("/v2/discovery:clusters", methods=["POST"])
def clusters():
    clusters = []
    for app in get_marathon().get_apps():
        port_labels = get_app_port_labels(app)
        for index, labels in enumerate(port_labels):
            if labels is None:
                continue

            name = "{}_{}".format(app["id"], index)
            clusters.append({
                "name": name,
                "type": "EDS",
                "eds_cluster_config": {
                    "eds_config": own_api_config_source(),
                    "service_name": name,
                },
                "lb_policy": "ROUND_ROBIN",
                "health_checks": [
                    {
                        "timeout": Duration(
                            flask_app.config["HEALTHCHECK_TIMEOUT"]),
                        "interval": Duration(
                            flask_app.config["HEALTHCHECK_INTERVAL"]),
                        "tcp_health_check": TcpHealthCheck(),
                        # unhealthy_threshold
                        # healthy_threshold
                    }
                ],
            })

    return jsonify(DiscoveryResponse("0", clusters, TYPE_CDS))


def get_cluster_load_assignment(cluster_name):
    app_id, port_index = cluster_name.rsplit("_", 1)
    port_index = int(port_index)
    app_with_tasks = get_marathon().get_app(app_id, embed=["app.tasks"])

    port_labels = get_app_port_labels(app_with_tasks)

    # We have to check these things because they may have changed since the
    # CDS request was made.
    if port_index >= len(port_labels):
        flask_app.logger.warn(
            "App %s with port index %d is outside the range of ports (%d)",
            app_id, port_index, len(port_labels))
        return ClusterLoadAssignment(cluster_name, [])  # no endpoints

    if port_labels[port_index] is None:
        flask_app.logger.warn(
            "App %s with port index %d has no labels", app_id, port_index)
        return ClusterLoadAssignment(cluster_name, [])  # no endpoints

    endpoints = []
    for task in app_with_tasks["tasks"]:
        ip, ports = get_task_ip_and_ports(app_with_tasks, task)
        if ip is None:
            flask_app.logger.warn("Couldn't find IP for task %s", task["id"])
            continue
        if ports is None:
            flask_app.logger.warn(
                "Couldn't find ports for task %s", task["id"])
            continue
        # FIXME: Do we need to check this?
        if len(ports) != len(port_labels):
            flask_app.logger.warn(
                "Unexpected number of ports for task %s. Expected %d, got %d",
                task["id"], len(port_labels), len(ports))
            continue

        endpoints.append(LbEndpoint(ip, ports[port_index]))
    return ClusterLoadAssignment(cluster_name, endpoints)


@flask_app.route("/v2/discovery:endpoints", methods=["POST"])
def endpoints():
    discovery_request = request.get_json()
    resource_names = discovery_request["resource_names"]

    clas = [get_cluster_load_assignment(n) for n in resource_names]

    return jsonify(DiscoveryResponse("0", clas, TYPE_EDS))


@flask_app.route("/v2/discovery:listeners", methods=["POST"])
def listeners():
    # TODO: Without TLS/SNI stuff, this is largely static
    pass


@flask_app.route("/v2/discovery:routers", methods=["POST"])
def routers():
    pass


if __name__ == "__main__":  # pragma: no cover
    flask_app.run()
