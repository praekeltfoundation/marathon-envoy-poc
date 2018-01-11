import os

from flask import Flask, g, jsonify, request

from .envoy import (
    Cluster, ClusterLoadAssignment, ConfigSource, DiscoveryResponse,
    Filter, FilterChain, HealthCheck, HttpConnectionManager, LbEndpoint,
    Listener, RouteConfiguration, VirtualHost)
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


def own_config_source():
    """
    The config to connect to this API. For specifying the EDS and RDS
    endpoints.
    """
    return ConfigSource(flask_app.config["CLUSTER_NAME"],
                        flask_app.config["REFRESH_DELAY"])


def truncate_object_name(object_name):
    """ Truncate an object name if it is too long. """
    max_len = flask_app.config["MAX_OBJECT_NAME_LENGTH"]
    if len(object_name) > max_len:
        flask_app.logger.warn(
            "Object name '%s' is too long (%d > %d). It will be truncated.",
            object_name, len(object_name), max_len)
        prefix = "[...]"
        object_name = prefix + object_name[-(max_len - len(prefix)):]
    return object_name


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


def default_healthcheck():
    return HealthCheck(
        flask_app.config["CLUSTER_HEALTHCHECK_TIMEOUT"],
        flask_app.config["CLUSTER_HEALTHCHECK_INTERVAL"],
        flask_app.config["CLUSTER_HEALTHCHECK_UNHEALTHY_THRESHOLD"],
        flask_app.config["CLUSTER_HEALTHCHECK_HEALTHY_THRESHOLD"])


@flask_app.route("/v2/discovery:clusters", methods=["POST"])
def clusters():
    clusters = []
    max_version = "0"
    for app in get_marathon().get_apps():
        port_labels = get_app_port_labels(app)
        for index, labels in enumerate(port_labels):
            if labels is None:
                continue

            max_version = max(
                max_version, app["versionInfo"]["lastConfigChangeAt"])

            service_name = "{}_{}".format(app["id"], index)
            cluster_name = truncate_object_name(service_name)

            clusters.append(Cluster(
                cluster_name, service_name, own_config_source(),
                flask_app.config["CLUSTER_CONNECT_TIMEOUT"],
                health_checks=[default_healthcheck()]))

    return jsonify(DiscoveryResponse(max_version, clusters, TYPE_CDS))


def get_cluster_load_assignment(cluster_name, app, tasks, port_index):
    port_labels = get_app_port_labels(app)

    # We have to check these things because they may have changed since the
    # CDS request was made.
    if port_index >= len(port_labels):
        flask_app.logger.warn(
            "App %s with port index %d is outside the range of ports (%d)",
            app["id"], port_index, len(port_labels))
        return ClusterLoadAssignment(cluster_name, [])  # no endpoints

    if port_labels[port_index] is None:
        flask_app.logger.warn(
            "App %s with port index %d has no labels", app["id"], port_index)
        return ClusterLoadAssignment(cluster_name, [])  # no endpoints

    endpoints = []
    for task in tasks:
        ip, ports = get_task_ip_and_ports(app, task)
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
    # Envoy does not send a 'content-type: application/json' header in this
    # request so we must set force=True
    discovery_request = request.get_json(force=True)
    resource_names = discovery_request["resource_names"]

    cluster_load_assignments = []
    max_version = "0"
    for cluster_name in resource_names:
        app_id, port_index = cluster_name.rsplit("_", 1)
        port_index = int(port_index)

        app = get_marathon().get_app(app_id, embed=["app.tasks"])
        # App could've gone away
        if not app:
            continue

        tasks = app["tasks"]
        cluster_load_assignments.append(
            get_cluster_load_assignment(cluster_name, app, tasks, port_index))

        for task in tasks:
            max_version = max(max_version, task.get("startedAt", "0"))

    return jsonify(
        DiscoveryResponse(max_version, cluster_load_assignments, TYPE_EDS))


@flask_app.route("/v2/discovery:listeners", methods=["POST"])
def listeners():
    # TODO: Without TLS/SNI stuff, this is largely static
    filter_chains = [
        FilterChain([
            Filter("envoy.http_connection_manager",
                   HttpConnectionManager("http", "http", own_config_source()))
        ])
    ]
    listeners = [
        Listener(
            "http",
            flask_app.config["HTTP_LISTEN_ADDR"],
            flask_app.config["HTTP_LISTEN_PORT"],
            filter_chains
        )
    ]

    return jsonify(DiscoveryResponse("0", listeners, TYPE_LDS))


def get_app_virtual_hosts(app):
    virtual_hosts = []
    port_labels = get_app_port_labels(app)
    for index, labels in enumerate(port_labels):
        if labels is None or "VHOST" not in labels:
            continue

        domains = labels["VHOST"].replace(",", " ").split()
        if not domains:
            continue

        service_name = "{}_{}".format(app["id"], index)
        cluster_name = truncate_object_name(service_name)

        require_tls = labels.get("REDIRECT_TO_HTTPS") == "true"

        virtual_hosts.append(
            VirtualHost("http_{}_{}".format(app["id"], index), domains,
                        cluster_name, require_tls))

    return virtual_hosts


@flask_app.route("/v2/discovery:routes", methods=["POST"])
def routes():
    # Envoy does not send a 'content-type: application/json' header in this
    # request so we must set force=True
    discovery_request = request.get_json(force=True)
    resource_names = discovery_request["resource_names"]

    apps = get_marathon().get_apps()

    route_configurations = []
    max_version = "0"
    for route_config_name in resource_names:
        # TODO: Support other routes
        if route_config_name != "http":
            return "Unknown route_config_name", 400

        virtual_hosts = []
        # This part is similar to CDS
        for app in apps:
            app_vhosts = get_app_virtual_hosts(app)
            if app_vhosts:
                virtual_hosts.extend(app_vhosts)
                max_version = max(
                    max_version, app["versionInfo"]["lastConfigChangeAt"])

        # TODO: internal_only_headers
        route_configurations.append(
            RouteConfiguration(route_config_name, virtual_hosts, []))

    return jsonify(
        DiscoveryResponse(max_version, route_configurations, TYPE_RDS))


if __name__ == "__main__":  # pragma: no cover
    flask_app.run()
