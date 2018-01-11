import os

from flask import Flask, g, jsonify, request

from .envoy import (
    Cluster, ClusterLoadAssignment, ConfigSource, DiscoveryResponse,
    Filter, FilterChain, HealthCheck, HttpConnectionManager, LbEndpoint,
    Listener, Route, RouteConfiguration, VirtualHost)
from .marathon import (
    MarathonClient, get_number_of_app_ports, get_task_ip_and_ports)

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


def find_port_labels(labels, port_index, prefix):
    label_prefix = "{}_{}_".format(prefix, port_index)
    return {
        key[len(label_prefix):]: val for key, val in labels.items()
        if key.startswith(label_prefix)
    }


def is_port_in_group(labels, port_index):
    """
    Does the given port index have labels that indicate it is in the correct
    HAPROXY_GROUP.
    """
    port_group = labels.get(
        "HAPROXY_{}_GROUP".format(port_index), labels.get("HAPROXY_GROUP"))

    return port_group == flask_app.config["HAPROXY_GROUP"]


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
        for port_index in range(get_number_of_app_ports(app)):
            if not is_port_in_group(app["labels"], port_index):
                continue

            max_version = max(
                max_version, app["versionInfo"]["lastConfigChangeAt"])

            cluster_name, service_name = app_cluster(app["id"], port_index)

            clusters.append(Cluster(
                cluster_name, service_name, own_config_source(),
                flask_app.config["CLUSTER_CONNECT_TIMEOUT"],
                health_checks=[default_healthcheck()]))

    return jsonify(DiscoveryResponse(max_version, clusters, TYPE_CDS))


def get_cluster_load_assignment(cluster_name, app, tasks, port_index):
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

        if port_index >= len(ports):
            flask_app.logger.warn(
                "Somehow task '%s' doesn't have port with index %d, it only "
                "has %d ports", task["id"], port_index, len(ports))
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

        # We have to check these things because they may have changed since the
        # CDS request was made--this is normal behaviour.
        # App could've gone away
        if not app:
            flask_app.logger.debug(
                "App '%s' endpoints requested but the app doesn't exist "
                "anymore",  app["id"])
            continue

        # Port could've gone away
        if port_index >= get_number_of_app_ports(app):
            flask_app.logger.debug(
                "App '%s' port %d endpoints requested but the port doesn't "
                "exist anymore", app["id"], port_index)
            continue

        # Port labels could've changed
        if not is_port_in_group(app["labels"], port_index):
            flask_app.logger.debug(
                "App '%s' port %d endpoints requested but the port isn't in "
                "the correct group anymore", app["id"], port_index)
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


def marathon_acme_cluster():
    ma, _ = app_cluster(flask_app.config["MARATHON_ACME_APP_ID"],
                        flask_app.config["MARATHON_ACME_PORT_INDEX"])
    return ma


def app_cluster(app_id, port_index):
    service_name = "{}_{}".format(app_id, port_index)
    return truncate_object_name(service_name), service_name


def get_app_virtual_hosts(app):
    virtual_hosts = []
    app_labels = app["labels"]
    for port_index in range(get_number_of_app_ports(app)):
        if not is_port_in_group(app_labels, port_index):
            continue

        vhost_domains = get_port_domains(
            app_labels, port_index, "HAPROXY", "VHOST")
        if not vhost_domains:
            flask_app.logger.debug(
                "App '%s' port %d has no domains in its HAPROXY_VHOST label. "
                "It will be ignored.", app["id"], port_index)
            continue

        marathon_acme_domains = get_port_domains(
            app_labels, port_index, "MARATHON_ACME", "DOMAIN")

        cluster_name, service_name = app_cluster(app["id"], port_index)

        routes = []
        # Routes are matched in order, and we want marathon-acme to apply first
        # NOTE: If a marathon-acme domain
        for domain in marathon_acme_domains:
            if domain not in vhost_domains:
                flask_app.logger.warn(
                    "App '%s' has marathon-acme domain (%s) that is not in "
                    "the vhost domains", app["id"], domain)
                continue

            routes.append(Route(marathon_acme_cluster(),
                                prefix="/.well-known/acme-challenge",
                                # FIXME: authority match is probably overkill
                                authority=domain))

        # TODO: Support other prefixes
        routes.append(Route(cluster_name, prefix="/"))

        # TODO: Figure out how to *not* redirect marathon-acme requests to
        # HTTPS.
        require_tls = app_labels.get("REDIRECT_TO_HTTPS") == "true"

        virtual_hosts.append(
            VirtualHost(service_name, vhost_domains, routes, require_tls))

    return virtual_hosts


def parse_domains(domain_str):
    # TODO: Validate domains are valid
    return domain_str.replace(",", " ").split()


def get_port_domains(app_labels, port_index, prefix, label):
    port_labels = find_port_labels(app_labels, port_index, prefix)
    return parse_domains(port_labels.get(label, ""))


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
