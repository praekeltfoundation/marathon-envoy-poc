import binascii
import os

from flask import Flask, g, jsonify, request

from .certs import (
    cert_fingerprint, fullchain_pem_str, key_pem_str, load_cert_obj,
    load_chain_objs, load_key_obj)
from .envoy import (
    Cluster, ClusterLoadAssignment, CommonTlsContext, ConfigSource,
    DiscoveryResponse, Filter, FilterChain, HealthCheck, HttpConnectionManager,
    LbEndpoint, Listener, RouteConfiguration, VirtualHost)
from .marathon import (
    MarathonClient, get_number_of_app_ports, get_task_ip_and_ports)
from .vault import VaultClient

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


def connect_vault():
    if flask_app.config["VAULT_TOKEN"] is None:
        flask_app.logger.warn(
            "VAULT_TOKEN config option not set. Unable to create Vault client."
        )
        return None

    client = VaultClient(
        flask_app.config["VAULT"], flask_app.config["VAULT_TOKEN"],
        flask_app.config["MARATHON_ACME_VAULT_PATH"])
    client.test()
    return client


def get_vault():
    if not hasattr(g, "vault"):
        g.vault = connect_vault()
    return g.vault


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


def app_cluster(app_id, port_index):
    service_name = "{}_{}".format(app_id, port_index)
    return truncate_object_name(service_name), service_name


def port_label(app_labels, port_index, label, prefix=None, default=None):
    """
    Get a label for a given port index.

    :param app_labels: All the labels for the app.
    :param port_index: The port index.
    :param label: The label to get.
    :param prefix:
        The prefix for the label key. If not specified, the config value for
        LABEL_PREFIX_MARATHON_LB will be used.
    :param default: Default value to return if the label is not found.
    """
    if prefix is None:
        prefix = flask_app.config["LABEL_PREFIX_MARATHON_LB"]

    port_label_key = "{}_{}_{}".format(prefix, port_index, label)
    return app_labels.get(port_label_key, default)


def app_label(app_labels, label, prefix=None, default=None):
    """
    Get a label for the app.

    :param app_labels: All the labels for the app.
    :param label: The label to get.
    :param prefix:
        The prefix for the label key. If not specified, the config value for
        LABEL_PREFIX_MARATHON_LB will be used.
    :param default: Default value to return if the label is not found.
    """
    if prefix is None:
        prefix = flask_app.config["LABEL_PREFIX_MARATHON_LB"]

    app_label_key = "{}_{}".format(prefix, label)
    return app_labels.get(app_label_key, default)


def is_port_in_group(app_labels, port_index):
    """
    Does the given port index have labels that indicate it is in the correct
    HAPROXY_GROUP.
    """
    port_group = port_label(app_labels, port_index, "GROUP",
                            default=app_label(app_labels, "GROUP"))

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


def default_http_conn_manager_filters(name):
    return [
        Filter("envoy.http_connection_manager",
               # Params are: name, stats_prefix, api_config_source
               HttpConnectionManager(name, name, own_config_source()))
    ]


def http_filter_chains():
    return [FilterChain(default_http_conn_manager_filters("http"))]


def _get_cached_cert(domain, cert_id):
    if domain in g._certificates:
        cert, chain, key = g._certificates[domain]
        # We check the fingerprint only when fetching certs from the cache, not
        # when storing. Doesn't really matter if the cert we get from Vault
        # doesn't have the right ID, it will hopefully be the right cert when
        # we next try to fetch from Vault.
        # NOTE: We compare "raw" bytes here. This way, binascii will take of
        # uppercase vs lowercase hex encoding.
        if cert_fingerprint(cert) == binascii.dehexlify(cert_id):
            return cert, chain, key

    return None


def _get_vault_cert(domain):
    cert = get_vault().get("/certificates/" + domain)
    if cert is None:
        flask_app.logger.warn(
            "Certificate not found in Vault for domain %s", domain)
        return None

    try:
        return (load_cert_obj(cert["cert"]),
                # Chain certificates optional
                load_chain_objs(cert.get("chain", "")),
                load_key_obj(cert["privkey"]))
    except Exception as e:
        flask_app.logger.warn(
            "Error parsing Vault certificate for domain %s: %s", domain, e)
        return None


def get_certificates():
    if not hasattr(g, "_certificates"):
        g._certificates = {}

    vault_client = get_vault()
    if vault_client is None:
        flask_app.logger.warn("Unable to fetch certificates: no Vault client.")
        return {}

    # Get the mapping of domain name to x509 cert hash. This can be used to
    # check our existing cache of certificates for changes.
    live_certs = vault_client.get("/live")

    # Regenerate the set of certificates, updating if certs added/changed
    certificates = {}
    for domain, cert_id in live_certs.items():
        # First, try get the certificate from the cache
        cached_cert = _get_cached_cert(domain, cert_id)
        if cached_cert is not None:
            certificates[domain] = cached_cert
        else:
            # Otherwise, fetch it from Vault
            vault_cert = _get_vault_cert(domain)
            if vault_cert is not None:
                certificates[domain] = vault_cert
        # Removed certs are skipped

    # Update the cache
    g._certificates = certificates

    # Finally, map the certificate and key objects back into the right form for
    # use by Envoy
    return {domain: (fullchain_pem_str(certs, chain), key_pem_str(key))
            for domain, (certs, chain, key) in certificates.items()}


def https_filter_chains():
    # NOTE: Filters must be identical across FilterChains for a given listener.
    # Currently, Envoy only supports multiple FilterChains in order to support
    # SNI.
    filters = default_http_conn_manager_filters("https")

    # Fetch the certs from Vault
    filter_chains = []
    certificates = get_certificates()
    for domain, (cert_chain, private_key) in sorted(certificates.items()):
        # TODO: Read domains from certificate to support SAN
        tls_context = CommonTlsContext(cert_chain, private_key)
        filter_chains.append(FilterChain(
            filters, sni_domains=[domain], common_tls_context=tls_context))
    return filter_chains


@flask_app.route("/v2/discovery:listeners", methods=["POST"])
def listeners():
    listeners = [
        Listener(
            "http",
            flask_app.config["HTTP_LISTEN_ADDR"],
            flask_app.config["HTTP_LISTEN_PORT"],
            http_filter_chains()
        ),
        Listener(
            "https",
            flask_app.config["HTTPS_LISTEN_ADDR"],
            flask_app.config["HTTPS_LISTEN_PORT"],
            https_filter_chains()
        )
    ]

    return jsonify(DiscoveryResponse("0", listeners, TYPE_LDS))


def get_app_virtual_hosts(app):
    virtual_hosts = []
    app_labels = app["labels"]
    for port_index in range(get_number_of_app_ports(app)):
        if not is_port_in_group(app_labels, port_index):
            continue

        domains = parse_domains(
            port_label(app_labels, port_index, "VHOST", default=""))
        if not domains:
            flask_app.logger.debug(
                "App '%s' port %d has no domains in its HAPROXY_VHOST label. "
                "It will be ignored.", app["id"], port_index)
            continue

        cluster_name, service_name = app_cluster(app["id"], port_index)

        # TODO: Figure out how to *not* redirect marathon-acme requests to
        # HTTPS.
        require_tls = app_labels.get("REDIRECT_TO_HTTPS") == "true"

        virtual_hosts.append(
            VirtualHost(service_name, domains, cluster_name, require_tls))

    return virtual_hosts


def parse_domains(domain_str):
    # TODO: Validate domains are valid
    return domain_str.replace(",", " ").split()


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
        if route_config_name not in ["http", "https"]:
            flask_app.logger.warn(
                "Unknown route config name: %s", route_config_name)
            continue

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
