import os


# Roughly copy Flask By Example's config setup:
# https://realpython.com/blog/python/flask-by-example-part-1-project-setup/

class _ConfigBase:
    DEBUG = False
    MARATHON = os.environ.get("MARATHON", "http://127.0.0.1:8080")
    SECRET_KEY = os.environ.get("SECRET_KEY", "change me")
    HAPROXY_GROUP = os.environ.get("HAPROXY_GROUP", "external")

    LABEL_PREFIX_MARATHON_LB = os.environ.get(
        "LABEL_PREFIX_MARATHON_LB", "HAPROXY")

    # Name of our service in Envoy
    CLUSTER_NAME = os.environ.get("CLUSTER_NAME", "xds_cluster")
    # Seconds between polls of our service
    REFRESH_DELAY = os.environ.get("REFRESH_DELAY", 30)

    VAULT = os.environ.get("VAULT", "http://127.0.0.1:8200")
    VAULT_TOKEN = os.environ.get("VAULT_TOKEN")

    VAULT_PKI_MOUNT = os.environ.get("VAULT_PKI_MOUNT", "pki")
    VAULT_PKI_ROLE = os.environ.get("VAULT_PKI_ROLE", "marathon-envoy-poc")
    VAULT_PKI_CN = os.environ.get("VAULT_PKI_CN", "marathon-envoy-poc")

    VAULT_KV_MOUNT = os.environ.get("VAULT_KV_MOUNT", "secret")
    MARATHON_ACME_KV_PATH = os.environ.get(
        "MARATHON_ACME_KV_PATH", "marathon-acme")

    HTTP_LISTEN_ADDR = os.environ.get("HTTP_LISTEN_ADDR", "0.0.0.0")
    HTTP_LISTEN_PORT = os.environ.get("HTTP_LISTEN_PORT", 80)
    HTTPS_LISTEN_ADDR = os.environ.get("HTTPS_LISTEN_ADDR", "0.0.0.0")
    HTTPS_LISTEN_PORT = os.environ.get("HTTPS_LISTEN_PORT", 443)

    CLUSTER_CONNECT_TIMEOUT = 5
    CLUSTER_HEALTHCHECK_TIMEOUT = 5
    CLUSTER_HEALTHCHECK_INTERVAL = 30
    CLUSTER_HEALTHCHECK_UNHEALTHY_THRESHOLD = 3
    CLUSTER_HEALTHCHECK_HEALTHY_THRESHOLD = 1

    MAX_OBJECT_NAME_LENGTH = 60


class DevConfig(_ConfigBase):
    DEBUG = True


class ProdConfig(_ConfigBase):
    # Nothing to do for now
    pass
