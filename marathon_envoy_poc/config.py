import os


# Roughly copy Flask By Example's config setup:
# https://realpython.com/blog/python/flask-by-example-part-1-project-setup/

class _ConfigBase:
    DEBUG = False
    MARATHON = os.environ.get("MARATHON", "http://127.0.0.1:8080")
    SECRET_KEY = os.environ.get("SECRET_KEY", "change me")
    HAPROXY_GROUP = os.environ.get("HAPROXY_GROUP", "external")

    # Name of our service in Envoy
    CLUSTER_NAME = os.environ.get("CLUSTER_NAME", "xds_cluster")
    # Seconds between polls of our service
    REFRESH_DELAY = os.environ.get("REFRESH_DELAY", 30)

    HTTP_LISTEN_ADDR = os.environ.get("HTTP_LISTEN_ADDR", "0.0.0.0")
    HTTP_LISTEN_PORT = os.environ.get("HTTP_LISTEN_PORT", 80)

    MARATHON_ACME_APP_ID = os.environ.get(
        "MARATHON_ACME_APP_ID", "marathon-acme")
    MARATHON_ACME_PORT_INDEX = os.environ.get("MARATHON_ACME_PORT_INDEX", 0)

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
