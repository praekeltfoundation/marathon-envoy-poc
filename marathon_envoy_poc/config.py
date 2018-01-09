import os


# Roughly copy Flask By Example's config setup:
# https://realpython.com/blog/python/flask-by-example-part-1-project-setup/

class _ConfigBase:
    DEBUG = False
    MARATHON = os.environ.get("MARATHON", "http://127.0.0.1:8080")
    SECRET_KEY = os.environ.get("SECRET_KEY", "change me")
    HAPROXY_GROUP = os.environ.get("HAPROXY_GROUP", "external")

    # Name of our service in Envoy
    CLUSTER_NAME = os.environ.get("CLUSTER_NAME", "xds_service")
    # Seconds between polls of our service
    REFRESH_DELAY = os.environ.get("REFRESH_DELAY", 30)

    HEALTHCHECK_TIMEOUT = 5
    HEALTHCHECK_INTERVAL = 30


class DevConfig(_ConfigBase):
    DEBUG = True


class ProdConfig(_ConfigBase):
    # Nothing to do for now
    pass
