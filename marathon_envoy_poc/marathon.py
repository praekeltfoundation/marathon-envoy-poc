import socket

import requests


class MarathonClient:
    def __init__(self, base_url, client=None):
        self._base_url = base_url

        if client is None:
            client = requests.Session()
        self._client = client

    def close(self):
        self._client.close()

    def _request(self, method, path, **kwargs):
        return self._client.request(method, self._base_url + path, **kwargs)

    def test(self):
        assert self._request("GET", "/ping").text == "pong"

    def _get_json_field(self, path, field, **kwargs):
        response = self._request(
            "GET", path, headers={"accept": "application/json"}, **kwargs)

        if response.status_code == 200:
            return response.json()[field]
        elif response.status_code == 404:
            return None
        else:
            raise RuntimeError(
                "Unexpected response code {} from {}: {}".format(
                    response.status_code, path, response.text))

    def get_apps(self):
        return self._get_json_field("/v2/apps", "apps")

    def get_app(self, app_id, embed=[]):
        return self._get_json_field(
            "/v2/apps{}".format(app_id), "app", params={"embed": embed})


# Below is roughly copied from marathon-lb:
# https://github.com/mesosphere/marathon-lb/blob/v1.11.2/utils.py#L314-L437


def get_task_ip_and_ports(app, task):
    mode = _get_networking_mode(app)
    task_ip = _get_task_ip(task, mode)
    task_ports = _get_app_task_ports(app, task, mode)
    return task_ip, task_ports


def _get_task_ip(task, mode):
    if mode == "container":
        task_ip_addresses = task.get("ipAddresses", [])
        if len(task_ip_addresses) == 0:
            # No address allocated yet
            return None
        task_ip = task_ip_addresses[0].get("ipAddress")
        if not task_ip:
            # No address allocated yet
            return None
        return task_ip
    else:
        host = task.get("host")
        if not host:
            # Has no host for some reason
            return None
        task_ip = _resolve_ip(host)
        if not task_ip:
            # Cannot resolve the host address
            return None
        return task_ip


def _resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _get_app_task_ports(app, task, mode):
    """
    :return: list
    """
    if mode == "host":
        task_ports = task.get("ports")
        if not task_ports:
            task_ports = _get_port_definition_ports(app)
        return task_ports
    elif mode == "container/bridge":
        task_ports = task.get("ports")
        if not task_ports:
            task_ports = _get_port_definition_ports(app)
            if not task_ports:
                task_ports = _get_port_mapping_ports(app)
        return task_ports
    else:
        task_ports = _get_ip_address_discovery_ports(app)
        if not task_ports:
            task_ports = _get_port_mapping_ports(app)
        return task_ports


def _get_port_definition_ports(app):
    port_definitions = app.get("portDefinitions", [])
    return [p["port"] for p in port_definitions if "port" in p]


def _get_port_mapping_ports(app):
    port_mappings = _get_app_port_mappings(app)
    return [p["containerPort"] for p in port_mappings if "containerPort" in p]


def _get_app_port_mappings(app):
    port_mappings = (app.get("container", {})
                        .get("docker", {})
                        .get("portMappings", []))
    if not port_mappings:
        port_mappings = app.get("container", {}).get("portMappings", [])

    return port_mappings


# Below is copy/pasta-ed from marathon-acme:
# https://github.com/praekeltfoundation/marathon-acme/blob/0.5.1/marathon_acme/marathon_util.py

def get_number_of_app_ports(app):
    """
    Get the number of ports for the given app JSON. This roughly follows the
    logic in marathon-lb for finding app IPs/ports, although we are only
    interested in the quantity of ports an app should have and don't consider
    the specific IPs/ports of individual tasks:
    https://github.com/mesosphere/marathon-lb/blob/v1.10.3/utils.py#L393-L415
    :param app: The app JSON from the Marathon API.
    :return: The number of ports for the app.
    """
    mode = _get_networking_mode(app)
    ports_list = None
    if mode == 'host':
        ports_list = _get_port_definitions(app)
    elif mode == 'container/bridge':
        ports_list = _get_port_definitions(app)
        if ports_list is None:
            ports_list = _get_container_port_mappings(app)
    elif mode == 'container':
        ports_list = _get_ip_address_discovery_ports(app)
        # Marathon 1.5+: the ipAddress field is missing -> ports_list is None
        # Marathon <1.5: the ipAddress field can be present, but ports_list can
        # still be empty while the container port mapping is not :-/
        if not ports_list:
            ports_list = _get_container_port_mappings(app)
    else:
        raise RuntimeError(
            "Unknown Marathon networking mode '{}'".format(mode))

    return len(ports_list)


def _get_networking_mode(app):
    """
    Get the Marathon networking mode for the app.
    """
    # Marathon 1.5+: there is a `networks` field
    networks = app.get('networks')
    if networks:
        # Modes cannot be mixed, so assigning the last mode is fine
        return networks[-1].get('mode', 'container')

    # Older Marathon: determine equivalent network mode
    container = app.get('container')
    if container is not None and 'docker' in container:
        docker_network = container['docker'].get('network')
        if docker_network == 'USER':
            return 'container'
        elif docker_network == 'BRIDGE':
            return 'container/bridge'

    return 'container' if _is_legacy_ip_per_task(app) else 'host'


def _get_container_port_mappings(app):
    """
    Get the ``portMappings`` field for the app container.
    """
    container = app['container']

    # Marathon 1.5+: container.portMappings field
    port_mappings = container.get('portMappings')

    # Older Marathon: container.docker.portMappings field
    if port_mappings is None and 'docker' in container:
        port_mappings = container['docker'].get('portMappings')

    return port_mappings


def _get_port_definitions(app):
    """
    Get the ``portDefinitions`` field for the app if present.
    """
    if 'portDefinitions' in app:
        return app['portDefinitions']

    # In the worst case try use the old `ports` array
    # Only useful on very old Marathons
    if 'ports' in app:
        return app['ports']

    return None


def _get_ip_address_discovery_ports(app):
    """
    Get the ports from the ``ipAddress`` field for the app if present.
    """
    if not _is_legacy_ip_per_task(app):
        return None
    return app['ipAddress']['discovery']['ports']


def _is_legacy_ip_per_task(app):
    """
    Return whether the application is using IP-per-task on Marathon < 1.5.
    :param app: The application to check.
    :return: True if using IP per task, False otherwise.
    """
    return app.get('ipAddress') is not None
