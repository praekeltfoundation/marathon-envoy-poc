import requests


class VaultClient:
    """
    World's most basic Vault API client. Can get data from Vault. A real
    implementation should manage the lease on the Vault token, support custom
    certs for connecting to Vault, etc.
    """

    def __init__(self, base_url, token, mount_point="/", client=None):
        self._base_url = base_url
        self._token = token
        self._mount_point = mount_point

        if client is None:
            client = requests.Session()
        self._client = client

    def close(self):
        self._client.close()

    def _request(self, method, path, headers=None, **kwargs):
        if headers is None:
            headers = {}

        _headers = {"X-Vault-Token": self._token}
        _headers.update(headers)

        return self._client.request(
            method, self._base_url + path, headers=_headers, **kwargs)

    def test(self):
        assert self._request("HEAD", "/v1/sys/health").status_code == 200

    def get(self, path, **kwargs):
        response = self._request(
            "GET", "/v1" + self._mount_point + path, **kwargs)

        if response.status_code == 200:
            return response.json()["data"]
        elif response.status_code == 404:
            return None
        else:
            raise RuntimeError(
                "Unexpected response code {} from {}: {}".format(
                    response.status_code, path, response.text))
