import json

import requests


class VaultClient:
    """
    World's most basic Vault API client. Can get data from Vault. A real
    implementation should manage the lease on the Vault token, support custom
    certs for connecting to Vault, etc.
    """

    def __init__(self, base_url, token, kv_mount="secret", pki_mount="pki",
                 client=None):
        self._base_url = base_url
        self._token = token
        self._kv_mount = kv_mount
        self._pki_mount = pki_mount

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

    def _get_raw(self, path, **kwargs):
        response = self._request("GET", "/v1/" + path, **kwargs)

        if response.status_code == 200:
            return response.text
        elif response.status_code == 404:
            return None
        else:
            raise RuntimeError(
                "Unexpected response code {} from {}: {}".format(
                    response.status_code, path, response.text))

    def get_kv(self, path, **kwargs):
        raw = self._get_raw("/".join((self._kv_mount, path)), **kwargs)
        return json.loads(raw)["data"] if raw is not None else None

    def issue_cert(self, role, common_name):
        json_data = {
            "common_name": common_name,
            "format": "pem_bundle",
            "private_key_format": "pkcs8",
        }
        response = self._request(
            "POST", "/v1/{}/issue/{}".format(self._pki_mount, role),
            json=json_data)

        if response.status_code == 200:
            return response.json()["data"]["certificate"]
        else:
            raise RuntimeError(
                "Unexpected response code {} when issuing cert for role {}: {}"
                .format(response.status_code, role, response.text))
