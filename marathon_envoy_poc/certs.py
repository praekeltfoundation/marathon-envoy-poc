"""
Various utilities for working with x509 PEM-encoded certificates.
"""
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, load_pem_private_key)

import pem


def get_cert_fingerprint(certs):
    # Generally the first certificate in the list is the one we want the
    # fingerprint for. The second cert is the intermediary CA cert.
    return certs[0].fingerprint(hashes.SHA1())


def load_cert_objs(certs_pem_bytes):
    cert_pems = pem.parse(certs_pem_bytes)
    if not cert_pems:
        raise ValueError("Unable to parse any certificate data.")

    return [load_pem_x509_certificate(cert_pem.as_bytes(), default_backend())
            for cert_pem in cert_pems]


def load_key_obj(key_pem_bytes):
    key_pems = pem.parse(key_pem_bytes)
    if len(key_pems) != 1:
        raise ValueError(
            "Unexpected number of private keys. Expected {}, got {}.".format(
                1, len(key_pems)))

    # None -> no password
    return load_pem_private_key(
        key_pems[0].as_bytes(), None, default_backend())


def certs_pem_bytes(cert_objs):
    return b"".join([cert.public_bytes(Encoding.PEM) for cert in cert_objs])


def key_pem_bytes(key_obj):
    return key_obj.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
