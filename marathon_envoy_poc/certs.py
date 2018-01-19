"""
Tools for converting PEM string data to/from cryptography primitive types.
"""
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, load_pem_private_key)

import pem


def cert_fingerprint(cert):
    return cert.fingerprint(hashes.SHA1())


def load_cert_obj(cert_pem_str):
    cert_pems = pem.parse(cert_pem_str.encode("utf-8"))
    if len(cert_pems) != 1:
        raise ValueError(
            "Unexpected number of certificates. Expected {}, got {}.".format(
                1, len(cert_pems)))

    return load_pem_x509_certificate(
        cert_pems[0].as_bytes(), default_backend())


def load_chain_objs(chain_pem_str):
    # 0 or more chain certificates
    return [load_pem_x509_certificate(chain_pem.as_bytes())
            for chain_pem in pem.parse(chain_pem_str.encode("utf-8"))]


def load_key_obj(key_pem_str):
    key_pems = pem.parse(key_pem_str.encode("utf-8"))
    if len(key_pems) != 1:
        raise ValueError(
            "Unexpected number of private keys. Expected {}, got {}.".format(
                1, len(key_pems)))

    # None -> no password
    return load_pem_private_key(
        key_pems[0].as_bytes(), None, default_backend())


def cert_pem_str(cert_obj):
    return cert_obj.public_bytes(Encoding.PEM).decode("utf-8")


def fullchain_pem_str(cert_obj, chain_objs):
    return "".join([cert_pem_str(cert) for cert in [cert_obj] + chain_objs])


def key_pem_str(key_obj):
    return key_obj.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("utf-8")
