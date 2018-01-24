import os
import ssl
import tempfile

from marathon_envoy_poc.app import flask_app, issue_vault_cert


def _load_cert_data(ssl_context, certdata):
    # Workaround because Python ssl lib doesn't support in-memory cert loading
    fd, temp_path = tempfile.mkstemp()
    try:
        os.write(fd, certdata.encode("utf-8"))
        ssl_context.load_cert_chain(temp_path)
    finally:
        os.close(fd)
        os.remove(temp_path)


def main():
    # TODO: Reload cert before it expires
    with flask_app.app_context():
        certdata = issue_vault_cert()

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    _load_cert_data(ssl_context, certdata)

    flask_app.run(ssl_context=ssl_context)


if __name__ == '__main__':
    main()
