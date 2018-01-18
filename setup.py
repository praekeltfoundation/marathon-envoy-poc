import os

from setuptools import find_packages, setup

HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    with open(os.path.join(HERE, *parts)) as f:
        return f.read()


setup(
    name="marathon-envoy-poc",
    license="BSD-3-Clause",
    author="Jamie Hewland",
    author_email="jamie@praekelt.org",
    long_description=read("README.rst"),
    version="0.1.0.dev0",
    url="https://github.com/praekeltfoundation/marathon-envoy-poc",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "cryptography",
        "flask",
        "pem",
        "requests",
    ],
    extras_require={
        # "test": ["pytest>=3"],
        "lint": ["flake8"],
    },
)
