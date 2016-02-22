import os
from setuptools import setup, find_packages

PACKAGE = "pyabs"
NAME = "pyabs"
DESCRIPTION = "ssh over proxy using paramiko"
AUTHOR = "gmaclinuxer"
AUTHOR_EMAIL = "gmaclinuxer@gmail.com"
URL = ""
# VERSION = __import__(PACKAGE).__version__
VERSION = "1.0.1"

def read(fname):
    # return open(os.path.join(os.path.dirname(__path__), fname)).read()
    return open(fname).read()

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=read("README.rst"),
    license="BSD",
    # py_modules=["pyabs"],
    packages=find_packages(exclude=["tests.*", "tests"]),
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    install_requires=[
        'paramiko'
    ]
)
