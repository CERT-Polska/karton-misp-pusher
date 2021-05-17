#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from pathlib import Path

version_path = Path(__file__).parent / "karton/misp_pusher/__version__.py"
version_info = {}
exec(version_path.read_text(), version_info)

setup(
    name="karton-misp-pusher",
    version=version_info["__version__"],
    description="MISP reporter for the Karton framework",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    namespace_packages=["karton"],
    packages=["karton.misp_pusher"],
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "karton-misp-pusher=karton.misp_pusher:MispPusher.main"
        ],
    },
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)
