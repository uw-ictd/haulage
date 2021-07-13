#! /usr/bin/env python3

""" This module builds all of the components in the colte ecosystem according to
specific tag versions for each component.

It attempts to only use python3 standard library functions for portability, but
assumes the host system has python3 and has access to git on the user PATH.
"""

from pathlib import Path

import argparse
import logging
import os
import shutil
import subprocess

DISTRIBUTIONS = ["buster", "bionic", "focal", "bullseye"]


def _setup_workspace(workspace_path):
    """Setup a barebones workspace with the correct directory structure and files."""
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Make a directory to bind mount into the containers for output
    Path(workspace_path.joinpath("build")).mkdir(parents=True, exist_ok=True)


def _build_docker_image(base_build_path, dockerfile, image_tag):
    subprocess.run(
        ["docker", "build", "-f", dockerfile, "--tag", image_tag, base_build_path]
    )


def _run_dockerized_build(workspace_path, image_tag):
    host_bind_path = workspace_path.joinpath("build").resolve()

    subprocess.run(
        [
            "docker",
            "run",
            "-v",
            "{}:/build-volume".format(str(host_bind_path)),
            image_tag,
            str(os.getuid()),
        ]
    )


def main(workspace_path):
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    log.debug("Parsed args {}".format(args))

    _setup_workspace(workspace_path)

    for distro in DISTRIBUTIONS:
        image_name = "haulage/{}-build-local".format(distro)
        _build_docker_image(
            workspace_path,
            Path("pkg/crossplatform/Dockerfile-{}".format(distro)),
            image_tag=image_name,
        )
        _run_dockerized_build(workspace_path, image_tag=image_name)


if __name__ == "__main__":
    logging.basicConfig()
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)

    main(workspace_path=Path("./"))

    logging.shutdown()
