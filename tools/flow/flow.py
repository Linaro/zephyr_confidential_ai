#! /usr/bin/env python3
#
# Copyright 2022 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#
# Implements: RTOS-25

import click
from pathlib import Path
import sys

import config
import keys

@click.command(help='''Generate keys to use''')
def gen():
    certdir = config.keydir()
    if certdir.exists():
        print("key directory already exists, remove to be able to create new")
        sys.exit(1)
    certdir.mkdir()
    print("Generating CA to {}, and {}".format(config.ca_key(), config.ca_cert()))
    cert = keys.CA()
    cert.gen()
    cert.save(config.ca_key(), config.ca_cert())

    print("Generating device keys to {}, and {}".format(config.device_key(), config.device_cert()))
    dev = keys.EndKey()
    dev.gen(config.device, cert, "Signing")
    dev.save(config.device_key(), config.device_cert())

    print("Generating cloud keys to {}, and {}".format(config.cloud_key(), config.cloud_cert()))
    cloud = keys.EndKey()
    cloud.gen(config.cloud, cert, "Encryption") # TODO: Distinguish the types of these.
    cloud.save(config.cloud_key(), config.cloud_cert())

@click.command(cls=click.Group)
def flow():
    pass

flow.add_command(gen)

if __name__ == '__main__':
    flow()
