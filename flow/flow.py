#! /usr/bin/env python3
#
# Copyright 2022 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#
# Implements: RTOS-25

import click
import config

import ca

@click.command(help='''Generate a CA key to use''')
def gen_ca():
    print("Generate CA cert, to", config.ca_cert())
    ca.gen()

@click.command(cls=click.Group)
def flow():
    pass

flow.add_command(gen_ca)

if __name__ == '__main__':
    flow()
