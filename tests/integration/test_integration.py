#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import asyncio
import logging
from pathlib import Path

import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]

DB_APPLICATION_NAME = "mongodb-k8s"
NRF_APPLICATION_NAME = "sdcore-nrf"
TLS_PROVIDER_NAME = "self-signed-certificates"


async def _deploy_mongodb(ops_test):
    await ops_test.model.deploy(
        DB_APPLICATION_NAME,
        application_name=DB_APPLICATION_NAME,
        channel="5/edge",
        trust=True,
    )


async def _deploy_sdcore_nrf_operator(ops_test):
    await _deploy_mongodb(ops_test)
    await ops_test.model.deploy(
        NRF_APPLICATION_NAME,
        application_name=NRF_APPLICATION_NAME,
        channel="edge",
        trust=True,
    )
    await ops_test.model.add_relation(
        relation1=DB_APPLICATION_NAME, relation2=NRF_APPLICATION_NAME
    )


async def _deploy_tls_provider(ops_test):
    await ops_test.model.deploy(
        TLS_PROVIDER_NAME,
        application_name=TLS_PROVIDER_NAME,
        channel="edge",
    )


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test):
    """Build the charm-under-test and deploy it."""
    deploy_nrf = asyncio.create_task(_deploy_sdcore_nrf_operator(ops_test))
    deploy_tls_provider = asyncio.create_task(_deploy_tls_provider(ops_test))
    charm = await ops_test.build_charm(".")
    await deploy_nrf
    await deploy_tls_provider
    resources = {
        "ausf-image": METADATA["resources"]["ausf-image"]["upstream-source"],
    }
    await ops_test.model.deploy(
        charm,
        resources=resources,
        application_name=APP_NAME,
        trust=True,
    )


@pytest.mark.abort_on_fail
async def test_relate_and_wait_for_active_status(
    ops_test,
    build_and_deploy,
):
    await ops_test.model.add_relation(relation1=APP_NAME, relation2=NRF_APPLICATION_NAME)
    await ops_test.model.add_relation(relation1=APP_NAME, relation2=TLS_PROVIDER_NAME)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )
