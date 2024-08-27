import tempfile

import pytest
import scenario
from interface_tester import InterfaceTester
from ops.pebble import Layer, ServiceStatus

from charm import AUSFOperatorCharm


@pytest.fixture
def interface_tester(interface_tester: InterfaceTester):
    with tempfile.TemporaryDirectory() as tempdir:
        certs_mount = scenario.Mount(
            location="/support/TLS",
            src=tempdir,
        )
        config_mount = scenario.Mount(
            location="/free5gc/config",
            src=tempdir,
        )
        container = scenario.Container(
            name="ausf",
            can_connect=True,
            mounts={"config": config_mount, "certs": certs_mount},
            layers={"ausf": Layer({"services": {"ausf": {}}})},
            service_status={"ausf": ServiceStatus.ACTIVE},
        )
        interface_tester.configure(
            charm_type=AUSFOperatorCharm,
            state_template=scenario.State(
                leader=True,
                containers=[container],
            ),
        )
        yield interface_tester
