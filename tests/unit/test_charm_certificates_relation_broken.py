# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile
from pathlib import Path

from ops import testing

from tests.unit.certificates_helpers import (
    example_cert_and_key,
)
from tests.unit.fixtures import AUSFUnitTestFixtures

CONTAINER_NAME = "ausf"
TEST_POD_IP = b"1.2.3.4"
TEST_NRF_URL = "https://nrf-example.com:1234"


class TestCharmCertificateRelationBroken(AUSFUnitTestFixtures):
    def test_given_charm_is_in_active_state_when_certificates_relation_broken_then_certificate_and_private_key_are_removed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg-nrf",
                remote_app_data={"url": TEST_NRF_URL},
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore-config",
                remote_app_data={"webui_url": "whatever"},
            )
            certs_mount = testing.Mount(
                location="/sdcore/certs",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/sdcore/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key
            with open(f"{tempdir}/ausf.key", "w") as f:
                f.write(str(private_key))
            with open(f"{tempdir}/ausf.pem", "w") as f:
                f.write(str(provider_certificate.certificate))
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation, nms_relation},
                leader=True,
            )

            self.ctx.run(self.ctx.on.relation_broken(certificates_relation), state_in)

            assert not Path(f"{tempdir}/ausf.key").exists()
            assert not Path(f"{tempdir}/ausf.pem").exists()
