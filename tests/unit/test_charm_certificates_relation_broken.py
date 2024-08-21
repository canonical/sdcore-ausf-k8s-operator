# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest
import scenario

from charm import AUSFOperatorCharm
from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate
from tests.unit.fixtures import AUSFUnitTestFixtures

CONTAINER_NAME = "ausf"
TEST_POD_IP = b"1.2.3.4"
TEST_PRIVATE_KEY = b"whatever private key"
TEST_CSR = b"whatever csr"
TEST_CERTIFICATE = "whatever certificate"
TEST_NRF_URL = "https://nrf-example.com:1234"


class TestCharmCertificateRelationBroken(AUSFUnitTestFixtures):
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=AUSFOperatorCharm,
        )

    def test_given_charm_is_in_active_state_when_certificates_relation_broken_then_certificate_csr_and_private_key_are_removed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = scenario.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg-nrf",
                remote_app_data={"url": TEST_NRF_URL},
            )
            nms_relation = scenario.Relation(
                endpoint="sdcore_config",
                interface="sdcore-config",
                remote_app_data={"webui_url": "whatever"},
            )
            certs_mount = scenario.Mount(
                location="/support/TLS",
                src=tempdir,
            )
            config_mount = scenario.Mount(
                location="/free5gc/config",
                src=tempdir,
            )
            container = scenario.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )

            self.mock_check_output.return_value = TEST_POD_IP
            with open(f"{tempdir}/ausf.csr", "w") as f:
                f.write(TEST_CSR.decode())
            with open(f"{tempdir}/ausf.key", "w") as f:
                f.write(TEST_PRIVATE_KEY.decode())
            with open(f"{tempdir}/ausf.pem", "w") as f:
                f.write(TEST_CERTIFICATE)
            provider_certificate = Mock(ProviderCertificate)
            provider_certificate.certificate = TEST_CERTIFICATE
            provider_certificate.csr = TEST_CSR.decode()
            self.mock_get_assigned_certificates.return_value = [
                provider_certificate,
            ]
            state_in = scenario.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
            )

            self.ctx.run(certificates_relation.broken_event, state_in)

            assert not Path(f"{tempdir}/ausf.csr").exists()
            assert not Path(f"{tempdir}/ausf.key").exists()
            assert not Path(f"{tempdir}/ausf.pem").exists()
