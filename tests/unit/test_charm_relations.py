# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from pathlib import Path
from typing import Tuple
from unittest.mock import Mock, patch

from ops import ActiveStatus, testing

from charm import AUSFOperatorCharm
from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate

TEST_NRF_URL = "https://nrf-example.com:1234"
TEST_POD_IP = b"1.2.3.4"


class TestCharmRelations(unittest.TestCase):
    def setUp(self):
        self.namespace = "whatever"
        self.harness = testing.Harness(AUSFOperatorCharm)
        self.harness.set_model_name(name=self.namespace)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    def test_given_charm_is_in_active_state_when_certificates_relation_broken_then_certificate_csr_and_private_key_are_removed(  # noqa: E501
        self, patched_get_assigned_certificates, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        certificates_relation_id, _ = self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.csr").write_text(test_csr.decode())
        (root / "support/TLS/ausf.key").write_text(test_private_key.decode())
        (root / "support/TLS/ausf.pem").write_text(test_certificate)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = test_certificate
        provider_certificate.csr = test_csr.decode()
        patched_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/ausf.key").read_text()
        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/ausf.pem").read_text()
        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/ausf.csr").read_text()

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation",  # noqa: E501
    )
    def test_given_charm_is_in_active_state_when_certificate_expiring_then_new_certificate_is_requested(  # noqa: E501
        self,
        patched_request_certificate_creation,
        patched_generate_csr,
        patched_get_assigned_certificates,
        patched_check_output,
    ):
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        patched_generate_csr.return_value = test_csr
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = test_certificate
        provider_certificate.csr = test_csr.decode()
        patched_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

        event = Mock()
        event.certificate = test_certificate
        self.harness.charm._on_certificate_expiring(event=event)

        patched_request_certificate_creation.assert_called_with(
            certificate_signing_request=test_csr
        )

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    def test_given_charm_is_in_active_state_when_nrf_available_then_ausf_config_is_updated(
        self, patched_get_assigned_certificates, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        _, fiveg_nrf_relation_id = self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.csr").write_text(test_csr.decode())
        (root / "support/TLS/ausf.key").write_text(test_private_key.decode())
        (root / "support/TLS/ausf.pem").write_text(test_certificate)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = test_certificate
        provider_certificate.csr = test_csr.decode()
        patched_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()
        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

        new_nrf_url = "https://new-nrf-url.com:1234"
        self.harness.update_relation_data(
            relation_id=fiveg_nrf_relation_id,
            app_or_unit="whatever-nrf",
            key_values={"url": new_nrf_url},
        )

        expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
        with open(expected_config_file_path, "r") as expected_config_file:
            expected_config = expected_config_file.read()

            self.assertEqual(
                (root / "free5gc/config/ausfcfg.conf").read_text(),
                expected_config.replace(TEST_NRF_URL, new_nrf_url),
            )

    def _create_charm_relations_and_relation_data(self) -> Tuple[int, int]:
        certificates_relation_id = self.harness.add_relation(
            relation_name="certificates", remote_app="whatever-certs"
        )
        fiveg_nrf_relation_id = self.harness.add_relation(
            relation_name="fiveg_nrf", remote_app="whatever-nrf"
        )
        self.harness.add_relation_unit(
            relation_id=fiveg_nrf_relation_id, remote_unit_name="whatever-nrf/0"
        )
        self.harness.update_relation_data(
            relation_id=fiveg_nrf_relation_id,
            app_or_unit="whatever-nrf",
            key_values={"url": TEST_NRF_URL},
        )
        return certificates_relation_id, fiveg_nrf_relation_id
