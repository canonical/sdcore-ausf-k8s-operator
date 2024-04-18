# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, patch

from charm import AUSFOperatorCharm
from ops import ActiveStatus, BlockedStatus, ModelError, WaitingStatus, testing

from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate

TEST_POD_IP = b"1.2.3.4"


class TestCharmStatus(unittest.TestCase):
    def setUp(self):
        self.namespace = "whatever"
        self.harness = testing.Harness(AUSFOperatorCharm)
        self.harness.set_model_name(name=self.namespace)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()

    def test_given_unit_is_not_leader_when_update_status_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=False)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Scaling is not implemented for this charm"),
        )

    def test_given_unit_is_leader_but_container_is_not_ready_when_update_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for container to start")
        )

    def test_given_unit_is_leader_and_container_is_ready_but_relations_are_not_created_when_update_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container="ausf", val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status, BlockedStatus("Waiting for fiveg_nrf relation")
        )

    def test_given_unit_is_leader_and_container_is_ready_but_fiveg_nrf_relation_is_not_created_when_update_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container="ausf", val=True)
        self.harness.add_relation(relation_name="certificates", remote_app="whatever")

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status, BlockedStatus("Waiting for fiveg_nrf relation")
        )

    def test_given_unit_is_leader_and_container_is_ready_but_certificates_relation_is_not_created_when_update_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container="ausf", val=True)
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="whatever")

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status, BlockedStatus("Waiting for certificates relation")
        )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_but_nrf_data_is_not_available_when_update_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container="ausf", val=True)
        self.harness.add_relation(relation_name="fiveg_nrf", remote_app="whatever")
        self.harness.add_relation(relation_name="certificates", remote_app="whatever")

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for NRF data to be available")
        )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_but_storage_is_not_ready_when_update_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container="ausf", val=True)
        self.harness.add_relation(relation_name="certificates", remote_app="whatever-certs")
        self._create_nrf_relation_and_set_nrf_url()

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for storage to be attached")
        )

    @patch("charm.check_output")
    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_but_pod_ip_is_not_available_when_update_status_then_status_is_waiting(  # noqa: E501
        self, patched_check_output
    ):
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = b""
        self.harness.set_can_connect(container="ausf", val=True)
        self.harness.add_relation(relation_name="certificates", remote_app="whatever-certs")
        self._create_nrf_relation_and_set_nrf_url()

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for pod IP address to be available"),
        )

    @patch("charm.check_output")
    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_and_pod_ip_is_available_but_csr_is_not_stored_when_update_status_then_status_is_waiting(  # noqa: E501
        self, patched_check_output
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        self.harness.set_can_connect(container="ausf", val=True)
        self.harness.add_relation(relation_name="certificates", remote_app="whatever-certs")
        self._create_nrf_relation_and_set_nrf_url()

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for certificates to be stored"),
        )

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    @patch("ops.model.Container.get_service")
    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_and_pod_ip_is_available_and_csr_is_stored_but_ausf_service_is_not_running_when_update_status_then_status_is_waiting(  # noqa: E501
        self, patched_get_service, patched_get_assigned_certificates, patched_check_output
    ):
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        self.harness.set_can_connect(container="ausf", val=True)
        self.harness.add_relation(relation_name="certificates", remote_app="whatever-certs")
        self._create_nrf_relation_and_set_nrf_url()
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.csr").write_text(test_csr.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = test_certificate
        provider_certificate.csr = test_csr.decode()
        patched_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        patched_get_service.side_effect = ModelError()

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for AUSF service to start"),
        )

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    def test_given_unit_is_configured_correctly_when_update_status_then_status_is_active(
        self, patched_get_assigned_certificates, patched_check_output
    ):
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        self.harness.set_can_connect(container="ausf", val=True)
        self.harness.add_relation(relation_name="certificates", remote_app="whatever-certs")
        self._create_nrf_relation_and_set_nrf_url()
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.csr").write_text(test_csr.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = test_certificate
        provider_certificate.csr = test_csr.decode()
        patched_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    def _create_nrf_relation_and_set_nrf_url(self):
        fiveg_nrf_relation_id = self.harness.add_relation(
            relation_name="fiveg_nrf", remote_app="whatever-nrf"
        )
        self.harness.add_relation_unit(
            relation_id=fiveg_nrf_relation_id, remote_unit_name="whatever-nrf/0"
        )
        self.harness.update_relation_data(
            relation_id=fiveg_nrf_relation_id,
            app_or_unit="whatever-nrf",
            key_values={"url": "https://nrf-example.com:1234"},
        )
