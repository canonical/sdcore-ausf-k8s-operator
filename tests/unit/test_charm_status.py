# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import os
from unittest.mock import Mock

from fixtures import AUSFUnitTestFixtures
from ops import ActiveStatus, BlockedStatus, ModelError, WaitingStatus

from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate

CONTAINER_NAME = "ausf"
TEST_POD_IP = b"1.2.3.4"
TEST_CSR = b"whatever csr"
TEST_PRIVATE_KEY = b"whatever private key"
TEST_CERTIFICATE = "whatever certificate"
NAMESPACE = "whatever"


class TestCharmStatus(AUSFUnitTestFixtures):
    def test_given_unit_is_not_leader_when_update_status_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=False)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Scaling is not implemented for this charm"
        )

    def test_given_unit_is_leader_but_container_is_not_ready_when_update_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for container to start")

    def test_given_unit_is_leader_and_container_is_ready_but_relations_are_not_created_when_update_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for fiveg_nrf, sdcore_config, certificates relation(s)"
        )

    def test_given_unit_is_leader_and_container_is_ready_but_fiveg_nrf_relation_is_not_created_when_update_status_then_status_is_blocked(  # noqa: E501
        self, certificates_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for fiveg_nrf, sdcore_config relation(s)"
        )

    def test_given_unit_is_leader_and_container_is_ready_but_sdcore_config_relation_is_not_created_when_update_status_then_status_is_blocked(  # noqa: E501
        self, certificates_relation_id, fiveg_nrf_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for sdcore_config relation(s)"
        )

    def test_given_unit_is_leader_and_container_is_ready_but_certificates_relation_is_not_created_when_update_status_then_status_is_blocked(  # noqa: E501
        self, fiveg_nrf_relation_id, webui_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for certificates relation(s)"
        )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_but_nrf_data_is_not_available_when_update_status_then_status_is_waiting(  # noqa: E501
        self, certificates_relation_id, fiveg_nrf_relation_id, webui_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for NRF data to be available"
        )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_but_webui_data_is_not_available_when_update_status_then_status_is_waiting(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, webui_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for Webui data to be available"
        )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_but_storage_is_not_ready_when_update_status_then_status_is_waiting(  # noqa: E501
        self,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for storage to be attached"
        )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_but_pod_ip_is_not_available_when_update_status_then_status_is_waiting(  # noqa: E501
        self,
        add_storage,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        certificates_relation_id,
    ):
        self.mock_check_output.return_value = b""
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for pod IP address to be available"
        )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_and_pod_ip_is_available_but_csr_is_not_stored_when_update_status_then_status_is_waiting(  # noqa: E501
        self,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        certificates_relation_id,
        add_storage,
    ):
        self.mock_generate_csr.return_value = TEST_CSR
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.mock_check_output.return_value = TEST_POD_IP
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for certificates to be stored"
        )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_and_pod_ip_is_available_and_csr_is_stored_but_ausf_service_is_not_running_when_update_status_then_status_is_waiting(  # noqa: E501
        self,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        certificates_relation_id,
        add_storage,
    ):
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.mock_get_service.side_effect = ModelError()

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for AUSF service to start")

    def test_given_unit_is_configured_correctly_when_update_status_then_status_is_active(
        self,
        create_nrf_relation_and_set_nrf_url,
        create_webui_relation_and_set_webui_url,
        certificates_relation_id,
        add_storage,
    ):
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ActiveStatus()

    def test_given_no_workload_version_file_when_pebble_ready_then_workload_version_not_set(
        self,
    ):
        self.harness.container_pebble_ready(container_name=CONTAINER_NAME)
        self.harness.evaluate_status()
        version = self.harness.get_workload_version()
        assert version == ""

    def test_given_workload_version_file_when_pebble_ready_then_workload_version_set(
        self,
    ):
        expected_version = "1.2.3"
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        os.mkdir(f"{root}/etc")
        (root / "etc/workload-version").write_text(expected_version)
        self.harness.container_pebble_ready(container_name=CONTAINER_NAME)
        self.harness.evaluate_status()
        version = self.harness.get_workload_version()
        assert version == expected_version
