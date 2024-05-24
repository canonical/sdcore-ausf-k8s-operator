# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Generator
from unittest.mock import Mock, patch

import pytest
from charm import AUSFOperatorCharm
from ops import ActiveStatus, BlockedStatus, ModelError, WaitingStatus, testing

from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate

CONTAINER_NAME = "ausf"
TEST_POD_IP = b"1.2.3.4"
TEST_CSR = b"whatever csr"
TEST_CERTIFICATE = "whatever certificate"
NAMESPACE = "whatever"


class TestCharmStatus:
    patcher_check_output = patch("charm.check_output")
    patcher_get_assigned_certificates = patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates")  # noqa: E501
    patcher_get_service = patch("ops.model.Container.get_service")

    @pytest.fixture()
    def setup(self):
        self.mock_check_output = TestCharmStatus.patcher_check_output.start()
        self.mock_get_assigned_certificates = TestCharmStatus.patcher_get_assigned_certificates.start()  # noqa: E501
        self.mock_get_service = TestCharmStatus.patcher_get_service.start()

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def create_harness(self, setup, request):
        self.harness = testing.Harness(AUSFOperatorCharm)
        self.harness.set_model_name(name=NAMESPACE)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.teardown)

    @pytest.fixture()
    def add_storage(self):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

    @pytest.fixture()
    def create_nrf_relation_and_set_nrf_url(self, fiveg_nrf_relation_id):
        self.harness.add_relation_unit(
            relation_id=fiveg_nrf_relation_id, remote_unit_name="whatever-nrf/0"
        )
        self.harness.update_relation_data(
            relation_id=fiveg_nrf_relation_id,
            app_or_unit="whatever-nrf",
            key_values={"url": "https://nrf-example.com:1234"},
        )

    @pytest.fixture()
    def fiveg_nrf_relation_id(self) -> Generator[int, None, None]:
        yield self.harness.add_relation(
            relation_name="fiveg_nrf",
            remote_app="whatever-nrf",
        )

    @pytest.fixture()
    def certificates_relation_id(self) -> Generator[int, None, None]:
        yield self.harness.add_relation(
            relation_name="certificates",
            remote_app="whatever",
        )

    def test_given_unit_is_not_leader_when_update_status_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=False)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Scaling is not implemented for this charm")  # noqa: E501

    def test_given_unit_is_leader_but_container_is_not_ready_when_update_status_then_status_is_waiting(self):  # noqa: E501
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for container to start")

    def test_given_unit_is_leader_and_container_is_ready_but_relations_are_not_created_when_update_status_then_status_is_blocked(self):  # noqa: E501
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation")

    def test_given_unit_is_leader_and_container_is_ready_but_fiveg_nrf_relation_is_not_created_when_update_status_then_status_is_blocked(  # noqa: E501
        self, certificates_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation")

    def test_given_unit_is_leader_and_container_is_ready_but_certificates_relation_is_not_created_when_update_status_then_status_is_blocked(  # noqa: E501
        self, fiveg_nrf_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for certificates relation")

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_but_nrf_data_is_not_available_when_update_status_then_status_is_waiting(  # noqa: E501
        self, certificates_relation_id, fiveg_nrf_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for NRF data to be available")  # noqa: E501

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_but_storage_is_not_ready_when_update_status_then_status_is_waiting(  # noqa: E501
        self, create_nrf_relation_and_set_nrf_url, certificates_relation_id
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for storage to be attached")  # noqa: E501

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_but_pod_ip_is_not_available_when_update_status_then_status_is_waiting(  # noqa: E501
        self, create_nrf_relation_and_set_nrf_url, certificates_relation_id
    ):
        self.harness.add_storage(storage_name="config", attach=True)
        self.mock_check_output.return_value = b""
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for pod IP address to be available")  # noqa: E501

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_and_pod_ip_is_available_but_csr_is_not_stored_when_update_status_then_status_is_waiting(  # noqa: E501
        self, create_nrf_relation_and_set_nrf_url, certificates_relation_id, add_storage
    ):
        self.mock_check_output.return_value = TEST_POD_IP
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for certificates to be stored")  # noqa: E501

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_and_pod_ip_is_available_and_csr_is_stored_but_ausf_service_is_not_running_when_update_status_then_status_is_waiting(  # noqa: E501
        self, create_nrf_relation_and_set_nrf_url, certificates_relation_id, add_storage
    ):
        self.mock_check_output.return_value = TEST_POD_IP
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
        self, create_nrf_relation_and_set_nrf_url, certificates_relation_id, add_storage
    ):
        self.mock_check_output.return_value = TEST_POD_IP
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
