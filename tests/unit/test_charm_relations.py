# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path
from typing import Generator, Tuple
from unittest.mock import Mock, patch

import pytest
from charm import AUSFOperatorCharm
from ops import ActiveStatus, testing

from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate

CONTAINER_NAME = "ausf"
TEST_POD_IP = b"1.2.3.4"
TEST_PRIVATE_KEY = b"whatever private key"
TEST_CSR = b"whatever csr"
TEST_CERTIFICATE = "whatever certificate"
NAMESPACE = "whatever"
TEST_NRF_URL = "https://nrf-example.com:1234"


class TestCharmRelations:
    patcher_check_output = patch("charm.check_output")
    patcher_generate_csr = patch("charm.generate_csr")
    patcher_get_assigned_certificates = patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates")  # noqa: E501
    patcher_request_certificate_creation = patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation")  # noqa: E501

    @pytest.fixture()
    def setup(self):
        self.mock_check_output = TestCharmRelations.patcher_check_output.start()
        self.mock_generate_csr = TestCharmRelations.patcher_generate_csr.start()
        self.mock_get_assigned_certificates = TestCharmRelations.patcher_get_assigned_certificates.start()  # noqa: E501
        self.mock_request_certificate_creation = TestCharmRelations.patcher_request_certificate_creation.start()  # noqa: E501

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
    def create_charm_relations_and_relation_data(self) -> Generator[Tuple[int, int], None, None]:
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
        yield certificates_relation_id, fiveg_nrf_relation_id

    def test_given_charm_is_in_active_state_when_certificates_relation_broken_then_certificate_csr_and_private_key_are_removed(  # noqa: E501
        self, create_charm_relations_and_relation_data, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        (root / "support/TLS/ausf.pem").write_text(TEST_CERTIFICATE)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus()

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        with pytest.raises(FileNotFoundError):
            (root / "support/TLS/ausf.key").read_text()
        with pytest.raises(FileNotFoundError):
            (root / "support/TLS/ausf.pem").read_text()
        with pytest.raises(FileNotFoundError):
            (root / "support/TLS/ausf.csr").read_text()

    def test_given_charm_is_in_active_state_when_certificate_expiring_then_new_certificate_is_requested(  # noqa E501
        self, create_charm_relations_and_relation_data, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_csr.return_value = TEST_CSR
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus()

        event = Mock()
        event.certificate = TEST_CERTIFICATE
        self.harness.charm._on_certificate_expiring(event=event)

        self.mock_request_certificate_creation.assert_called_with(
            certificate_signing_request=TEST_CSR
        )

    def test_given_charm_is_in_active_state_when_nrf_available_then_ausf_config_is_updated(
        self, create_charm_relations_and_relation_data, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        (root / "support/TLS/ausf.pem").write_text(TEST_CERTIFICATE)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == ActiveStatus()

        new_nrf_url = "https://new-nrf-url.com:1234"
        self.harness.update_relation_data(
            relation_id=create_charm_relations_and_relation_data[1],
            app_or_unit="whatever-nrf",
            key_values={"url": new_nrf_url},
        )

        expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
        with open(expected_config_file_path, "r") as expected_config_file:
            expected_config = expected_config_file.read()

            assert (root / "free5gc/config/ausfcfg.conf").read_text() == expected_config.replace(TEST_NRF_URL, new_nrf_url)  # noqa E501
