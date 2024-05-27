# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from io import StringIO
from pathlib import Path
from typing import Generator
from unittest.mock import Mock, patch

import pytest
from charm import AUSFOperatorCharm
from ops import testing

from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate

CONTAINER_NAME = "ausf"
TEST_POD_IP = b"1.2.3.4"
TEST_PRIVATE_KEY = b"whatever private key"
TEST_CSR = b"whatever csr"
TEST_CERTIFICATE = "whatever certificate"
NAMESPACE = "whatever"


class TestCharmWorkloadConfiguration:
    patcher_check_output = patch("charm.check_output")
    patcher_generate_csr = patch("charm.generate_csr")
    patcher_generate_private_key = patch("charm.generate_private_key")
    patcher_get_assigned_certificates = patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates")  # noqa: E501
    patcher_request_certificate_creation = patch("charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation")  # noqa: E501
    patcher_restart = patch("ops.model.Container.restart")

    @pytest.fixture()
    def setup(self):
        self.mock_check_output = TestCharmWorkloadConfiguration.patcher_check_output.start()
        self.mock_generate_csr = TestCharmWorkloadConfiguration.patcher_generate_csr.start()
        self.mock_generate_private_key = TestCharmWorkloadConfiguration.patcher_generate_private_key.start()  # noqa: E501
        self.mock_get_assigned_certificates = TestCharmWorkloadConfiguration.patcher_get_assigned_certificates.start()  # noqa: E501
        self.mock_request_certificate_creation = TestCharmWorkloadConfiguration.patcher_request_certificate_creation.start()  # noqa: E501
        self.mock_restart = TestCharmWorkloadConfiguration.patcher_restart.start()

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

    def test_given_charm_workload_is_ready_to_configure_and_private_key_is_not_stored_when_update_status_then_private_key_is_generated_and_stored_in_the_container(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())

        self.harness.charm.on.update_status.emit()

        self.mock_generate_private_key.assert_called_once()
        assert (root / "support/TLS/ausf.key").read_text() == TEST_PRIVATE_KEY.decode()

    def test_given_charm_workload_is_ready_to_configure_and_private_key_is_stored_but_csr_is_not_stored_when_update_status_then_csr_is_generated_and_stored_in_the_container(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        self.mock_generate_csr.return_value = TEST_CSR
        mock_pull = patch("ops.model.Container.pull").start()
        mock_pull.return_value = StringIO(TEST_PRIVATE_KEY.decode())

        self.harness.charm.on.update_status.emit()

        self.mock_generate_csr.assert_called_once_with(
            private_key=TEST_PRIVATE_KEY,
            subject="ausf.sdcore",
            sans_dns=["ausf.sdcore"],
        )
        assert (root / "support/TLS/ausf.csr").read_text() == TEST_CSR.decode()

    def test_given_charm_workload_is_ready_to_configure_and_private_key_is_stored_but_csr_is_not_stored_when_update_status_then_new_certificate_is_requested(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        self.mock_generate_csr.return_value = TEST_CSR

        self.harness.charm.on.update_status.emit()

        self.mock_request_certificate_creation.assert_called_once()

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_needs_updating_when_update_status_then_new_provider_certificate_is_pushed_to_the_container(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()

        assert (root / "support/TLS/ausf.pem").read_text() == TEST_CERTIFICATE

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_is_up_to_date_when_update_status_then_new_provider_certificate_is_not_pushed_to_the_container(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        (root / "support/TLS/ausf.pem").write_text(TEST_CERTIFICATE)
        certificate_file_creation_time = (root / "support/TLS/ausf.pem").lstat().st_mtime
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()

        assert (root / "support/TLS/ausf.pem").lstat().st_mtime == certificate_file_creation_time

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_is_up_to_date_and_workload_config_needs_updating_when_update_status_then_new_workload_config_is_pushed_to_the_container(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
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

        expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
        with open(expected_config_file_path, "r") as expected_config_file:
            expected_config = expected_config_file.read()
            assert (root / "free5gc/config/ausfcfg.conf").read_text() == expected_config

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_is_up_to_date_and_workload_config_is_up_to_date_when_update_status_then_new_workload_config_is_not_pushed_to_the_container(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        (root / "support/TLS/ausf.pem").write_text(TEST_CERTIFICATE)
        expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
        with open(expected_config_file_path, "r") as expected_config_file:
            expected_config = expected_config_file.read()
            (root / "free5gc/config/ausfcfg.conf").write_text(expected_config)
        config_file_creation_time = (root / "free5gc/config/ausfcfg.conf").lstat().st_mtime
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()

        assert (root / "free5gc/config/ausfcfg.conf").lstat().st_mtime == config_file_creation_time

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_and_workload_config_are_stored_when_update_status_then_pebble_layer_is_created(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        (root / "support/TLS/ausf.pem").write_text(TEST_CERTIFICATE)
        expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
        with open(expected_config_file_path, "r") as expected_config_file:
            expected_config = expected_config_file.read()
            (root / "free5gc/config/ausfcfg.conf").write_text(expected_config)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()

        expected_pebble_layer = {
            "services": {
                CONTAINER_NAME: {
                    "override": "replace",
                    "startup": "enabled",
                    "command": "/bin/ausf --ausfcfg /free5gc/config/ausfcfg.conf",
                    "environment": {
                        "GOTRACEBACK": "crash",
                        "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
                        "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
                        "GRPC_TRACE": "all",
                        "GRPC_VERBOSITY": "DEBUG",
                        "POD_IP": TEST_POD_IP.decode(),
                        "MANAGED_BY_CONFIG_POD": "true",
                    },
                },
            }
        }
        actual_pebble_plan = self.harness.get_container_pebble_plan(CONTAINER_NAME).to_dict()
        assert expected_pebble_layer == actual_pebble_plan

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_has_changed_when_update_status_then_workload_service_is_restarted(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()

        self.mock_restart.assert_called_once()

    def test_given_charm_workload_is_ready_to_configure_and_workload_config_has_changed_when_update_status_then_workload_service_is_restarted(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
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

        self.mock_restart.assert_called_once()

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_hasnt_changed_and_workload_config_hasnt_changed_when_update_status_then_workload_service_is_not_restarted(  # noqa: E501
        self, certificates_relation_id, create_nrf_relation_and_set_nrf_url, add_storage
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.csr").write_text(TEST_CSR.decode())
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        (root / "support/TLS/ausf.pem").write_text(TEST_CERTIFICATE)
        expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
        with open(expected_config_file_path, "r") as expected_config_file:
            expected_config = expected_config_file.read()
            (root / "free5gc/config/ausfcfg.conf").write_text(expected_config)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = TEST_CERTIFICATE
        provider_certificate.csr = TEST_CSR.decode()
        self.mock_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()

        self.mock_restart.assert_not_called()
