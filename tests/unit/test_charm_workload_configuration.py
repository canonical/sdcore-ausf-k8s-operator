# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate
from tests.unit.fixtures import AUSFUnitTestFixtures

CONTAINER_NAME = "ausf"
TEST_POD_IP = b"1.2.3.4"
TEST_PRIVATE_KEY = b"whatever private key"
TEST_CSR = b"whatever csr"
TEST_CERTIFICATE = "whatever certificate"
NAMESPACE = "whatever"


class TestCharmWorkloadConfiguration(AUSFUnitTestFixtures):
    def test_given_charm_workload_is_ready_to_configure_and_private_key_is_not_stored_when_update_status_then_private_key_is_generated_and_stored_in_the_container(  # noqa: E501
        self,
        certificates_relation_id,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        add_storage,
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
        self,
        certificates_relation_id,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        add_storage,
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
        self,
        certificates_relation_id,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        add_storage,
    ):
        self.harness.set_can_connect(container=CONTAINER_NAME, val=True)
        self.mock_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root(CONTAINER_NAME)
        (root / "support/TLS/ausf.key").write_text(TEST_PRIVATE_KEY.decode())
        self.mock_generate_csr.return_value = TEST_CSR

        self.harness.charm.on.update_status.emit()

        self.mock_request_certificate_creation.assert_called_once()

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_needs_updating_when_update_status_then_new_provider_certificate_is_pushed_to_the_container(  # noqa: E501
        self,
        certificates_relation_id,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        add_storage,
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
        self,
        certificates_relation_id,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        add_storage,
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
        self,
        certificates_relation_id,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        add_storage,
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
        self,
        certificates_relation_id,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        add_storage,
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
        self,
        certificates_relation_id,
        create_nrf_relation_and_set_nrf_url,
        create_nms_relation_and_set_webui_url,
        add_storage,
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
