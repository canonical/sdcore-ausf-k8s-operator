# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, call, patch

from charm import AUSFOperatorCharm
from ops import testing

from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate

TEST_POD_IP = b"1.2.3.4"


class TestCharmWorkloadConfiguration(unittest.TestCase):
    def setUp(self):
        self.namespace = "whatever"
        self.harness = testing.Harness(AUSFOperatorCharm)
        self.harness.set_model_name(name=self.namespace)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()

    @patch("charm.check_output")
    @patch("charm.generate_private_key")
    @patch("ops.model.Container.push")
    def test_given_charm_workload_is_ready_to_configure_and_private_key_is_not_stored_when_update_status_then_private_key_is_generated_and_stored_in_the_container(  # noqa: E501
        self, patched_push, patched_generate_private_key, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        patched_generate_private_key.return_value = test_private_key
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.csr").write_text(test_csr.decode())

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        patched_generate_private_key.assert_called_once()
        patched_push.assert_called_once_with(
            path="/support/TLS/ausf.key", source=test_private_key.decode()
        )

    @patch("charm.check_output")
    @patch("charm.generate_csr")
    @patch("ops.model.Container.push")
    @patch("ops.model.Container.pull")
    def test_given_charm_workload_is_ready_to_configure_and_private_key_is_stored_but_csr_is_not_stored_when_update_status_then_csr_is_generated_and_stored_in_the_container(  # noqa: E501
        self, patched_pull, patched_push, patched_generate_csr, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.key").write_text(test_private_key.decode())
        patched_generate_csr.return_value = test_csr
        patched_pull.side_effect = [
            StringIO(test_private_key.decode()), StringIO(test_csr.decode())
        ]

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        patched_generate_csr.assert_called_once_with(
            private_key=test_private_key,
            subject="ausf.sdcore",
            sans_dns=["ausf.sdcore"],
        )
        patched_push.assert_called_once_with(
            path="/support/TLS/ausf.csr", source=test_csr.decode()
        )

    @patch("charm.check_output")
    @patch("charm.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"  # noqa: E501
    )
    def test_given_charm_workload_is_ready_to_configure_and_private_key_is_stored_but_csr_is_not_stored_when_update_status_then_new_certificate_is_requested(  # noqa: E501
        self, patched_request_certificate_creation, patched_generate_csr, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.key").write_text(test_private_key.decode())
        patched_generate_csr.return_value = test_csr

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        patched_request_certificate_creation.assert_called_once()

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    @patch("ops.model.Container.push")
    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_needs_updating_when_update_status_then_new_provider_certificate_is_pushed_to_the_container(  # noqa: E501
        self, patched_push, patched_get_assigned_certificates, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.csr").write_text(test_csr.decode())
        (root / "support/TLS/ausf.key").write_text(test_private_key.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = test_certificate
        provider_certificate.csr = test_csr.decode()
        patched_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            patched_push.mock_calls[0], call(path="/support/TLS/ausf.pem", source=test_certificate)
        )

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    @patch("ops.model.Container.push")
    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_is_up_to_date_when_update_status_then_new_provider_certificate_is_not_pushed_to_the_container(  # noqa: E501
        self, patched_push, patched_get_assigned_certificates, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
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

        self.assertFalse(
            call(path="/support/TLS/ausf.pem", source=test_certificate) in patched_push.mock_calls
        )

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    @patch("ops.model.Container.push")
    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_is_up_to_date_and_workload_config_needs_updating_when_update_status_then_new_workload_config_is_pushed_to_the_container(  # noqa: E501
        self, patched_push, patched_get_assigned_certificates, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
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

        expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
        with open(expected_config_file_path, "r") as expected_config_file:
            expected_config = expected_config_file.read()
            patched_push.assert_called_once_with(
                path="/free5gc/config/ausfcfg.conf", source=expected_config, make_dirs=True
            )

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    @patch("ops.model.Container.push")
    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_is_up_to_date_and_workload_config_is_up_to_date_when_update_status_then_new_workload_config_is_not_pushed_to_the_container(  # noqa: E501
        self, patched_push, patched_get_assigned_certificates, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.csr").write_text(test_csr.decode())
        (root / "support/TLS/ausf.key").write_text(test_private_key.decode())
        (root / "support/TLS/ausf.pem").write_text(test_certificate)
        expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
        with open(expected_config_file_path, "r") as expected_config_file:
            expected_config = expected_config_file.read()
            (root / "free5gc/config/ausfcfg.conf").write_text(expected_config)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = test_certificate
        provider_certificate.csr = test_csr.decode()
        patched_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        patched_push.assert_not_called()

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_and_workload_config_are_stored_when_update_status_then_pebble_layer_is_created(  # noqa: E501
        self, patched_get_assigned_certificates, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.csr").write_text(test_csr.decode())
        (root / "support/TLS/ausf.key").write_text(test_private_key.decode())
        (root / "support/TLS/ausf.pem").write_text(test_certificate)
        expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
        with open(expected_config_file_path, "r") as expected_config_file:
            expected_config = expected_config_file.read()
            (root / "free5gc/config/ausfcfg.conf").write_text(expected_config)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = test_certificate
        provider_certificate.csr = test_csr.decode()
        patched_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        expected_pebble_layer = {
            "services": {
                "ausf": {
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
        actual_pebble_plan = self.harness.get_container_pebble_plan("ausf").to_dict()
        self.assertEqual(expected_pebble_layer, actual_pebble_plan)

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    @patch("ops.model.Container.restart")
    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_has_changed_when_update_status_then_workload_service_is_restarted(  # noqa: E501
        self, patched_restart, patched_get_assigned_certificates, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.csr").write_text(test_csr.decode())
        (root / "support/TLS/ausf.key").write_text(test_private_key.decode())
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = test_certificate
        provider_certificate.csr = test_csr.decode()
        patched_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        patched_restart.assert_called_once()

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    @patch("ops.model.Container.restart")
    def test_given_charm_workload_is_ready_to_configure_and_workload_config_has_changed_when_update_status_then_workload_service_is_restarted(  # noqa: E501
        self, patched_restart, patched_get_assigned_certificates, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
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

        patched_restart.assert_called_once()

    @patch("charm.check_output")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates",  # noqa: E501
    )
    @patch("ops.model.Container.restart")
    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_hasnt_changed_and_workload_config_hasnt_changed_when_update_status_then_workload_service_is_not_restarted(  # noqa: E501
        self, patched_restart, patched_get_assigned_certificates, patched_check_output
    ):
        test_private_key = b"whatever private key"
        test_csr = b"whatever csr"
        test_certificate = "whatever certificate"
        self.harness.set_can_connect(container="ausf", val=True)
        self._create_charm_relations_and_relation_data()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patched_check_output.return_value = TEST_POD_IP
        root = self.harness.get_filesystem_root("ausf")
        (root / "support/TLS/ausf.csr").write_text(test_csr.decode())
        (root / "support/TLS/ausf.key").write_text(test_private_key.decode())
        (root / "support/TLS/ausf.pem").write_text(test_certificate)
        expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
        with open(expected_config_file_path, "r") as expected_config_file:
            expected_config = expected_config_file.read()
            (root / "free5gc/config/ausfcfg.conf").write_text(expected_config)
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = test_certificate
        provider_certificate.csr = test_csr.decode()
        patched_get_assigned_certificates.return_value = [
            provider_certificate,
        ]

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        patched_restart.assert_not_called()

    def _create_charm_relations_and_relation_data(self):
        self.harness.add_relation(relation_name="certificates", remote_app="whatever-certs")
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
