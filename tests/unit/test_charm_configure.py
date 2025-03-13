# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import tempfile
from pathlib import Path

from ops import testing
from ops.pebble import Layer

from tests.unit.certificates_helpers import (
    example_cert_and_key,
)
from tests.unit.fixtures import AUSFUnitTestFixtures

CONTAINER_NAME = "ausf"
TEST_POD_IP = b"1.2.3.4"
TEST_NRF_URL = "https://nrf-example.com:1234"
TEST_WEBUI_URL = "some-webui:7890"


class TestCharmConfigure(AUSFUnitTestFixtures):
    def test_given_charm_workload_is_ready_to_configure_and_private_key_is_not_stored_when_update_status_then_private_key_is_stored_in_the_container(  # noqa: E501
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
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation, nms_relation},
                leader=True,
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            self.ctx.run(self.ctx.on.update_status(), state_in)

            with open(f"{tempdir}/ausf.key", "r") as f:
                assert f.read() == str(private_key)
            with open(f"{tempdir}/ausf.pem", "r") as f:
                assert f.read() == str(provider_certificate.certificate)

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_needs_updating_when_update_status_then_new_provider_certificate_is_pushed_to_the_container(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            initial_certificate, initial_private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
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
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation, nms_relation},
                leader=True,
            )
            self.mock_check_output.return_value = TEST_POD_IP
            with open(f"{tempdir}/ausf.key", "w") as f:
                f.write(str(initial_private_key))
            with open(f"{tempdir}/ausf.pem", "w") as f:
                f.write(str(initial_certificate.certificate))
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            self.ctx.run(self.ctx.on.update_status(), state_in)

            with open(f"{tempdir}/ausf.key", "r") as f:
                assert f.read() == str(private_key)
            with open(f"{tempdir}/ausf.pem", "r") as f:
                assert f.read() == str(provider_certificate.certificate)

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_is_up_to_date_when_update_status_then_new_provider_certificate_is_not_pushed_to_the_container(  # noqa: E501
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
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation, nms_relation},
                leader=True,
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            with open(f"{tempdir}/ausf.key", "w") as f:
                f.write(str(private_key))
            with open(f"{tempdir}/ausf.pem", "w") as f:
                f.write(str(provider_certificate.certificate))

            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key
            certificate_file_creation_time = Path(f"{tempdir}/ausf.pem").lstat().st_mtime

            self.ctx.run(self.ctx.on.update_status(), state_in)

            with open(f"{tempdir}/ausf.key", "r") as f:
                assert f.read() == str(private_key)
            with open(f"{tempdir}/ausf.pem", "r") as f:
                assert f.read() == str(provider_certificate.certificate)
            assert Path(f"{tempdir}/ausf.pem").lstat().st_mtime == certificate_file_creation_time

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_is_up_to_date_and_workload_config_needs_updating_when_update_status_then_new_workload_config_is_pushed_to_the_container(  # noqa: E501
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
                remote_app_data={"webui_url": TEST_WEBUI_URL},
            )
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation, nms_relation},
                leader=True,
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

            self.ctx.run(self.ctx.on.update_status(), state_in)

            expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
            with open(expected_config_file_path, "r") as expected_config_file:
                expected_config = expected_config_file.read()

            with open(f"{tempdir}/ausfcfg.conf", "r") as f:
                assert f.read() == expected_config

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_is_up_to_date_and_workload_config_is_up_to_date_when_update_status_then_new_workload_config_is_not_pushed_to_the_container(  # noqa: E501
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
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation},
                leader=True,
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            with open(f"{tempdir}/ausf.key", "w") as f:
                f.write(str(private_key))
            with open(f"{tempdir}/ausf.pem", "w") as f:
                f.write(str(provider_certificate.certificate))
            expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
            with open(expected_config_file_path, "r") as expected_config_file:
                expected_config = expected_config_file.read()
            with open(f"{tempdir}/ausfcfg.conf", "w") as f:
                f.write(expected_config)
            config_file_creation_time = Path(f"{tempdir}/ausfcfg.conf").lstat().st_mtime
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            self.ctx.run(self.ctx.on.update_status(), state_in)

            assert Path(f"{tempdir}/ausfcfg.conf").lstat().st_mtime == config_file_creation_time

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_and_workload_config_are_stored_when_update_status_then_pebble_layer_is_created(  # noqa: E501
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
                remote_app_data={"webui_url": TEST_WEBUI_URL},
            )
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation, nms_relation},
                leader=True,
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            with open(f"{tempdir}/ausf.key", "w") as f:
                f.write(str(private_key))
            with open(f"{tempdir}/ausf.pem", "w") as f:
                f.write(str(provider_certificate.certificate))
            expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
            with open(expected_config_file_path, "r") as expected_config_file:
                expected_config = expected_config_file.read()
            with open(f"{tempdir}/ausfcfg.conf", "w") as f:
                f.write(expected_config)

            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            state_out = self.ctx.run(self.ctx.on.update_status(), state_in)

            assert state_out.get_container(CONTAINER_NAME).layers["ausf"] == Layer(
                {
                    "services": {
                        "ausf": {
                            "startup": "enabled",
                            "override": "replace",
                            "command": "/bin/ausf --cfg /free5gc/config/ausfcfg.conf",
                            "environment": {
                                "POD_IP": "1.2.3.4",
                                "MANAGED_BY_CONFIG_POD": "true",
                            },
                        }
                    }
                }
            )

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_has_changed_when_update_status_then_workload_service_is_restarted(  # noqa: E501
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
                remote_app_data={"webui_url": TEST_WEBUI_URL},
            )
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation, nms_relation},
                leader=True,
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            self.ctx.run(self.ctx.on.update_status(), state_in)

            self.mock_restart.assert_called_once()

    def test_given_charm_workload_is_ready_to_configure_and_workload_config_has_changed_when_update_status_then_workload_service_is_restarted(  # noqa: E501
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
                remote_app_data={"webui_url": TEST_WEBUI_URL},
            )
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation, nms_relation},
                leader=True,
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            with open(f"{tempdir}/ausf.key", "w") as f:
                f.write(str(private_key))
            with open(f"{tempdir}/ausf.pem", "w") as f:
                f.write(str(provider_certificate.certificate))
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            self.ctx.run(self.ctx.on.update_status(), state_in)

            self.mock_restart.assert_called_once()

    def test_given_charm_workload_is_ready_to_configure_and_provider_certificate_hasnt_changed_and_workload_config_hasnt_changed_when_update_status_then_workload_service_is_not_restarted(  # noqa: E501
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
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation},
                leader=True,
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            with open(f"{tempdir}/ausf.key", "w") as f:
                f.write(str(private_key))
            with open(f"{tempdir}/ausf.pem", "w") as f:
                f.write(str(provider_certificate.certificate))

            expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
            with open(expected_config_file_path, "r") as expected_config_file:
                expected_config = expected_config_file.read()
            with open(f"{tempdir}/ausfcfg.conf", "w") as f:
                f.write(expected_config)
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            self.ctx.run(self.ctx.on.update_status(), state_in)

            self.mock_restart.assert_not_called()

    def test_given_charm_is_configured_when_update_status_then_ausf_config_is_updated(
        self,
    ):
        expected_nrf_url = "https://new-nrf-url:1234"
        with tempfile.TemporaryDirectory() as tempdir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg-nrf",
                remote_app_data={"url": expected_nrf_url},
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore-config",
                remote_app_data={"webui_url": TEST_WEBUI_URL},
            )
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation, nms_relation},
                leader=True,
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            with open(f"{tempdir}/ausf.key", "w") as f:
                f.write(str(private_key))
            with open(f"{tempdir}/ausf.pem", "w") as f:
                f.write(str(provider_certificate.certificate))
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            self.ctx.run(self.ctx.on.update_status(), state_in)

            expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
            with open(expected_config_file_path, "r") as expected_config_file:
                expected_config = expected_config_file.read()

            with open(f"{tempdir}/ausfcfg.conf", "r") as f:
                assert f.read() == expected_config.replace(TEST_NRF_URL, expected_nrf_url)

    def test_given_charm_is_in_active_state_when_webui_url_available_then_ausf_config_is_updated(
        self,
    ):
        expected_webui_url = "https://new-webui-url"
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
                remote_app_data={"webui_url": expected_webui_url},
            )
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/free5gc/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"certs": certs_mount, "config": config_mount},
            )
            state_in = testing.State(
                containers={container},
                relations={certificates_relation, nrf_relation, nms_relation},
                leader=True,
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            with open(f"{tempdir}/ausf.key", "w") as f:
                f.write(str(private_key))
            with open(f"{tempdir}/ausf.pem", "w") as f:
                f.write(str(provider_certificate.certificate))
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            self.ctx.run(self.ctx.on.update_status(), state_in)

            expected_config_file_path = Path(__file__).parent / "expected_config" / "config.conf"
            with open(expected_config_file_path, "r") as expected_config_file:
                expected_config = expected_config_file.read()

            with open(f"{tempdir}/ausfcfg.conf", "r") as f:
                assert f.read() == expected_config.replace(TEST_WEBUI_URL, expected_webui_url)
