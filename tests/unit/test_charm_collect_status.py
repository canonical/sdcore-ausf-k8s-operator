# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile
from unittest.mock import Mock

import scenario
from ops import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer, ServiceStatus

from lib.charms.tls_certificates_interface.v3.tls_certificates import ProviderCertificate
from tests.unit.fixtures import AUSFUnitTestFixtures

CONTAINER_NAME = "ausf"
TEST_POD_IP = b"1.2.3.4"
TEST_CSR = b"whatever csr"
TEST_PRIVATE_KEY = b"whatever private key"
TEST_CERTIFICATE = "whatever certificate"
TEST_NRF_URL = "https://nrf-example.com:1234"


class TestCharmCollectStatus(AUSFUnitTestFixtures):
    def test_given_unit_is_not_leader_when_collect_unit_status_then_status_is_blocked(self):
        container = scenario.Container(
            name=CONTAINER_NAME,
        )
        state_in = scenario.State(
            containers=[container],
            leader=False,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus("Scaling is not implemented for this charm")

    def test_given_unit_is_leader_but_container_is_not_ready_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        container = scenario.Container(
            name=CONTAINER_NAME,
            can_connect=False,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for container to start")

    def test_given_unit_is_leader_and_container_is_ready_but_relations_are_not_created_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        container = scenario.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus(
            "Waiting for fiveg_nrf, sdcore_config, certificates relation(s)"
        )

    def test_given_unit_is_leader_and_container_is_ready_but_fiveg_nrf_relation_is_not_created_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        container = scenario.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
            relations=[certificates_relation],
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus(
            "Waiting for fiveg_nrf, sdcore_config relation(s)"
        )

    def test_given_unit_is_leader_and_container_is_ready_but_sdcore_config_relation_is_not_created_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        fiveg_nrf_relation = scenario.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg-nrf",
        )
        container = scenario.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
            relations=[certificates_relation, fiveg_nrf_relation],
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus("Waiting for sdcore_config relation(s)")

    def test_given_unit_is_leader_and_container_is_ready_but_certificates_relation_is_not_created_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        fiveg_nrf_relation = scenario.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg-nrf",
        )
        nms_relation = scenario.Relation(
            endpoint="sdcore_config",
            interface="sdcore-config",
        )
        container = scenario.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
            relations=[fiveg_nrf_relation, nms_relation],
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus("Waiting for certificates relation(s)")

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_but_nrf_data_is_not_available_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        fiveg_nrf_relation = scenario.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg-nrf",
        )
        nms_relation = scenario.Relation(
            endpoint="sdcore_config",
            interface="sdcore-config",
        )
        container = scenario.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
            relations=[certificates_relation, fiveg_nrf_relation, nms_relation],
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for NRF data to be available")

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_but_webui_data_is_not_available_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        fiveg_nrf_relation = scenario.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg-nrf",
            remote_app_data={"url": TEST_NRF_URL},
        )
        nms_relation = scenario.Relation(
            endpoint="sdcore_config",
            interface="sdcore-config",
        )
        container = scenario.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
            relations=[certificates_relation, fiveg_nrf_relation, nms_relation],
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for Webui data to be available")

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_but_storage_is_not_ready_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
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
        certificates_relation = scenario.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        container = scenario.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
            relations=[nrf_relation, nms_relation, certificates_relation],
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for storage to be attached")

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_but_pod_ip_is_not_available_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
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
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
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
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                relations=[nrf_relation, nms_relation, certificates_relation],
            )
            self.mock_check_output.return_value = b""

            state_out = self.ctx.run("collect_unit_status", state_in)

            assert state_out.unit_status == WaitingStatus(
                "Waiting for pod IP address to be available"
            )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_and_pod_ip_is_available_but_csr_is_not_stored_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
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
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
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
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                relations=[nrf_relation, nms_relation, certificates_relation],
            )
            with open(f"{tempdir}/ausf.csr", "w") as f:
                f.write(TEST_CSR.decode())
            self.mock_generate_csr.return_value = TEST_CSR
            self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
            self.mock_check_output.return_value = TEST_POD_IP

            state_out = self.ctx.run("collect_unit_status", state_in)

            assert state_out.unit_status == WaitingStatus("Waiting for certificates to be stored")

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_and_pod_ip_is_available_and_csr_is_stored_but_ausf_service_is_not_running_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
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
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
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
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                relations=[nrf_relation, nms_relation, certificates_relation],
            )
            self.mock_check_output.return_value = TEST_POD_IP
            self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
            with open(f"{tempdir}/ausf.csr", "w") as f:
                f.write(TEST_CSR.decode())
            provider_certificate = Mock(ProviderCertificate)
            provider_certificate.certificate = TEST_CERTIFICATE
            provider_certificate.csr = TEST_CSR.decode()
            self.mock_get_assigned_certificates.return_value = [
                provider_certificate,
            ]

            state_out = self.ctx.run("collect_unit_status", state_in)

            assert state_out.unit_status == WaitingStatus("Waiting for AUSF service to start")

    def test_given_unit_is_configured_correctly_when_collect_unit_status_then_status_is_active(
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
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
            certificates_relation = scenario.Relation(
                endpoint="certificates",
                interface="tls-certificates",
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
                mounts={"config": config_mount, "certs": certs_mount},
                layers={"ausf": Layer({"services": {"ausf": {}}})},
                service_status={"ausf": ServiceStatus.ACTIVE},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                relations=[nrf_relation, nms_relation, certificates_relation],
            )
            self.mock_check_output.return_value = TEST_POD_IP
            self.mock_generate_private_key.return_value = TEST_PRIVATE_KEY
            with open(f"{tempdir}/ausf.csr", "w") as f:
                f.write(TEST_CSR.decode())
            provider_certificate = Mock(ProviderCertificate)
            provider_certificate.certificate = TEST_CERTIFICATE
            provider_certificate.csr = TEST_CSR.decode()
            self.mock_get_assigned_certificates.return_value = [
                provider_certificate,
            ]

            state_out = self.ctx.run("collect_unit_status", state_in)

            assert state_out.unit_status == ActiveStatus()

    def test_given_no_workload_version_file_when_collect_unit_status_then_workload_version_not_set(
        self,
    ):
        container = scenario.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = scenario.State(
            containers=[container],
            leader=True,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.workload_version == ""

    def test_given_workload_version_file_when_collect_unit_status_then_workload_version_set(
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            expected_version = "1.2.3"
            workload_version_mount = scenario.Mount(
                location="/etc",
                src=tempdir,
            )
            container = scenario.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"workload-version": workload_version_mount},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
            )
            with open(f"{tempdir}/workload-version", "w") as f:
                f.write(expected_version)

            state_out = self.ctx.run("collect_unit_status", state_in)

            assert state_out.workload_version == expected_version
