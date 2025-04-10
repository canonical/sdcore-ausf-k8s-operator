# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile

from ops import ActiveStatus, BlockedStatus, WaitingStatus, testing
from ops.pebble import Layer, ServiceStatus

from tests.unit.certificates_helpers import (
    example_cert_and_key,
)
from tests.unit.fixtures import AUSFUnitTestFixtures

CONTAINER_NAME = "ausf"
TEST_POD_IP = b"1.2.3.4"
TEST_NRF_URL = "https://nrf-example.com:1234"


class TestCharmCollectStatus(AUSFUnitTestFixtures):
    # def test_given_unit_is_not_leader_when_collect_unit_status_then_status_is_blocked(self):
    #     container = testing.Container(
    #         name=CONTAINER_NAME,
    #     )
    #     state_in = testing.State(
    #         containers={container},
    #         leader=False,
    #     )
    #
    #     state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)
    #
    #     assert state_out.unit_status == BlockedStatus("Scaling is not implemented for this charm")

    def test_given_unit_is_leader_but_container_is_not_ready_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        container = testing.Container(
            name=CONTAINER_NAME,
            can_connect=False,
        )
        state_in = testing.State(
            containers={container},
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for container to start")

    def test_given_invalid_log_level_config_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        container = testing.Container(name="ausf", can_connect=True)
        state_in = testing.State(
            leader=True,
            config={"log-level": "invalid"},
            containers={container},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "The following configurations are not valid: ['log-level']"
        )

    def test_given_unit_is_leader_and_container_is_ready_but_relations_are_not_created_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        container = testing.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = testing.State(
            containers={container},
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Waiting for fiveg_nrf, sdcore_config, certificates relation(s)"
        )

    def test_given_unit_is_leader_and_container_is_ready_but_fiveg_nrf_relation_is_not_created_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        container = testing.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = testing.State(
            containers={container},
            leader=True,
            relations={certificates_relation},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "Waiting for fiveg_nrf, sdcore_config relation(s)"
        )

    def test_given_unit_is_leader_and_container_is_ready_but_sdcore_config_relation_is_not_created_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        fiveg_nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg-nrf",
        )
        container = testing.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = testing.State(
            containers={container},
            leader=True,
            relations={certificates_relation, fiveg_nrf_relation},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Waiting for sdcore_config relation(s)")

    def test_given_unit_is_leader_and_container_is_ready_but_certificates_relation_is_not_created_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        fiveg_nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg-nrf",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore-config",
        )
        container = testing.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = testing.State(
            containers={container},
            leader=True,
            relations={fiveg_nrf_relation, nms_relation},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Waiting for certificates relation(s)")

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_but_nrf_data_is_not_available_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        fiveg_nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg-nrf",
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore-config",
        )
        container = testing.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = testing.State(
            containers={container},
            leader=True,
            relations={certificates_relation, fiveg_nrf_relation, nms_relation},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for NRF data to be available")

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_but_webui_data_is_not_available_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        fiveg_nrf_relation = testing.Relation(
            endpoint="fiveg_nrf",
            interface="fiveg-nrf",
            remote_app_data={"url": TEST_NRF_URL},
        )
        nms_relation = testing.Relation(
            endpoint="sdcore_config",
            interface="sdcore-config",
        )
        container = testing.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = testing.State(
            containers={container},
            leader=True,
            relations={certificates_relation, fiveg_nrf_relation, nms_relation},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for Webui data to be available")

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_but_storage_is_not_ready_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
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
        certificates_relation = testing.Relation(
            endpoint="certificates",
            interface="tls-certificates",
        )
        container = testing.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = testing.State(
            containers={container},
            leader=True,
            relations={nrf_relation, nms_relation, certificates_relation},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for storage to be attached")

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_but_pod_ip_is_not_available_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
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
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            certs_mount = testing.Mount(
                location="/sdcore/certs",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/sdcore/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers={container},
                leader=True,
                relations={nrf_relation, nms_relation, certificates_relation},
            )
            self.mock_check_output.return_value = b""

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == WaitingStatus(
                "Waiting for pod IP address to be available"
            )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_and_pod_ip_is_available_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
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
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            certs_mount = testing.Mount(
                location="/sdcore/certs",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/sdcore/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers={container},
                leader=True,
                relations={nrf_relation, nms_relation, certificates_relation},
            )

            self.mock_check_output.return_value = TEST_POD_IP
            self.mock_get_assigned_certificate.return_value = None, None

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == WaitingStatus(
                "Waiting for certificates to be available"
            )

    def test_given_unit_is_leader_and_container_is_ready_and_relations_are_created_and_nrf_data_is_available_and_storage_is_ready_and_pod_ip_is_available_but_ausf_service_is_not_running_when_collect_unit_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
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
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            certs_mount = testing.Mount(
                location="/sdcore/certs",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/sdcore/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers={container},
                leader=True,
                relations={nrf_relation, nms_relation, certificates_relation},
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == WaitingStatus("Waiting for AUSF service to start")

    def test_given_unit_is_configured_correctly_when_collect_unit_status_then_status_is_active(
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
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
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            certs_mount = testing.Mount(
                location="/sdcore/certs",
                source=tempdir,
            )
            config_mount = testing.Mount(
                location="/sdcore/config",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
                layers={"ausf": Layer({"services": {"ausf": {}}})},
                service_statuses={"ausf": ServiceStatus.ACTIVE},
            )
            state_in = testing.State(
                containers={container},
                leader=True,
                relations={nrf_relation, nms_relation, certificates_relation},
            )
            self.mock_check_output.return_value = TEST_POD_IP
            provider_certificate, private_key = example_cert_and_key(
                tls_relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = provider_certificate, private_key

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.unit_status == ActiveStatus()

    def test_given_no_workload_version_file_when_collect_unit_status_then_workload_version_not_set(
        self,
    ):
        container = testing.Container(
            name=CONTAINER_NAME,
            can_connect=True,
        )
        state_in = testing.State(
            containers={container},
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.workload_version == ""

    def test_given_workload_version_file_when_collect_unit_status_then_workload_version_set(
        self,
    ):
        with tempfile.TemporaryDirectory() as tempdir:
            expected_version = "1.2.3"
            workload_version_mount = testing.Mount(
                location="/etc",
                source=tempdir,
            )
            container = testing.Container(
                name=CONTAINER_NAME,
                can_connect=True,
                mounts={"workload-version": workload_version_mount},
            )
            state_in = testing.State(
                containers={container},
                leader=True,
            )
            with open(f"{tempdir}/workload-version", "w") as f:
                f.write(expected_version)

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

            assert state_out.workload_version == expected_version
