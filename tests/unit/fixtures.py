# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Generator
from unittest.mock import patch

import pytest
from charm import AUSFOperatorCharm
from ops import testing

NAMESPACE = "whatever"
TEST_NRF_URL = "https://nrf-example.com:1234"
TEST_WEBUI_URL = "some-webui:7890"


class AUSFUnitTestFixtures:
    patcher_check_output = patch("charm.check_output")
    patcher_generate_csr = patch("charm.generate_csr")
    patcher_generate_private_key = patch("charm.generate_private_key")
    patcher_get_service = patch("ops.model.Container.get_service")
    patcher_get_assigned_certificates = patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"
    )
    patcher_request_certificate_creation = patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    patcher_restart = patch("ops.model.Container.restart")

    @pytest.fixture()
    def setup(self):
        self.mock_check_output = AUSFUnitTestFixtures.patcher_check_output.start()
        self.mock_generate_csr = AUSFUnitTestFixtures.patcher_generate_csr.start()
        self.mock_generate_private_key = AUSFUnitTestFixtures.patcher_generate_private_key.start()
        self.mock_get_service = AUSFUnitTestFixtures.patcher_get_service.start()
        self.mock_get_assigned_certificates = (
            AUSFUnitTestFixtures.patcher_get_assigned_certificates.start()
        )
        self.mock_request_certificate_creation = (
            AUSFUnitTestFixtures.patcher_request_certificate_creation.start()
        )
        self.mock_restart = AUSFUnitTestFixtures.patcher_restart.start()

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
            key_values={"url": TEST_NRF_URL},
        )

    @pytest.fixture()
    def fiveg_nrf_relation_id(self) -> Generator[int, None, None]:
        yield self.harness.add_relation(
            relation_name="fiveg_nrf",
            remote_app="whatever-nrf",
        )

    @pytest.fixture()
    def create_nms_relation_and_set_webui_url(self, nms_relation_id):
        self.harness.add_relation_unit(
            relation_id=nms_relation_id, remote_unit_name="whatever-nms/0"
        )
        self.harness.update_relation_data(
            relation_id=nms_relation_id,
            app_or_unit="whatever-nms",
            key_values={"webui_url": TEST_WEBUI_URL},
        )

    @pytest.fixture()
    def nms_relation_id(self) -> Generator[int, None, None]:
        yield self.harness.add_relation(
            relation_name="sdcore_config",
            remote_app="whatever-nms",
        )

    @pytest.fixture()
    def certificates_relation_id(self) -> Generator[int, None, None]:
        yield self.harness.add_relation(
            relation_name="certificates",
            remote_app="whatever",
        )
