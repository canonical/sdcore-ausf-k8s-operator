# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
import scenario

from charm import AUSFOperatorCharm


class AUSFUnitTestFixtures:
    patcher_check_output = patch("charm.check_output")
    patcher_generate_csr = patch("charm.generate_csr")
    patcher_generate_private_key = patch("charm.generate_private_key")
    patcher_get_assigned_certificates = patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.get_assigned_certificates"
    )
    patcher_request_certificate_creation = patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    patcher_restart = patch("ops.model.Container.restart")

    @pytest.fixture(autouse=True)
    def setup(self, request):
        self.mock_check_output = AUSFUnitTestFixtures.patcher_check_output.start()
        self.mock_generate_csr = AUSFUnitTestFixtures.patcher_generate_csr.start()
        self.mock_generate_private_key = AUSFUnitTestFixtures.patcher_generate_private_key.start()
        self.mock_get_assigned_certificates = (
            AUSFUnitTestFixtures.patcher_get_assigned_certificates.start()
        )
        self.mock_request_certificate_creation = (
            AUSFUnitTestFixtures.patcher_request_certificate_creation.start()
        )
        self.mock_restart = AUSFUnitTestFixtures.patcher_restart.start()
        yield
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=AUSFOperatorCharm,
        )
