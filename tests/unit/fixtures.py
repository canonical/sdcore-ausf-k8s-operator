# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
from ops import testing

from charm import AUSFOperatorCharm


class AUSFUnitTestFixtures:
    patcher_check_output = patch("charm.check_output")
    patcher_get_assigned_certificate = patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    patcher_restart = patch("ops.model.Container.restart")

    @pytest.fixture(autouse=True)
    def setup(self, request):
        self.mock_check_output = AUSFUnitTestFixtures.patcher_check_output.start()
        self.mock_get_assigned_certificate = (
            AUSFUnitTestFixtures.patcher_get_assigned_certificate.start()
        )
        self.mock_restart = AUSFUnitTestFixtures.patcher_restart.start()
        yield
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=AUSFOperatorCharm,
        )
