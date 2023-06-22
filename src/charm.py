#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core AUSF service."""

import logging
from ipaddress import IPv4Address
from subprocess import check_output
from typing import Optional

from charms.observability_libs.v1.kubernetes_service_patch import (  # type: ignore[import]
    KubernetesServicePatch,
)
from charms.sdcore_nrf.v0.fiveg_nrf import NRFRequires  # type: ignore[import]
from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from jinja2 import Environment, FileSystemLoader
from lightkube.models.core_v1 import ServicePort
from ops.charm import CharmBase, EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer, PathError

logger = logging.getLogger(__name__)

AUSF_GROUP_ID = "ausfGroup001"
SBI_PORT = 29509
CONFIG_DIR = "/free5gc/config"
CONFIG_FILE_NAME = "ausfcfg.conf"
CONFIG_TEMPLATE_DIR = "src/templates/"
CONFIG_TEMPLATE_NAME = "ausfcfg.conf.j2"
CERTS_DIR_PATH = "/free5gc/support/TLS"  # Certificate paths are hardcoded in AUSF code
PRIVATE_KEY_NAME = "ausf.key"
CSR_NAME = "ausf.csr"
CERTIFICATE_NAME = "ausf.pem"
CERTIFICATE_COMMON_NAME = "ausf.sdcore"


class AUSFOperatorCharm(CharmBase):
    """Main class to describe juju event handling for the SD-Core AUSF operator."""

    def __init__(self, *args) -> None:
        super().__init__(*args)
        if not self.unit.is_leader():
            raise NotImplementedError("Scaling is not implemented for this charm")
        self._container_name = self._service_name = "ausf"
        self._container = self.unit.get_container(self._container_name)
        self._nrf_requires = NRFRequires(charm=self, relation_name="fiveg_nrf")
        self._service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[
                ServicePort(name="sbi", port=SBI_PORT),
            ],
        )
        self._certificates = TLSCertificatesRequiresV2(self, "certificates")

        self.framework.observe(self.on.ausf_pebble_ready, self._configure_ausf)
        self.framework.observe(self.on.fiveg_nrf_relation_joined, self._configure_ausf)
        self.framework.observe(self._nrf_requires.on.nrf_available, self._configure_ausf)

        self.framework.observe(
            self.on.certificates_relation_created, self._on_certificates_relation_created
        )
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.on.certificates_relation_broken, self._on_certificates_relation_broken
        )
        self.framework.observe(
            self._certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self._certificates.on.certificate_expiring, self._on_certificate_expiring
        )

    def _configure_ausf(
        self,
        event: EventBase,
    ) -> None:
        """Configure AUSF configuration file and pebble service.

        Args:
            event (EventBase): Juju event
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for container to start")
            event.defer()
            return
        if not self._relation_created("fiveg_nrf"):
            self.unit.status = BlockedStatus("Waiting for fiveg_nrf relation")
            return
        if not self._nrf_data_is_available:
            self.unit.status = WaitingStatus("Waiting for NRF data to be available")
            event.defer()
            return
        if not self._container.exists(path=CONFIG_DIR):
            self.unit.status = WaitingStatus("Waiting for storage to be attached")
            event.defer()
            return
        if not _get_pod_ip():
            self.unit.status = WaitingStatus("Waiting for pod IP address to be available")
            event.defer()
            return
        config_file_changed = self._apply_ausf_config()
        self._configure_ausf_service(force_restart=config_file_changed)
        self.unit.status = ActiveStatus()

    def _on_certificates_relation_created(self, event: EventBase) -> None:
        """Generates Private key."""
        if not self._container.can_connect():
            event.defer()
            return
        self._generate_private_key()

    def _on_certificates_relation_broken(self, event: EventBase) -> None:
        """Deletes TLS related artifacts and reconfigures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_private_key()
        self._delete_csr()
        self._delete_certificate()
        self._configure_ausf(event)

    def _on_certificates_relation_joined(self, event: EventBase) -> None:
        """Generates CSR and requests new certificate."""
        if not self._container.can_connect():
            event.defer()
            return
        if not self._private_key_is_stored():
            event.defer()
            return
        self._request_new_certificate()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Pushes certificate to workload and configures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        if not self._csr_is_stored():
            logger.warning("Certificate is available but no CSR is stored")
            return
        if event.certificate_signing_request != self._get_stored_csr():
            logger.debug("Stored CSR doesn't match one in certificate available event")
            return
        self._store_certificate(event.certificate)
        self._configure_ausf(event)

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        """Requests new certificate."""
        if not self._container.can_connect():
            event.defer()
            return
        if event.certificate != self._get_stored_certificate():
            logger.debug("Expiring certificate is not the one stored")
            return
        self._request_new_certificate()

    def _generate_private_key(self) -> None:
        """Generates and stores private key."""
        private_key = generate_private_key()
        self._store_private_key(private_key)

    def _request_new_certificate(self) -> None:
        """Generates and stores CSR, and uses it to request a new certificate."""
        private_key = self._get_stored_private_key()
        csr = generate_csr(
            private_key=private_key,
            subject=CERTIFICATE_COMMON_NAME,
            sans_dns=[CERTIFICATE_COMMON_NAME],
        )
        self._store_csr(csr)
        self._certificates.request_certificate_creation(certificate_signing_request=csr)

    def _delete_private_key(self):
        """Removes private key from workload."""
        if not self._private_key_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")
        logger.info("Removed private key from workload")

    def _delete_csr(self) -> None:
        """Deletes CSR from workload."""
        if not self._csr_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")
        logger.info("Removed CSR from workload")

    def _delete_certificate(self):
        """Deletes certificate from workload."""
        if not self._certificate_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")
        logger.info("Removed certificate from workload")

    def _private_key_is_stored(self) -> bool:
        """Returns whether private key is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")

    def _csr_is_stored(self) -> bool:
        """Returns whether CSR is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")

    def _get_stored_certificate(self) -> str:
        """Returns stored certificate."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}").read())

    def _get_stored_csr(self) -> str:
        """Returns stored CSR."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CSR_NAME}").read())

    def _get_stored_private_key(self) -> bytes:
        """Returns stored private key."""
        return str(
            self._container.pull(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}").read()
        ).encode()

    def _certificate_is_stored(self) -> bool:
        """Returns whether certificate is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")

    def _store_certificate(self, certificate: str) -> None:
        """Stores certificate in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}", source=certificate)
        logger.info("Pushed certificate pushed to workload")

    def _store_private_key(self, private_key: bytes) -> None:
        """Stores private key in workload."""
        self._container.push(
            path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}",
            source=private_key.decode(),
        )
        logger.info("Pushed private key to workload")

    def _store_csr(self, csr: bytes) -> None:
        """Stores CSR in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CSR_NAME}", source=csr.decode().strip())
        logger.info("Pushed CSR to workload")

    def _apply_ausf_config(self) -> bool:
        """Generate and push AUSF configuration file.

        Returns:
            bool: True if the configuration file was changed.
        """
        content = self._render_config_file(
            ausf_group_id=AUSF_GROUP_ID,
            ausf_ip=_get_pod_ip(),  # type: ignore[arg-type]
            nrf_url=self._nrf_requires.nrf_url,
            sbi_port=SBI_PORT,
            scheme="https" if self._certificate_is_stored() else "http",
        )
        if not self._config_file_content_matches(content):
            self._push_config_file(
                content=content,
            )
            return True
        return False

    def _render_config_file(
        self,
        *,
        ausf_group_id: str,
        ausf_ip: str,
        sbi_port: int,
        nrf_url: str,
        scheme: str,
    ):
        """Render the AUSF config file.

        Args:
            ausf_group_id (str): Group ID of the AUSF.
            ausf_ip (str): IP of the AUSF.
            nrf_url (str): URL of the NRF.
            sbi_port (int): AUSF SBi port.
            scheme (str): SBI Interface scheme ("http" or "https")
        """
        jinja2_environment = Environment(loader=FileSystemLoader(CONFIG_TEMPLATE_DIR))
        template = jinja2_environment.get_template(CONFIG_TEMPLATE_NAME)
        content = template.render(
            ausf_group_id=ausf_group_id,
            ausf_ip=ausf_ip,
            nrf_url=nrf_url,
            sbi_port=sbi_port,
            scheme=scheme,
        )
        return content

    def _config_file_content_matches(self, content: str) -> bool:
        """Return whether the config file content matches the provided content.

        Returns:
            bool: Whether the config file content matches
        """
        f"{CONFIG_DIR}/{CONFIG_FILE_NAME}"
        try:
            existing_content = self._container.pull(path=f"{CONFIG_DIR}/{CONFIG_FILE_NAME}")
            return existing_content.read() == content
        except PathError:
            return False

    def _push_config_file(
        self,
        content: str,
    ) -> None:
        """Push the AUSF config file to the container.

        Args:
            content (str): Content of the config file.
        """
        self._container.push(
            path=f"{CONFIG_DIR}/{CONFIG_FILE_NAME}",
            source=content,
            make_dirs=True,
        )
        logger.info("Pushed %s config file", CONFIG_FILE_NAME)

    def _configure_ausf_service(self, *, force_restart: bool = False) -> None:
        """Manage AUSF's pebble layer and service.

        Updates the pebble layer if the proposed config is different from the current one. If layer
        has been updated also restart the workload service.

        Args:
            force_restart (bool): Allows for forcibly restarting the service even if Pebble plan
                didn't change.
        """
        pebble_layer = self._pebble_layer
        plan = self._container.get_plan()
        if plan.services != pebble_layer.services or force_restart:
            self._container.add_layer(self._container_name, pebble_layer, combine=True)
            self._container.restart(self._service_name)
            logger.info("Restarted container %s", self._service_name)

    def _relation_created(self, relation_name: str) -> bool:
        """Return True if the relation is created, False otherwise.

        Args:
            relation_name (str): Name of the relation.

        Returns:
            bool: True if the relation is created, False otherwise.
        """
        return bool(self.model.get_relation(relation_name))

    @property
    def _pebble_layer(self) -> Layer:
        """Return pebble layer for the ausf container.

        Returns:
            Layer: Pebble Layer
        """
        return Layer(
            {
                "services": {
                    self._service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": f"/free5gc/ausf/ausf --ausfcfg {CONFIG_DIR}/{CONFIG_FILE_NAME}",  # noqa: E501
                        "environment": self._ausf_environment_variables,
                    },
                },
            }
        )

    @property
    def _ausf_environment_variables(self) -> dict:
        """Return environment variables for the ausf container.

        Returns:
            dict: Environment variables.
        """
        return {
            "GOTRACEBACK": "crash",
            "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
            "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
            "GRPC_TRACE": "all",
            "GRPC_VERBOSITY": "DEBUG",
            "POD_IP": _get_pod_ip(),
            "MANAGED_BY_CONFIG_POD": "true",
        }

    @property
    def _nrf_data_is_available(self) -> bool:
        """Return whether the NRF data is available.

        Returns:
            bool: Whether the NRF data is available.
        """
        return bool(self._nrf_requires.nrf_url)


def _get_pod_ip() -> Optional[str]:
    """Returns the pod IP using juju client.

    Returns:
        str: The pod IP.
    """
    ip_address = check_output(["unit-get", "private-address"])
    return str(IPv4Address(ip_address.decode().strip())) if ip_address else None


if __name__ == "__main__":  # pragma: no cover
    main(AUSFOperatorCharm)
