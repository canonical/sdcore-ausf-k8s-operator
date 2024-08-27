# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from charms.tls_certificates_interface.v4.tls_certificates import (
    PrivateKey,
    ProviderCertificate,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)


def example_cert_and_key(tls_relation_id: int) -> tuple[ProviderCertificate, PrivateKey]:
    private_key = generate_private_key()
    csr = generate_csr(
        private_key=private_key,
        common_name="amf",
    )
    ca_private_key = generate_private_key()
    ca_certificate = generate_ca(
        private_key=ca_private_key,
        common_name="ca.com",
        validity=365,
    )
    certificate = generate_certificate(
        csr=csr,
        ca=ca_certificate,
        ca_private_key=ca_private_key,
        validity=365,
    )
    provider_certificate = ProviderCertificate(
        relation_id=tls_relation_id,
        certificate=certificate,
        certificate_signing_request=csr,
        ca=ca_certificate,
        chain=[ca_certificate],
    )
    return provider_certificate, private_key