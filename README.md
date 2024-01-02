# SD-Core AUSF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-ausf-k8s/badge.svg)](https://charmhub.io/sdcore-ausf-k8s)

A Charmed Operator for SD-Core's Authentication Server Function (AUSF) component for K8s. 

## Usage

```bash
juju deploy sdcore-ausf-k8s --channel=edge
juju deploy sdcore-nrf-k8s --channel=edge
juju deploy mongodb-k8s --trust --channel=6/beta
juju deploy self-signed-certificates --channel=beta
juju integrate sdcore-nrf-k8s:database mongodb-k8s
juju integrate sdcore-nrf-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-ausf-k8s:fiveg-nrf sdcore-nrf-k8s:fiveg-nrf
juju integrate sdcore-ausf-k8s:certificates self-signed-certificates:certificates
```

## Image

- **ausf**: `ghcr.io/canonical/sdcore-ausf:1.3`
