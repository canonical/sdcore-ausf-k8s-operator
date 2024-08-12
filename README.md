# Aether SD-Core AUSF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-ausf-k8s/badge.svg)](https://charmhub.io/sdcore-ausf-k8s)

A Charmed Operator for Aether SD-Core's Authentication Server Function (AUSF) component for K8s. 

## Usage

```bash
juju deploy sdcore-ausf-k8s --channel=1.5/edge
juju deploy sdcore-nrf-k8s --channel=1.5/edge
juju deploy sdcore-nms-k8s --channel=1.5/edge
juju deploy mongodb-k8s --trust --channel=6/beta
juju deploy self-signed-certificates
juju integrate sdcore-nrf-k8s:database mongodb-k8s
juju integrate sdcore-nrf-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-nms-k8s:common_database mongodb-k8s:database
juju integrate sdcore-nms-k8s:auth_database mongodb-k8s:database
juju integrate sdcore-ausf-k8s:fiveg_nrf sdcore-nrf-k8s:fiveg_nrf
juju integrate sdcore-ausf-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-ausf-k8s:sdcore_config sdcore-nms-k8s:sdcore_config
```

## Image

- **ausf**: `ghcr.io/canonical/sdcore-ausf:1.4.1`
