# SD-Core AUSF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-ausf/badge.svg)](https://charmhub.io/sdcore-ausf)

A Charmed Operator for SD-Core's Authentication Server Function (AUSF) component. 

## Usage

```bash
juju deploy sdcore-ausf --trust --channel=edge
juju deploy sdcore-nrf --trust --channel=edge
juju deploy mongodb-k8s --trust --channel=5/edge
juju deploy self-signed-certificates --channel=beta
juju integrate sdcore-nrf:database mongodb-k8s
juju integrate sdcore-nrf:certificates self-signed-certificates:certificates
juju integrate sdcore-ausf:fiveg-nrf sdcore-nrf:fiveg-nrf
juju integrate sdcore-ausf:certificates self-signed-certificates:certificates
```

## Image

- **ausf**: `ghcr.io/canonical/sdcore-ausf:1.3`
