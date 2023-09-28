<div align="center">
  <img src="./icon.svg" alt="ONF Icon" width="200" height="200">
</div>
<br/>
<div align="center">
  <a href="https://charmhub.io/sdcore-ausf"><img src="https://charmhub.io/sdcore-ausf/badge.svg" alt="CharmHub Badge"></a>
  <a href="https://github.com/canonical/sdcore-ausf-operator/actions/workflows/publish-charm.yaml">
    <img src="https://github.com/canonical/sdcore-ausf-operator/actions/workflows/publish-charm.yaml/badge.svg?branch=main" alt=".github/workflows/publish-charm.yaml">
  </a>
  <br/>
  <br/>
  <h1>SD-Core AUSF Operator</h1>
</div>

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
