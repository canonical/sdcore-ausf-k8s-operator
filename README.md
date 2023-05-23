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
  <h1>SD-CORE AUSF Operator</h1>
</div>

A Charmed Operator for SDCORE's Authentication Server Function (AUSF) component. 

## Usage

```bash
juju deploy sdcore-ausf --trust --channel=edge
```

## Image

- **ausf**: `omecproject/5gc-ausf:master-c84dff4`
