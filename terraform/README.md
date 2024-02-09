# SD-Core AUSF K8s Terraform Module

This SD-Core AUSF K8s Terraform module aims to deploy the [sdcore-ausf-k8s charm](https://charmhub.io/sdcore-ausf-k8s) via Terraform.

## Getting Started

### Prerequisites

The following software and tools needs to be installed and should be running in the local environment. Please [set up your environment](https://discourse.charmhub.io/t/set-up-your-development-environment-with-microk8s-for-juju-terraform-provider/13109) before deployment.

- `microk8s`
- `juju 3.x`
- `terrafom`

The `sdcore-ausf-ks8` application requires the integrations with the following applications.

- `self-signed-certificates`
- `sdcore-nrf-k8s`

### Deploy the sdcore-ausf-k8s charm using Terraform

Make sure that `storage` plugin is enabled for Microk8s:

```console
sudo microk8s enable hostpath-storage
```

Add a Juju model:

```console
juju add-model <model-name>
```

Initialise the provider:

```console
terraform init
```

Fill the mandatory config options in the `terraform.tfvars` file:

```yaml
# Mandatory Config Options
model_name             = "put your model-name here"
certs_application_name = "put your Self Signed Certificates app name here"
nrf_application_name   = "put your NRF app name here"
```

Create the Terraform Plan:

```console
terraform plan -var-file="terraform.tfvars" 
```

Deploy the resources:

```console
terraform apply -auto-approve 
```

### Check the Output

Run `juju switch <juju model>` to switch to the target Juju model and observe the status of the applications.

```console
juju status --relations
```

### Clean up

Destroy the deployment:

```console
terraform destroy -auto-approve
```