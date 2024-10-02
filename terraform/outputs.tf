# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.ausf.name
}

# Required integration endpoints

output "requires" {
  value = {
    fiveg_nrf     = "fiveg_nrf"
    sdcore_config = "sdcore_config"
    certificates  = "certificates"
    logging       = "logging"
  }
}

output "provides" {
  value = {
    metrics = "metrics-endpoint"
  }
}
