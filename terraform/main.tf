resource "juju_application" "ausf" {
  name  = "ausf"
  model = var.model_name

  charm {
    name    = "sdcore-ausf-k8s"
    channel = var.channel
  }
  units = 1
  trust = true
}

resource "juju_integration" "ausf-certs" {
  model = var.model_name

  application {
    name     = juju_application.ausf.name
    endpoint = "certificates"
  }

  application {
    name     = var.certs_application_name
    endpoint = "certificates"
  }
}

resource "juju_integration" "ausf-nrf" {
  model = var.model_name

  application {
    name     = juju_application.ausf.name
    endpoint = "fiveg_nrf"
  }

  application {
    name     = var.nrf_application_name
    endpoint = "fiveg-nrf"
  }
}
