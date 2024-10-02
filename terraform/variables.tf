# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

variable "app_name" {
  description = "Name of the application in the Juju model."
  type        = string
  default     = "ausf"
}

variable "channel" {
  description = "The channel to use when deploying a charm."
  type        = string
  default     = "1.5/edge"
}

variable "config" {
  description = "Configuration for this charm."
  type        = map(string)
  default     = {}
}

variable "constraints" {
  description = "Juju constraints to apply to this application."
  type        = string
  default     = ""
}

variable "model" {
  description = "Reference to a `juju_model`."
  type        = string
  default     = ""
}

variable "revision" {
  description = "Revision number of the charm."
  type        = number
  default     = null
}

variable "units" {
  description = "Number of units to deploy"
  type        = number
  default     = 1

  validation {
    condition     = var.units == 1
    error_message = "Scaling is not supported for this charm."
  }

}
