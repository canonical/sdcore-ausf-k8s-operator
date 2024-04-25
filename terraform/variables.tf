# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

variable "model_name" {
  description = "Name of Juju model to deploy application to."
  type        = string
  default     = ""
}

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
