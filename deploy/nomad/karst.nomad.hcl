# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# The co-located deployment, run under Nomad instead of docker compose: one
# coordination server and one relay, on one host, sharing one directory. This
# is a direct Nomad translation of ../compose/docker-compose.yml -- same
# images, same env vars, same ./state layout, same bootstrap.sh. Run
# ./bootstrap.sh (../compose/bootstrap.sh -- it is orchestrator-agnostic,
# nothing compose-specific in it) once before `nomad job run` here.
#
# Host networking, not Nomad's bridge/CNI networking: this is a single-node
# deployment and CNI reference plugins are an extra dependency this doesn't
# need. Each task binds directly to the host's ports, same as compose's own
# `network_mode: host` already does for the optional coturn service in
# turn.nomad.hcl.
#
# See README.md for how this differs operationally from the compose path,
# and for the unrelated "Nomad" meaning elsewhere in this repo (the
# Infrastructure Connections Nomad connection type is karst's scaler treating
# a Nomad cluster as a placement *target* -- a different concern from this
# file, which runs karst's own control-plane *under* Nomad as orchestrator).

variable "deploy_dir" {
  type        = string
  default     = "."
  description = "Directory holding ./state (and, if present, .env-equivalent values below). Defaults to the directory nomad job run is invoked from, matching compose's own cwd-relative ./state convention."
}

variable "node_name" {
  type        = string
  default     = "shannon"
  description = "The Nomad node (by attr.unique.hostname) this deployment is pinned to. A co-located deployment's state only exists on one host; unlike the generic self-hoster default this isn't meant to float across a multi-node cluster."
}

variable "karst_aquifer" {
  type    = string
  default = ""
}

job "karst" {
  datacenters = ["dc1"]
  type        = "service"

  group "control" {
    count = 1

    constraint {
      attribute = "${attr.unique.hostname}"
      value     = var.node_name
    }

    task "control" {
      driver = "docker"

      config {
        image        = "ghcr.io/karst-net/karst-control:dev"
        network_mode = "host"
        volumes = [
          "${var.deploy_dir}/state:/var/lib/karst",
          "${var.deploy_dir}/state/netbird:/var/lib/netbird",
          # Read-write, not read-only: the daemon generates a store
          # encryption key on first boot and saves it back into this file.
          "${var.deploy_dir}/state/management.json:/etc/netbird/management.json",
        ]
      }

      env {
        NB_DISABLE_GEOLOCATION        = "true"
        KARST_RELAY_ROSTER_FILE       = "/var/lib/karst/roster.toml"
        KARST_AQUIFER                 = var.karst_aquifer
        KARST_RELAY_REGISTRY_FILE     = "/var/lib/karst/relays.json"
        KARST_POLICY_FILE             = "/var/lib/karst/policy.json"
        KARST_BOOTSTRAP_SETUP_KEY_FILE = "/var/lib/karst/bootstrap.key"
      }

      resources {
        cpu    = 1000
        memory = 1024
      }
    }
  }

  group "relay" {
    count = 1

    constraint {
      attribute = "${attr.unique.hostname}"
      value     = var.node_name
    }

    task "relay" {
      driver = "docker"

      config {
        image        = "ghcr.io/karst-net/karst-relay:dev"
        network_mode = "host"
        args         = ["--config", "/var/lib/karst/relay.toml"]
        volumes = [
          "${var.deploy_dir}/state:/var/lib/karst",
        ]
      }

      resources {
        cpu    = 500
        memory = 512
      }
    }
  }
}
