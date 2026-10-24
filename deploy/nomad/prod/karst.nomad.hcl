# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# The Caddy + Keycloak variant this file documents is the same deployment
# shape as ../../compose/prod/docker-compose.yml: the console and Keycloak
# share one externally-forwarded port, karst-control is not published to the
# host at all (only reachable from Caddy over a private network), and
# control/relay are pinned by image digest to a cosign-verified release
# rather than a mutable tag. See that compose file's own header comment for
# why this shape exists (ADR pentest / real production posture, not
# disposable test infra) -- unchanged by running it under Nomad instead of
# compose.
#
# Networking is split, matching compose's own architecture rather than
# flattening everything to the host:
#   - control, keycloak: join the pre-created `karst` Docker network
#     (`docker network create karst`, once) with a network alias, same as
#     compose's bridge network + service-name DNS. No ports published to the
#     host at all -- control is genuinely unreachable except from Caddy, and
#     keycloak likewise.
#   - relay: network_mode = "host". It needs the real host port 443 and has
#     no service-to-service dependency on the others (it only reads shared
#     state files), so there's nothing it needs the `karst` network for.
#   - caddy: on the `karst` network (to resolve control/keycloak by name,
#     exactly as the Caddyfile expects) *and* publishes host port 33073.
# This is why control/keycloak must NOT also use host networking: under host
# networking every task shares one real network namespace, so control's own
# default listen port (33073) would collide with Caddy's externally
# published 33073 -- a real conflict, not a style choice, caught during
# `nomad job plan` before this was ever run for real.
#
# This job reuses an *existing* compose deployment's state in place -- point
# the variables below at a live deploy/compose/prod checkout (its ./state,
# ./release, ./versions, ./config.json) and the shared deploy/compose/state
# both compose and this job read bootstrap.sh's output from. Zero data
# migration, same as compose itself never needing one across its own
# releases.

variable "node_name" {
  type        = string
  default     = "shannon"
  description = "This deployment's bind-mounted state only exists on one host -- the Nomad node (attr.unique.hostname) it must be pinned to."
}

variable "repo_root" {
  type        = string
  default     = "/home/adrian/code/karst"
  description = "Checkout root, for web/console/dist and web/portal/dist (Caddy serves these as static assets, same as compose)."
}

variable "shared_state_dir" {
  type        = string
  default     = "/home/adrian/code/karst/deploy/compose/state"
  description = "The state directory compose's control+relay services share (bootstrap.sh's output: roster.toml, relays.json, policy.json, bootstrap.key, tls/, netbird/, management.json) -- deploy/compose/prod/docker-compose.yml's own `../state`."
}

variable "prod_dir" {
  type        = string
  default     = "/home/adrian/code/karst/deploy/compose/prod"
  description = "This prod deployment's own directory -- ./state/keycloak, ./state/keycloak-realm.json, ./state/caddy, ./release, ./versions, ./config.json."
}

variable "jobspec_dir" {
  type        = string
  default     = "/home/adrian/code/mycelium/deploy/nomad/prod"
  description = "Where this job file (and its sibling Caddyfile) actually live on the host -- Nomad docker volumes need an absolute host path, unlike compose's cwd-relative ./Caddyfile."
}

variable "docker_network" {
  type        = string
  default     = "karst"
  description = "Pre-created via `docker network create karst` -- Nomad's docker driver can join an existing user-defined network but does not create one itself."
}

variable "control_image_digest" {
  type        = string
  default     = "sha256:aeb3f72381c3575541f9909e5e16a477f2802cc6443f5c89fea5bbbfeb5d086e"
  description = "cosign-verified against deliverables.yml -- see docs/OPERATIONS.md §7 before changing this."
}

variable "relay_image_digest" {
  type        = string
  default     = "sha256:45a72850a7f3864c5200f3d147998f8e291c0ceb8aaa5f81e045a3eba93c1404"
}

variable "console_image" {
  type        = string
  default     = "local/karst-console:0996bc9"
  description = "Not yet a published, cosign-verified artefact like control/relay above -- built locally from deploy/images/karst-console.Dockerfile (web/ as context) against whatever web/console revision was current. Rebuild and bump this for a newer admin console."
}

variable "karst_console_host" {
  type        = string
  description = "Public hostname or IP, no scheme/port -- Caddy's TLS SNI identity and Keycloak's issuer URL both depend on this."
}

variable "karst_aquifer" {
  type    = string
  default = ""
}

variable "kc_master_admin_password" {
  type        = string
  description = "Pass with -var, never commit a real value here."
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
        image           = "ghcr.io/karst-net/karst-control@${var.control_image_digest}"
        network_mode    = var.docker_network
        network_aliases = ["control"]
        volumes = [
          "${var.shared_state_dir}:/var/lib/karst",
          "${var.shared_state_dir}/netbird:/var/lib/netbird",
          "${var.shared_state_dir}/management.json:/etc/netbird/management.json",
          "${var.prod_dir}/versions:/run/karst-versions:ro",
        ]
      }

      env {
        NB_DISABLE_GEOLOCATION         = "true"
        KARST_RELAY_ROSTER_FILE        = "/var/lib/karst/roster.toml"
        KARST_AQUIFER                  = var.karst_aquifer
        KARST_RELAY_REGISTRY_FILE      = "/var/lib/karst/relays.json"
        KARST_POLICY_FILE              = "/var/lib/karst/policy.json"
        KARST_BOOTSTRAP_SETUP_KEY_FILE = "/var/lib/karst/bootstrap.key"
        KARST_COMPONENT_VERSIONS_FILE  = "/run/karst-versions/components.json"
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
        image        = "ghcr.io/karst-net/karst-relay@${var.relay_image_digest}"
        network_mode = "host"
        args         = ["--config", "/var/lib/karst/relay.toml"]
        volumes = [
          "${var.shared_state_dir}:/var/lib/karst",
        ]
      }

      resources {
        cpu    = 500
        memory = 512
      }
    }
  }

  group "keycloak" {
    count = 1

    constraint {
      attribute = "${attr.unique.hostname}"
      value     = var.node_name
    }

    task "keycloak" {
      driver = "docker"

      config {
        image           = "quay.io/keycloak/keycloak:26.4"
        network_mode    = var.docker_network
        network_aliases = ["keycloak"]
        args            = ["start-dev", "--import-realm", "--http-relative-path=/auth"]
        volumes = [
          "${var.prod_dir}/state/keycloak:/opt/keycloak/data",
          "${var.prod_dir}/state/keycloak-realm.json:/opt/keycloak/data/import/karst-realm.json:ro",
        ]
      }

      env {
        KEYCLOAK_ADMIN          = "admin"
        KEYCLOAK_ADMIN_PASSWORD = var.kc_master_admin_password
        # Caddy terminates TLS and forwards plaintext; these three make
        # Keycloak generate issuer/redirect URLs for the externally-visible
        # address instead of its own container-internal one.
        KC_HOSTNAME_URL       = "https://${var.karst_console_host}:33073/auth"
        KC_HOSTNAME_ADMIN_URL = "https://${var.karst_console_host}:33073/auth"
        KC_PROXY_HEADERS      = "xforwarded"
        KC_HTTP_ENABLED       = "true"
      }

      resources {
        cpu    = 1000
        memory = 1536
      }
    }
  }

  group "console" {
    count = 1

    constraint {
      attribute = "${attr.unique.hostname}"
      value     = var.node_name
    }

    task "console" {
      driver = "docker"

      config {
        image           = var.console_image
        network_mode    = var.docker_network
        network_aliases = ["console"]
      }

      resources {
        cpu    = 200
        memory = 128
      }
    }
  }

  group "caddy" {
    count = 1

    constraint {
      attribute = "${attr.unique.hostname}"
      value     = var.node_name
    }

    network {
      port "https" {
        static = 33073
      }
    }

    task "caddy" {
      driver = "docker"

      config {
        image        = "caddy:2.10"
        network_mode = var.docker_network
        ports        = ["https"]
        volumes = [
          "${var.jobspec_dir}/Caddyfile:/etc/caddy/Caddyfile:ro",
          "${var.repo_root}/web/portal/dist:/srv/portal:ro",
          "${var.prod_dir}/release:/srv/releases:ro",
          "${var.prod_dir}/state/caddy:/data",
          "${var.prod_dir}/config.json:/etc/karst/config.json:ro",
        ]
      }

      env {
        KARST_CONSOLE_HOST = var.karst_console_host
      }

      resources {
        cpu    = 200
        memory = 256
      }
    }
  }
}
