module github.com/netbirdio/netbird

go 1.27

// Pinned to the release candidate because crypto/mldsa is a 1.27 addition and
// 1.27.0 is not out yet. Without this line the toolchain tries to fetch a
// go1.27.0 that does not exist and the build fails with "toolchain not
// available", which names the symptom and not the cause.
//
// Drop it when 1.27.0 ships: the `go` directive above is the real requirement,
// and this one only says which build satisfies it today.
toolchain go1.27rc3

require (
	github.com/DeRuina/timberjack v1.4.2
	github.com/c-robinson/iplib v1.0.3
	github.com/caddyserver/certmagic v0.21.3
	github.com/coder/websocket v1.8.14
	github.com/coreos/go-oidc/v3 v3.18.0
	github.com/dexidp/dex v2.13.0+incompatible
	github.com/dexidp/dex/api/v2 v2.4.0
	github.com/eko/gocache/lib/v4 v4.2.0
	github.com/eko/gocache/store/go_cache/v4 v4.2.2
	github.com/eko/gocache/store/redis/v4 v4.2.2
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.4
	github.com/google/go-cmp v0.7.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.0.2-0.20240212192251-757544f21357
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2
	github.com/hashicorp/go-version v1.7.0
	github.com/jackc/pgx/v5 v5.9.2
	github.com/libdns/route53 v1.5.0
	github.com/miekg/dns v1.1.72
	github.com/netbirdio/management-integrations/integrations v0.0.0-20260416123949-2355d972be42
	github.com/oapi-codegen/runtime v1.1.2
	github.com/okta/okta-sdk-golang/v2 v2.18.0
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.34.1
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/petermattis/goid v0.0.0-20250303134427-723919f7f203
	github.com/prometheus/client_golang v1.23.2
	github.com/redis/go-redis/v9 v9.7.3
	github.com/rs/cors v1.8.0
	github.com/rs/xid v1.3.0
	github.com/sirupsen/logrus v1.9.4
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	github.com/testcontainers/testcontainers-go v0.37.0
	github.com/testcontainers/testcontainers-go/modules/mysql v0.37.0
	github.com/testcontainers/testcontainers-go/modules/postgres v0.37.0
	github.com/testcontainers/testcontainers-go/modules/redis v0.37.0
	github.com/vmihailenco/msgpack/v5 v5.4.1
	go.opentelemetry.io/otel v1.43.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.43.0
	go.opentelemetry.io/otel/exporters/prometheus v0.64.0
	go.opentelemetry.io/otel/metric v1.43.0
	go.opentelemetry.io/otel/sdk v1.43.0
	go.opentelemetry.io/otel/sdk/metric v1.43.0
	go.opentelemetry.io/otel/trace v1.43.0
	go.uber.org/mock v0.6.0
	go.uber.org/zap v1.27.0
	goauthentik.io/api/v3 v3.2023051.3
	golang.org/x/crypto v0.56.0
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f
	golang.org/x/mod v0.38.0
	golang.org/x/net v0.57.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sys v0.47.0
	golang.org/x/time v0.15.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	golang.zx2c4.com/wireguard/windows v0.5.3
	google.golang.org/api v0.276.0
	google.golang.org/grpc v1.82.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/driver/mysql v1.5.7
	gorm.io/driver/postgres v1.5.7
	gorm.io/driver/sqlite v1.5.7
	gorm.io/gorm v1.25.12
)

require (
	cloud.google.com/go/auth v0.20.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	dario.cat/mergo v1.0.2 // indirect
	filippo.io/edwards25519 v1.1.1 // indirect
	github.com/AppsFlyer/go-sundheit v0.6.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/Azure/go-ntlmssp v0.1.0 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.38.3 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.31.6 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.18.10 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.42.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.29.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.34.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.38.2 // indirect
	github.com/aws/smithy-go v1.23.0 // indirect
	github.com/beevik/etree v1.6.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/caddyserver/zerossl v0.1.3 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/cpuguy83/dockercfg v0.3.2 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/docker v28.0.1+incompatible // indirect
	github.com/docker/go-connections v0.6.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.9.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/go-ldap/ldap/v3 v3.4.13 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-sql-driver/mysql v1.9.3 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.16.4 // indirect
	github.com/go-webauthn/x v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.14 // indirect
	github.com/googleapis/gax-go/v2 v2.21.0 // indirect
	github.com/gorilla/handlers v1.5.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-7 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/klauspost/compress v1.18.3 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/lib/pq v1.12.3 // indirect
	github.com/libdns/libdns v0.2.2 // indirect
	github.com/lufia/plan9stats v0.0.0-20240513124658-fba389f38bae // indirect
	github.com/magiconair/properties v1.8.10 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.42 // indirect
	github.com/mdelapenya/tlscert v0.2.0 // indirect
	github.com/mholt/acmez/v2 v2.0.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/patternmatcher v0.6.0 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/user v0.3.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nxadm/tail v1.4.11 // indirect
	github.com/openbao/openbao/api/v2 v2.5.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/pquerna/otp v1.5.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/otlptranslator v1.0.0 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/russellhaering/goxmldsig v1.6.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/shirou/gopsutil/v4 v4.25.8 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/tinylib/msgp v1.6.3 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.67.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.43.0 // indirect
	go.opentelemetry.io/proto/otlp v1.10.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gotest.tools/v3 v3.5.2 // indirect
)

replace github.com/kardianos/service => github.com/netbirdio/service v0.0.0-20240911161631-f62744f42502

replace github.com/getlantern/systray => github.com/netbirdio/systray v0.0.0-20231030152038-ef1ed2a27949

replace golang.zx2c4.com/wireguard => github.com/netbirdio/wireguard-go v0.0.0-20260628102922-2834bebf6c1a

replace github.com/pion/ice/v4 => github.com/netbirdio/ice/v4 v4.0.0-20250908184934-6202be846b51

replace github.com/dexidp/dex => github.com/netbirdio/dex v0.244.1-0.20260716205454-a163de3129e5

replace github.com/dexidp/dex/api/v2 => github.com/netbirdio/dex/api/v2 v2.0.0-20260512110716-8d70ad8647c1

replace github.com/mailru/easyjson => github.com/netbirdio/easyjson v0.9.0

replace github.com/wailsapp/wails/v3 => github.com/netbirdio/wails/v3 v3.0.0-beta.3.0.20260807055527-fc03f984d701
