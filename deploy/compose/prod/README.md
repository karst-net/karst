# Console TLS trust

Set `KARST_CONSOLE_HOST` to the hostname or IP used in the browser, without
scheme or port. Set `KARST_CONSOLE_ORIGIN` to the corresponding full origin,
for example `https://203.0.113.7:33073`. For IPv6, bracket the address in
`KARST_CONSOLE_HOST` as well as in the origin. Use that same address when
opening the console: trusting a CA does not bypass hostname validation.

Caddy issues and renews the server certificate using its internal CA. Its
signing identity is persistent because Compose mounts `./state/caddy` at
`/data`. Leaf certificates are short-lived and renew automatically; trusting
an individual leaf through a browser exception therefore causes recurring
warnings. Trust the CA root instead. The same root signs replacement leaves
and survives container restarts and recreation.

After starting Caddy, copy **only** the public root certificate from the
server to each client over a trusted channel:

```sh
cd deploy/compose/prod
sudo cp state/caddy/caddy/pki/authorities/local/root.crt karst-console-root.crt
openssl x509 -in karst-console-root.crt -noout -subject -dates -fingerprint -sha256
```

Compare the SHA-256 fingerprint on the client with the server's output before
trusting it. On macOS, import the file into Keychain Access's System keychain
and set its SSL trust to Always Trust, or run on the client:

```sh
sudo security add-trusted-cert -d -r trustRoot -p ssl \
  -k /Library/Keychains/System.keychain karst-console-root.crt
```

On Windows, import it into Trusted Root Certification Authorities. On Linux,
use the distribution's CA installation mechanism. Browsers with a separate
trust store also need this root imported into that store. Restart the browser
and visit the configured origin. Do not distribute `root.key` or other
private keys.

Preserve and securely back up `state/caddy` with the deployment state. Deleting
it creates a new CA and requires trusting a new root on every client. Existing
deployments retain their current CA when applying this configuration change;
there is no need to delete state or lengthen server-certificate lifetimes.

Validate and apply the configuration from this directory:

```sh
docker compose run --rm --no-deps caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker compose up -d --force-recreate caddy
```

From a client with the copied root, verify the chain and address without
bypassing verification:

```sh
curl --cacert karst-console-root.crt https://203.0.113.7:33073/config.json
```

Repeat after recreating Caddy; the root fingerprint should remain unchanged
and this request should still validate. Substitute your real origin above.
