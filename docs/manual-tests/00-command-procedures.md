<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Manual tests: command procedures

This is the executable companion to the scenario matrices. Replace values in
angle brackets. Do not enter real credentials, private keys, PSKs, or bundles
into shell history or attach them to a result.

## Test setup and common probes

On each Linux client, set non-secret labels, then capture the baseline:

```sh
export KARST_ZONE='<mesh-zone>'
export BOB_OVERLAY='<bob-overlay-ip>'
export ALLOWED_PORT=18080
sudo systemctl status karstd karst-control karst-relay --no-pager
sudo karst status
```

On Bob, start the test echo service. Leave it running:

```sh
sudo ncat -lk "$ALLOWED_PORT" --keep-open --exec /bin/cat
```

From Alice, this is the allowed-traffic probe used below:

```sh
printf 'karst-manual-test\n' | nc -w 5 "$BOB_OVERLAY" "$ALLOWED_PORT"
sudo karst status
```

The response must equal `karst-manual-test`. If `ncat` is unavailable, use the
local `nc -lk` equivalent and record its implementation.

## FND-01 through FND-05: control and relay

### FND-01 — bootstrap and default deny

1. Restart the control service and require it to be active and listening:

   ```sh
   sudo systemctl restart karst-control
   sudo systemctl is-active karst-control
   sudo ss -ltnp | grep ':33073'
   sudo journalctl -u karst-control -n 100 --no-pager | grep 'karst: server'
   ```

2. Record the two public pin lines. Restart again, extract the last pin lines,
   and compare values; they must not change.

   ```sh
   sudo systemctl restart karst-control
   sudo journalctl -u karst-control --no-pager | grep 'karst: server' | tail -2
   ```

3. Apply the disposable empty/default-deny policy in the Console (**Access** →
   **Edit policy** → **Validate** → **Save**). Run the common traffic probe;
   it must time out. Restore the approved policy immediately.

### FND-02, FND-06, FND-07 — enrollment, wrong pins, reuse

1. In Console go to **Auth keys** → **Create key**. Set one use and the
   shortest usable expiry. Deliver the resulting credential only through the
   protected enrollment bundle path.
2. On a clean client run:

   ```sh
   sudo karst enroll --bundle /secure/path/<device>.bundle
   sudo systemctl enable --now karstd
   sudo karst status
   ```

3. In **Machines**, verify exactly one new device. In `status`, require a
   non-empty address list and `[policy] enforcing = true`.
4. Repeat the `karst enroll` command with the same bundle, then revoke the key
   in Console and repeat once more. Both must fail and Machines must not gain a
   device.
5. For each pin, back up the test config, change *only* that pin, validate and
   restart, collect the rejection, then restore the original:

   ```sh
   sudo cp /etc/karst/karstd.toml /etc/karst/karstd.toml.test-save
   sudoedit /etc/karst/karstd.toml
   sudo karstd check --config /etc/karst/karstd.toml
   sudo systemctl restart karstd
   sudo journalctl -u karstd -n 80 --no-pager
   sudo mv /etc/karst/karstd.toml.test-save /etc/karst/karstd.toml
   sudo systemctl restart karstd
   ```

### FND-03 through FND-05 — relay configuration and admission

1. On the relay host:

   ```sh
   sudo karst-relay check --config /etc/karst/relay.toml
   sudo karst-relay pubkey --config /etc/karst/relay.toml
   sudo systemctl status karst-relay --no-pager
   ```

2. In **Relays** select **Add relay**. Enter the numeric `IP:port`, TLS name,
   printed `identity_pk`, and region, then save. Wait for roster refresh and
   validate it.

   ```sh
   sleep 30
   sudo stat /etc/karst/roster.toml
   sudo karst-relay check --config /etc/karst/relay.toml
   ```

3. Attempt to save `relay.example.test:443` as the address; it must be rejected.
   In a disposable entry use a wrong TLS name and, separately, a wrong identity.
   Restart a test node and confirm relay authentication fails.
4. Stop control; after 95 seconds inspect relay logs for roster lease expiry.
   Start control, wait 30 seconds, and repeat `karst-relay check` to prove
   recovery.

   ```sh
   sudo systemctl stop karst-control
   sleep 95
   sudo journalctl -u karst-relay -n 100 --no-pager
   sudo systemctl start karst-control
   sleep 30
   sudo karst-relay check --config /etc/karst/relay.toml
   ```

## FND-08 through FND-12: lifecycle, paths, and policy

1. In **Machines**, rename a disposable node, save and refresh; deprovision it
   and run `sudo karst status` on that node. It must have no active authorized
   session. Never deprovision a shared traffic-test node.
2. In **Access**, save a policy allowing only Alice → Bob TCP `$ALLOWED_PORT`.
   Run the common probe and retain both nodes' status output.
3. For relay fallback, block direct UDP only (substitute the node listener
   port; do not block TCP 443), then run the probe and inspect status:

   ```sh
   sudo nft add table inet karst_manual
   sudo nft 'add chain inet karst_manual output { type filter hook output priority 0; policy accept; }'
   sudo nft add rule inet karst_manual output udp dport <peer-udp-port> drop
   # run the common probe; status must say transport = relay
   sudo nft delete table inet karst_manual
   ```

4. Exercise allowed TCP, a denied TCP port, and denied UDP; record all exit
   codes and ACL counters:

   ```sh
   nc -zvw 5 "$BOB_OVERLAY" "$ALLOWED_PORT"
   nc -zvw 5 "$BOB_OVERLAY" $((ALLOWED_PORT + 1))
   nc -zuv -w 5 "$BOB_OVERLAY" "$ALLOWED_PORT"
   sudo karst metrics | grep 'karst_acl_denied'
   ```

5. Leave permitted traffic active, then restart control and Alice's daemon.
   The node must safely reconnect and reapply current policy:

   ```sh
   sudo systemctl restart karst-control
   sudo systemctl restart karstd
   sudo karst status
   ```

## CLI-01 through CLI-05: client package and control surface

1. On a disposable VM install the release artifact with the platform installer:
   Linux: `sudo apt install ./<package>.deb` or `sudo dnf install ./<package>.rpm`;
   macOS: open the signed `.pkg`; Windows: run the MSI elevated. Record version
   and publisher/signature verification.
2. Reboot. On Linux inspect the installed service and tunnel; on macOS use
   `sudo launchctl print system/<service-label>`, `ifconfig`, `netstat -rn`; on
   Windows use elevated PowerShell `Get-Service *karst*`, `Get-NetAdapter`,
   `Get-NetIPAddress`, and `Get-NetRoute`.

   ```sh
   sudo systemctl is-enabled karstd
   sudo systemctl is-active karstd
   ip link show karst0
   ip addr show dev karst0
   ip route show
   ```

3. Exercise every local CLI action:

   ```sh
   sudo karst status
   sudo karst version
   sudo karst metrics | head -40
   sudo karst down
   sudo karst status; test $? -ne 0
   sudo systemctl start karstd
   ```

4. Interrupt desktop setup after identity creation. Reopen Karst Setup and use
   **Retry**, or run `karst setup --resume`. Feed malformed test text to
   `karst setup --stdin`; it must fail without creating a device.
5. Uninstall, reboot, and prove normal DNS/networking still works. Retain
   before/after service and resolver evidence.

## CLI-03 and NET-01 through NET-04: userspace and DNS

1. Put this in a disposable userspace config, validate/start it through the
   documented service path, and prove it did not create a TUN interface:

   ```toml
   [node]
   network_mode = "userspace"
   userspace_socks5_listen = "127.0.0.1:1080"
   ```

   ```sh
   karstd check --config <userspace-config>
   ip link show karst0; test $? -ne 0
   karst dns status
   curl --socks5-hostname 127.0.0.1:1080 http://<overlay-ip>:<port>/
   ```

2. Save resolver state and test mesh, missing mesh, and public resolution:

   ```sh
   sudo cp -a /etc/resolv.conf /tmp/karst-resolv.conf.before
   sudo karst dns status
   sudo karst dns query "<bob-name>.$KARST_ZONE"
   getent hosts "<bob-name>.$KARST_ZONE"
   sudo karst dns query "missing.$KARST_ZONE"
   sudo karst dns query example.com
   ```

3. In **DNS**, add a nameserver group with `<split-zone>` and `<upstream-ip>`
   assigned only to the test group. Use `karst dns query` for matching and
   nonmatching names and retain upstream query logs. Stop that upstream and
   repeat the matching query: it must be SERVFAIL, not a global fallback.
4. Stop `karstd`, apply DNS recovery, compare the saved resolver, then restart:

   ```sh
   sudo systemctl stop karstd
   sudo karst dns revert --config /etc/karst/karstd.toml
   cmp /tmp/karst-resolv.conf.before /etc/resolv.conf || true
   sudo systemctl start karstd
   ```

## NET-05 through NET-07: routers and exit routes

1. On the disposable Linux gateway enable forwarding, then inspect live state:

   ```sh
   sudo sysctl -w net.ipv4.ip_forward=1
   sudo karst status
   sudo nft list table inet karst_routes
   ```

2. In **Routes** → **Add route**, enter `<test-cidr>`, gateway, recipient and
   access groups, metric, and masquerade; save. On an allowed client run `ip
   route show <test-cidr>` and probe a LAN test service. On a forbidden client,
   no route or connectivity may be present.
3. Add a separate `0.0.0.0/0` exit route. Confirm no automatic selection, then
   select and withdraw it explicitly:

   ```sh
   sudo karst exit-node list
   ip rule show
   curl -4 https://ifconfig.me/ip
   sudo karst exit-node use <route-id>
   sudo karst status
   ip rule show
   curl -4 https://ifconfig.me/ip
   sudo karst exit-node disable
   ip rule show
   ```

4. Disable/delete the route in Console during a probe, confirm removal and no
   black-hole default route, recreate it, and confirm recovery. Restore the
   forwarding sysctl to its prior value.

## ADM-01 through ADM-11: Console and portal

Use a separate private browser window for each role; preserve no bearer tokens.

1. Sign in as admin and visit **Setup**, **Machines**, **Auth keys**, **Users**,
   **Groups**, and **Audit**. Sign out. Repeat as Alice and auditor; request a
   console URL as Alice and a mutating control as auditor. Both must be denied.
2. In **Users** → **Invite user**, enter a disposable address, role and
   auto-groups → **Send**. Change role/groups, **Block**, verify login denial,
   **Unblock**, then **Deprovision** and verify access remains denied.
3. In **Groups** → **Add group**, create `manual-test-group`, add Alice, save,
   rename, save, and delete. Attempt edits to `All` and an IdP group; they must
   not yield a mutation.
4. In **Auth keys** create one-use, short-expiry, and ephemeral keys. Consume
   only the one-use key, refresh its status, then revoke/delete all three. In
   **Machines**, filter, rename/save, then deprovision a disposable device.
5. In **Access** edit the disposable policy; use **Validate**, **Preview diff**,
   and **Test** for an allowed and denied tuple before **Save**. Submit a syntax
   error, then save a second version and use **Rollback**. Prove behavior with
   the FND-11 probes.
6. In **DNS**, add/edit/delete a nameserver group and excluded group; submit a
   malformed upstream and retain the error. In **Routes** and **Relays**, create,
   toggle/edit/delete only disposable entries, completing NET-05/06 and FND-03.
7. As Alice use **My devices** → **Add device**, enroll a clean endpoint, then
   rename and revoke it. As Bob request Alice's copied device API path; require
   a server-side forbidden response. Compare **My access** and **Sessions**
   before/after a policy change and revocation. Use **Download** to complete a
   clean-client installation.
8. Keyboard-only, reload each route, use `Tab` to activate the skip link, and
   navigate every control. Trigger required-field validation, empty state,
   forbidden action, and test-only server error; record focus and recovery.

## OPS-01 through OPS-09: Bedrock and operations

On an offline signer with media at `/media/hsm`, run this exact genesis ceremony:

```sh
umask 077
karst-bedrock init root /media/hsm/root-a.key
karst-bedrock init root /media/hsm/root-b.key
karst-bedrock init root /media/hsm/root-c.key
karst-bedrock init authority /media/hsm/authority-a.key
karst-bedrock init authority /media/hsm/authority-b.key
karst-bedrock init authority /media/hsm/authority-c.key
karst-bedrock genesis-request /tmp/genesis.json "$KARST_ZONE" 2 \
  /media/hsm/root-a.key.pub /media/hsm/root-b.key.pub /media/hsm/root-c.key.pub -- \
  2 /media/hsm/authority-a.key.pub /media/hsm/authority-b.key.pub /media/hsm/authority-c.key.pub
karst-bedrock inspect /tmp/genesis.json
karst-bedrock sign /tmp/genesis.json /media/hsm/root-a.key /tmp/root-a.response
karst-bedrock sign /tmp/genesis.json /media/hsm/root-b.key /tmp/root-b.response
karst-bedrock combine /tmp/genesis.json /tmp/genesis.bedrock /tmp/root-a.response /tmp/root-b.response
karst-bedrock verify /tmp/genesis.bedrock
```

Type confirmation only after the rendered signing summary is correct. In
**Network lock**, import the bundle and choose advisory. Upload an altered copy
and a below-quorum copy; each must fail without advancing the head. Switch to
enforcing with acknowledgment and prove uncovered enrollment and online mode
downgrade fail.

For audit/posture/metrics/telemetry/diagnostics: perform one disposable user,
policy, device, relay and Bedrock action; filter and verify **Audit**, export to
the test SIEM, and compare sink logs. In **Crypto posture**, compare direct and
relay rows to `karst status` and export CSV. Before and after an enrollment,
netmap push, relay path and denied flow, run:

```sh
curl -fsS http://127.0.0.1:9090/metrics | grep '^management_karst_'
sudo karst metrics | grep '^karst_'
curl -fsS http://127.0.0.1:9091/metrics  # only when node listener is enabled
sudo karst bugreport > /tmp/karst-bugreport.txt
if grep -Ein 'psk|private.?key|setup.?key|secret|token' /tmp/karst-bugreport.txt; then exit 1; fi
```

Enable relay telemetry only in test configuration, restart relay, connect and
disconnect a client, stop control for one reporting interval, restore it, and
verify forwarding plus telemetry recovery. Review the bug report locally: it
may name redaction but must never include an actual secret or full config.

## Cleanup

```sh
sudo nft delete table inet karst_manual 2>/dev/null || true
sudo systemctl start karst-control karst-relay karstd
sudo karst dns revert --config /etc/karst/karstd.toml
sudo karst exit-node disable 2>/dev/null || true
```

Delete only named disposable objects, restore the approved policy/resolver and
forwarding setting, and remove protected `/tmp` captures under the local data
handling policy.

