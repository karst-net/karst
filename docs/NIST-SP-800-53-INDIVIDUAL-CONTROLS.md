<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# NIST SP 800-53 individual-control mapping

This index supplements [the Karst NIST control mapping](NIST-SP-800-53-CONTROL-MAPPING.md).
It maps individual controls and selected control enhancements, rather than
treating an entire control family as a single item.

## How to read the impact columns

SP 800-53B's Low, Moderate, and High columns are **baseline selections**, not
product ratings. A check mark says NIST selects that exact control or
enhancement in that security baseline; `—` says it is not selected by the
baseline (though an organization can select it through tailoring). The Karst
mapping state is separate, so a check mark never by itself means Karst or a
deployment is compliant.

| Mark | Meaning |
| --- | --- |
| **✓** | Selected in the NIST SP 800-53B Low, Moderate, or High baseline. |
| **—** | Not selected in that baseline. |
| **Direct** | Karst technically enforces or provides evidence for a material part. |
| **Shared** | Karst contributes, but the organization or another system completes it. |
| **External** | Karst must not receive credit for the function. |

Identifiers use leading zeroes and parenthesized enhancements: `AC-01`,
`AC-06(02)`. Selections were transcribed from the NIST SP 800-53B Release
5.2.0 OSCAL profiles. NIST states that 5.2.0 did not change the baselines;
recheck these values whenever the catalog or an overlay changes.

## Control index

| Individual control | Low | Moderate | High | Karst contribution |
| --- | :---: | :---: | :---: | --- |
| AC-01 Access Control Policy and Procedures | ✓ | ✓ | ✓ | External — organization policy and review process. |
| AC-02 Account Management | ✓ | ✓ | ✓ | Shared — IdP/SCIM lifecycle, roles, node revocation, audit. |
| AC-02(01) Automated System Account Management | — | ✓ | ✓ | Shared — SCIM/IdP can supply automation; governance remains external. |
| AC-02(02) Automated Temporary/Emergency Account Management | — | ✓ | ✓ | Shared — short-lived enrollment credentials help; account policy is external. |
| AC-02(03) Disable Accounts | — | ✓ | ✓ | Shared — Karst blocks/deprovisions accounts and revokes devices. |
| AC-02(04) Automated Audit Actions | — | ✓ | ✓ | Direct for Karst lifecycle changes; external for other systems. |
| AC-02(05) Inactivity Logout | — | ✓ | ✓ | External — IdP and application sessions own this function. |
| AC-02(11) Usage Conditions | — | — | ✓ | External. |
| AC-02(12) Atypical Usage | — | — | ✓ | Shared — telemetry input; detection workflow external. |
| AC-02(13) High-risk Individuals | — | ✓ | ✓ | Shared — organization decision plus disablement. |
| AC-03 Access Enforcement | ✓ | ✓ | ✓ | Direct — default-deny identity/group, destination, and port ACLs. |
| AC-04 Information Flow Enforcement | — | ✓ | ✓ | Direct — ACLs and route/gateway forwarding restrictions. |
| AC-04(04) Flow Control of Encrypted Information | — | — | ✓ | Shared — no application-content policy inspection. |
| AC-05 Separation of Duties | — | ✓ | ✓ | Shared — administrator, auditor, relay, and Bedrock roles. |
| AC-06 Least Privilege | — | ✓ | ✓ | Direct for overlay reachability; shared for host/application privilege. |
| AC-06(01) Access to Security Functions | — | ✓ | ✓ | Shared — administrative roles restrict Karst functions. |
| AC-06(02) Non-privileged Access for Nonsecurity Functions | — | ✓ | ✓ | Shared — user/admin roles; host/application behavior external. |
| AC-06(03) Network Access to Privileged Commands | — | — | ✓ | External — no host command authorization. |
| AC-06(05) Privileged Accounts | — | ✓ | ✓ | Shared — distinct roles; governance external. |
| AC-06(07) Review of User Privileges | — | ✓ | ✓ | Shared — history is evidence; review cadence external. |
| AC-06(09) Log Privileged Functions | — | ✓ | ✓ | Direct for Karst administration. |
| AC-06(10) Prohibit Privileged Functions | — | ✓ | ✓ | Direct for Karst administration; external for host/apps. |
| AC-17 Remote Access | ✓ | ✓ | ✓ | Shared — protected transport; approval and endpoint management external. |
| AC-17(01) Automated Monitoring and Control | — | ✓ | ✓ | Shared — telemetry/policy input; monitoring workflow external. |
| AC-17(02) Encryption | — | ✓ | ✓ | Direct for overlay traffic. |
| AC-17(03) Managed Access Control Points | — | ✓ | ✓ | Shared — routers/exit nodes; operation external. |
| AC-17(04) Privileged Commands and Access | — | ✓ | ✓ | External. |
| AU-01 Audit Policy and Procedures | ✓ | ✓ | ✓ | External. |
| AU-02 Event Logging | ✓ | ✓ | ✓ | Direct for Karst administrative/security events; shared overall. |
| AU-03 Content of Audit Records | ✓ | ✓ | ✓ | Direct for Karst records. |
| AU-03(01) Additional Audit Information | — | ✓ | ✓ | Shared. |
| AU-06 Audit Review, Analysis, and Reporting | ✓ | ✓ | ✓ | Shared — auditor role, filtering, verification, export, SIEM sink. |
| AU-06(01) Automated Process Integration | — | ✓ | ✓ | Shared — SIEM integration; alert handling external. |
| AU-06(03) Correlate Audit Repositories | — | ✓ | ✓ | Shared — external SIEM correlation required. |
| AU-06(05) Integrated Audit Analysis | — | — | ✓ | External. |
| AU-06(06) Physical Monitoring Correlation | — | — | ✓ | External. |
| AU-09 Protection of Audit Information | ✓ | ✓ | ✓ | Shared — hash chain/auditor role; independent retention external. |
| AU-09(02) Separate Storage | — | — | ✓ | Shared — independent audit sink. |
| AU-09(03) Cryptographic Protection | — | — | ✓ | Shared — sink/storage encryption and custody external. |
| AU-09(04) Privileged-user Subset | — | ✓ | ✓ | Direct for auditor-role separation. |
| AU-12 Audit Record Generation | ✓ | ✓ | ✓ | Direct for Karst events; shared overall. |
| AU-12(01) System-wide Trail | — | — | ✓ | External — Karst is not system-wide audit. |
| AU-12(03) Authorized Changes | — | — | ✓ | Direct for Karst changes; shared overall. |
| CA-07 Continuous Monitoring | ✓ | ✓ | ✓ | Shared — Karst telemetry; monitoring program/response external. |
| CA-07(01) Independent Assessment | — | ✓ | ✓ | External. |
| CA-07(04) Risk Monitoring | ✓ | ✓ | ✓ | Shared — telemetry input; risk decisions external. |
| CM-01 Configuration Management Policy and Procedures | ✓ | ✓ | ✓ | External. |
| CM-03 Configuration Change Control | — | ✓ | ✓ | Shared — versioning/audit/rollback; approvals external. |
| CM-03(01) Automated Documentation and Notification | — | — | ✓ | Shared. |
| CM-03(02) Testing and Validation | — | ✓ | ✓ | Shared. |
| CM-03(04) Security/Privacy Representatives | — | ✓ | ✓ | External. |
| CM-03(06) Cryptography Management | — | — | ✓ | Shared — protocol design; governance external. |
| CM-05 Access Restrictions for Change | ✓ | ✓ | ✓ | Shared — authorization; host/infrastructure control external. |
| CM-05(01) Automated Access Enforcement/Auditing | — | — | ✓ | Direct for Karst administration; shared overall. |
| IA-01 Identification and Authentication Policy and Procedures | ✓ | ✓ | ✓ | External. |
| IA-02 Organizational Users | ✓ | ✓ | ✓ | Shared — IdP authenticates; Karst maps roles/groups. |
| IA-02(01) MFA to Privileged Accounts | ✓ | ✓ | ✓ | External — IdP configuration. |
| IA-02(02) MFA to Non-privileged Accounts | ✓ | ✓ | ✓ | External — IdP configuration. |
| IA-02(05) Individual Authentication with Group Authentication | — | — | ✓ | External. |
| IA-02(08) Replay-resistant Authentication | ✓ | ✓ | ✓ | Shared — IdP requirement; node protocol separately authenticated. |
| IA-02(12) PIV Credentials | ✓ | ✓ | ✓ | External. |
| IA-03 Device Identification and Authentication | — | ✓ | ✓ | Direct — node identities and peer authentication. |
| IA-05 Authenticator Management | ✓ | ✓ | ✓ | Shared — Karst keys/enrollment material; IdP authenticators external. |
| IA-05(01) Password Authentication | ✓ | ✓ | ✓ | External. |
| IA-05(02) Public-key Authentication | — | ✓ | ✓ | Direct for Karst keys; shared for human identities. |
| IA-05(06) Authenticator Protection | — | ✓ | ✓ | Shared — local sealing/offline custody; platform protection external. |
