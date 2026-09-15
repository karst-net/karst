<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# NIST SP 800-53 individual-control mapping

This index supplements [the Karst NIST control mapping](NIST-SP-800-53-CONTROL-MAPPING.md).
It maps individual controls and selected control enhancements, rather than
treating an entire control family as a single item. For engineering detail,
see [NIST-SP-800-53-IMPLEMENTATION-CROSSWALK.md](NIST-SP-800-53-IMPLEMENTATION-CROSSWALK.md).

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
| [AC-01](https://csrc.nist.gov/projects/cprt/catalog) Access Control Policy and Procedures | ✓ | ✓ | ✓ | External — organization policy and review process. |
| [AC-02](https://csrc.nist.gov/projects/cprt/catalog) Account Management | ✓ | ✓ | ✓ | Shared — IdP/SCIM lifecycle, roles, node revocation, audit. |
| [AC-02(01)](https://csrc.nist.gov/projects/cprt/catalog) Automated System Account Management | — | ✓ | ✓ | Shared — SCIM/IdP can supply automation; governance remains external. |
| [AC-02(02)](https://csrc.nist.gov/projects/cprt/catalog) Automated Temporary/Emergency Account Management | — | ✓ | ✓ | Shared — short-lived enrollment credentials help; account policy is external. |
| [AC-02(03)](https://csrc.nist.gov/projects/cprt/catalog) Disable Accounts | — | ✓ | ✓ | Shared — Karst blocks/deprovisions accounts and revokes devices. |
| [AC-02(04)](https://csrc.nist.gov/projects/cprt/catalog) Automated Audit Actions | — | ✓ | ✓ | Direct for Karst lifecycle changes; external for other systems. |
| [AC-02(05)](https://csrc.nist.gov/projects/cprt/catalog) Inactivity Logout | — | ✓ | ✓ | External — IdP and application sessions own this function. |
| [AC-02(11)](https://csrc.nist.gov/projects/cprt/catalog) Usage Conditions | — | — | ✓ | External. |
| [AC-02(12)](https://csrc.nist.gov/projects/cprt/catalog) Atypical Usage | — | — | ✓ | Shared — telemetry input; detection workflow external. |
| [AC-02(13)](https://csrc.nist.gov/projects/cprt/catalog) High-risk Individuals | — | ✓ | ✓ | Shared — organization decision plus disablement. |
| [AC-03](https://csrc.nist.gov/projects/cprt/catalog) Access Enforcement | ✓ | ✓ | ✓ | Direct — default-deny identity/group, destination, and port ACLs. |
| [AC-04](https://csrc.nist.gov/projects/cprt/catalog) Information Flow Enforcement | — | ✓ | ✓ | Direct — ACLs and route/gateway forwarding restrictions. |
| [AC-04(04)](https://csrc.nist.gov/projects/cprt/catalog) Flow Control of Encrypted Information | — | — | ✓ | Shared — no application-content policy inspection. |
| [AC-05](https://csrc.nist.gov/projects/cprt/catalog) Separation of Duties | — | ✓ | ✓ | Shared — administrator, auditor, relay, and Bedrock roles. |
| [AC-06](https://csrc.nist.gov/projects/cprt/catalog) Least Privilege | — | ✓ | ✓ | Direct for overlay reachability; shared for host/application privilege. |
| [AC-06(01)](https://csrc.nist.gov/projects/cprt/catalog) Access to Security Functions | — | ✓ | ✓ | Shared — administrative roles restrict Karst functions. |
| [AC-06(02)](https://csrc.nist.gov/projects/cprt/catalog) Non-privileged Access for Nonsecurity Functions | — | ✓ | ✓ | Shared — user/admin roles; host/application behavior external. |
| [AC-06(03)](https://csrc.nist.gov/projects/cprt/catalog) Network Access to Privileged Commands | — | — | ✓ | External — no host command authorization. |
| [AC-06(05)](https://csrc.nist.gov/projects/cprt/catalog) Privileged Accounts | — | ✓ | ✓ | Shared — distinct roles; governance external. |
| [AC-06(07)](https://csrc.nist.gov/projects/cprt/catalog) Review of User Privileges | — | ✓ | ✓ | Shared — history is evidence; review cadence external. |
| [AC-06(09)](https://csrc.nist.gov/projects/cprt/catalog) Log Privileged Functions | — | ✓ | ✓ | Direct for Karst administration. |
| [AC-06(10)](https://csrc.nist.gov/projects/cprt/catalog) Prohibit Privileged Functions | — | ✓ | ✓ | Direct for Karst administration; external for host/apps. |
| [AC-17](https://csrc.nist.gov/projects/cprt/catalog) Remote Access | ✓ | ✓ | ✓ | Shared — protected transport; approval and endpoint management external. |
| [AC-17(01)](https://csrc.nist.gov/projects/cprt/catalog) Automated Monitoring and Control | — | ✓ | ✓ | Shared — telemetry/policy input; monitoring workflow external. |
| [AC-17(02)](https://csrc.nist.gov/projects/cprt/catalog) Encryption | — | ✓ | ✓ | Direct for overlay traffic. |
| [AC-17(03)](https://csrc.nist.gov/projects/cprt/catalog) Managed Access Control Points | — | ✓ | ✓ | Shared — routers/exit nodes; operation external. |
| [AC-17(04)](https://csrc.nist.gov/projects/cprt/catalog) Privileged Commands and Access | — | ✓ | ✓ | External. |
| [AU-01](https://csrc.nist.gov/projects/cprt/catalog) Audit Policy and Procedures | ✓ | ✓ | ✓ | External. |
| [AU-02](https://csrc.nist.gov/projects/cprt/catalog) Event Logging | ✓ | ✓ | ✓ | Direct for Karst administrative/security events; shared overall. |
| [AU-03](https://csrc.nist.gov/projects/cprt/catalog) Content of Audit Records | ✓ | ✓ | ✓ | Direct for Karst records. |
| [AU-03(01)](https://csrc.nist.gov/projects/cprt/catalog) Additional Audit Information | — | ✓ | ✓ | Shared. |
| [AU-06](https://csrc.nist.gov/projects/cprt/catalog) Audit Review, Analysis, and Reporting | ✓ | ✓ | ✓ | Shared — auditor role, filtering, verification, export, SIEM sink. |
| [AU-06(01)](https://csrc.nist.gov/projects/cprt/catalog) Automated Process Integration | — | ✓ | ✓ | Shared — SIEM integration; alert handling external. |
| [AU-06(03)](https://csrc.nist.gov/projects/cprt/catalog) Correlate Audit Repositories | — | ✓ | ✓ | Shared — external SIEM correlation required. |
| [AU-06(05)](https://csrc.nist.gov/projects/cprt/catalog) Integrated Audit Analysis | — | — | ✓ | External. |
| [AU-06(06)](https://csrc.nist.gov/projects/cprt/catalog) Physical Monitoring Correlation | — | — | ✓ | External. |
| [AU-09](https://csrc.nist.gov/projects/cprt/catalog) Protection of Audit Information | ✓ | ✓ | ✓ | Shared — hash chain/auditor role; independent retention external. |
| [AU-09(02)](https://csrc.nist.gov/projects/cprt/catalog) Separate Storage | — | — | ✓ | Shared — independent audit sink. |
| [AU-09(03)](https://csrc.nist.gov/projects/cprt/catalog) Cryptographic Protection | — | — | ✓ | Shared — sink/storage encryption and custody external. |
| [AU-09(04)](https://csrc.nist.gov/projects/cprt/catalog) Privileged-user Subset | — | ✓ | ✓ | Direct for auditor-role separation. |
| [AU-12](https://csrc.nist.gov/projects/cprt/catalog) Audit Record Generation | ✓ | ✓ | ✓ | Direct for Karst events; shared overall. |
| [AU-12(01)](https://csrc.nist.gov/projects/cprt/catalog) System-wide Trail | — | — | ✓ | External — Karst is not system-wide audit. |
| [AU-12(03)](https://csrc.nist.gov/projects/cprt/catalog) Authorized Changes | — | — | ✓ | Direct for Karst changes; shared overall. |
| [CA-07](https://csrc.nist.gov/projects/cprt/catalog) Continuous Monitoring | ✓ | ✓ | ✓ | Shared — Karst telemetry; monitoring program/response external. |
| [CA-07(01)](https://csrc.nist.gov/projects/cprt/catalog) Independent Assessment | — | ✓ | ✓ | External. |
| [CA-07(04)](https://csrc.nist.gov/projects/cprt/catalog) Risk Monitoring | ✓ | ✓ | ✓ | Shared — telemetry input; risk decisions external. |
| [CM-01](https://csrc.nist.gov/projects/cprt/catalog) Configuration Management Policy and Procedures | ✓ | ✓ | ✓ | External. |
| [CM-03](https://csrc.nist.gov/projects/cprt/catalog) Configuration Change Control | — | ✓ | ✓ | Shared — versioning/audit/rollback; approvals external. |
| [CM-03(01)](https://csrc.nist.gov/projects/cprt/catalog) Automated Documentation and Notification | — | — | ✓ | Shared. |
| [CM-03(02)](https://csrc.nist.gov/projects/cprt/catalog) Testing and Validation | — | ✓ | ✓ | Shared. |
| [CM-03(04)](https://csrc.nist.gov/projects/cprt/catalog) Security/Privacy Representatives | — | ✓ | ✓ | External. |
| [CM-03(06)](https://csrc.nist.gov/projects/cprt/catalog) Cryptography Management | — | — | ✓ | Shared — protocol design; governance external. |
| [CM-05](https://csrc.nist.gov/projects/cprt/catalog) Access Restrictions for Change | ✓ | ✓ | ✓ | Shared — authorization; host/infrastructure control external. |
| [CM-05(01)](https://csrc.nist.gov/projects/cprt/catalog) Automated Access Enforcement/Auditing | — | — | ✓ | Direct for Karst administration; shared overall. |
| [IA-01](https://csrc.nist.gov/projects/cprt/catalog) Identification and Authentication Policy and Procedures | ✓ | ✓ | ✓ | External. |
| [IA-02](https://csrc.nist.gov/projects/cprt/catalog) Organizational Users | ✓ | ✓ | ✓ | Shared — IdP authenticates; Karst maps roles/groups. |
| [IA-02(01)](https://csrc.nist.gov/projects/cprt/catalog) MFA to Privileged Accounts | ✓ | ✓ | ✓ | External — IdP configuration. |
| [IA-02(02)](https://csrc.nist.gov/projects/cprt/catalog) MFA to Non-privileged Accounts | ✓ | ✓ | ✓ | External — IdP configuration. |
| [IA-02(05)](https://csrc.nist.gov/projects/cprt/catalog) Individual Authentication with Group Authentication | — | — | ✓ | External. |
| [IA-02(08)](https://csrc.nist.gov/projects/cprt/catalog) Replay-resistant Authentication | ✓ | ✓ | ✓ | Shared — IdP requirement; node protocol separately authenticated. |
| [IA-02(12)](https://csrc.nist.gov/projects/cprt/catalog) PIV Credentials | ✓ | ✓ | ✓ | External. |
| [IA-03](https://csrc.nist.gov/projects/cprt/catalog) Device Identification and Authentication | — | ✓ | ✓ | Direct — node identities and peer authentication. |
| [IA-05](https://csrc.nist.gov/projects/cprt/catalog) Authenticator Management | ✓ | ✓ | ✓ | Shared — Karst keys/enrollment material; IdP authenticators external. |
| [IA-05(01)](https://csrc.nist.gov/projects/cprt/catalog) Password Authentication | ✓ | ✓ | ✓ | External. |
| [IA-05(02)](https://csrc.nist.gov/projects/cprt/catalog) Public-key Authentication | — | ✓ | ✓ | Direct for Karst keys; shared for human identities. |
| [IA-05(06)](https://csrc.nist.gov/projects/cprt/catalog) Authenticator Protection | — | ✓ | ✓ | Shared — local sealing/offline custody; platform protection external. |
