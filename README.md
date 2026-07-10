# JIThunter 🏹
**Hunt JIT / PAM paths. Touch nothing.**
by **@Gromak123** (and **LLM** <3)

JIThunter is a **read-only Active Directory auditor** for **Just-In-Time (JIT) access / Privileged Access Management (PAM)**.
JIT leaves no single authoritative marker in AD, so JIThunter aggregates several signals and correlates them into a **posture + attack-surface** report: **who can grant privileged access**, **on what**, **who holds it right now**, and **where the JIT manager lives**. It binds to LDAP with a domain account and reads SYSVOL over SMB — nothing else. Beautiful **Rich** console output, plus **CSV / JSON / HTML** reports.

> 🔒 **Strictly read-only.** No LDAP writes, no SYSVOL writes, no membership changes, no account creation, no ticket requests. It *discovers and reports* exposure — exploitation stays manual and separate.

> 🎯 **Facts, not guesses.** A group is only called "requestable" when there is a *fact* tying it to JIT (a live time-bound member, or membership delegated to a non-admin). Name heuristics are used only as a labelled hint, never as evidence.

---

## ✨ Features

- 🎯 **Requestable groups — facts only** — a group is listed when it is **JIT-active right now** (a live TTL member) **or** its membership is **writable by a principal you can target** (a delegation). Each row shows *what it grants* and *who can add you*.
- 🧑‍⚖️ **Authoritative approvers from the DACL** — who can write a group's `member` attribute, not who *looks* like an approver:
  - `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `WriteProperty` (member / all attributes)
  - 👑 **object ownership** — the SD `OwnerSid` holds implicit `WriteDacl`, so a non-default owner can add itself (`Owner (implicit WriteDacl)`)
  - 🙋 **Self-Membership** validated write reported **separately** (add/remove *self* only — not a general approver)
  - inherited ACEs kept & marked; deny ACEs skipped; privileged trustees filtered by default
- 🗝️ **Membership writers — your target list** — every principal that can grant access, deduplicated, with **service account / gMSA highlighted** (controlling one = self-approval without the app or a human).
- 🕵️ **JIT manager / approval engine location** — pivots from the writer to the manager itself:
  - `servicePrincipalName` → host, and an **`HTTP` SPN → the approval web-app URL**
  - **gMSA writer → the servers that run it** (`msDS-GroupMSAMembership` allowed hosts)
  - **evidence-based confidence** (a lone service-account writer is `low`, not `high`) with a *Why* column
  - 🏷️ domain-wide **PAM/JIT product fingerprints** (MIM, CyberArk, Delinea, BeyondTrust, One Identity, Netwrix/StealthBits, PAM360, Silverfort, WALLIX…) — clearly labelled indicative
- ⏱️ **Live TTL memberships** (`LDAP_SERVER_LINK_TTL`) + **active-access correlation** — *"who has admin on which machine right now, and for how long"*.
- 🏰 **Definitive PAM facts** — the **PAM feature** enablement, the **PAM bastion trust** (`trustAttributes` PIM bit `0x400` — *proves* a MIM/PAM bastion), and **shadow principals** with their TTLs.
- 🧱 **Tiering hardening facts** — **Protected Users** membership and **Authentication Policy Silos** (with enforced state).
- 🗺️ **SYSVOL group→machine mapping** — GPP `Groups.xml` (machine **and** user) + **Restricted Groups** `GptTmpl.inf`, namespace-tolerant, item-level-targeting aware, with **gPLink scope** resolution.
- 🕰️ **Recent-access forensics** (`--history`) — replication metadata (`msDS-ReplValueMetaData`) for membership changes that already lapsed.
- 🔑 **Auth**: password · NT hash (`LM:NT`) · Kerberos (`KRB5CCNAME`).
- 📤 **Exports** — Rich console, plus CSV (sectioned), structured JSON, and a standalone HTML report.

---

## ⚠️ Legal / Safety Note

This tool is meant for **authorized security testing** (labs, CTFs, pentests and audits with permission).
It is **read-only**, but you are still responsible for how and where you run it.

---

## 📦 Installation

### Requirements
- Python **3.8+**
- `ldap3`, `impacket`, `rich`, `rich-argparse`

```bash
pip install -r requirements.txt
```

> `rich-argparse` is optional (a plain help formatter is used if it is missing). For Kerberos, `gssapi` is pulled in transitively by ldap3.

---

## 🚀 Quick Start

### Full scan (password)

```bash
python jithunter.py -d corp.com -u mary -p '12Maintwelve' --dc-ip 192.168.70.100
```

### Authenticate with an NT hash, export an HTML report

```bash
python jithunter.py -d corp.com -u mary -H 942f15864b02fdee... --dc-ip 192.168.70.100 --export report.html
```

### LDAP only (skip SYSVOL SMB access)

```bash
python jithunter.py -d corp.com -u mary -p '...' --dc-ip 192.168.70.100 --no-sysvol
```

### Big domain — skip the full membership-DACL sweep

```bash
python jithunter.py -d corp.com -u mary -p '...' --dc-ip 192.168.70.100 --fast
```

### Everything on (privileged trustees, full workflow view, recent-access forensics)

```bash
python jithunter.py -d corp.com -u mary -p '...' --dc-ip 192.168.70.100 \
    --include-privileged --verbose --history
```

---

## 🔑 Authentication

Provide **exactly one** method:

```bash
# Password
python jithunter.py -d corp.com -u mary -p 'Passw0rd'   --dc-ip 192.168.70.100

# NT hash (or LM:NT)
python jithunter.py -d corp.com -u mary -H <NThash>      --dc-ip 192.168.70.100

# Kerberos (ticket from KRB5CCNAME)
python jithunter.py -d corp.com -u mary -k --dc-ip dc01.corp.com
```

> 🎫 **Kerberos + IP-only DC:** SASL/GSSAPI (LDAP) and Kerberos SMB derive the SPN from the host you pass. A bare IP yields `ldap/<ip>` / `cifs/<ip>`, which have no Kerberos principal — pass the DC **FQDN** to `--dc-ip` when using `-k`.

---

## 🌐 Connection

```bash
# Force LDAPS (636)
python jithunter.py -d corp.com -u mary -p 'Passw0rd' --dc-ip 192.168.70.100 --ssl
```

JIThunter binds over NTLM (password/hash) or SASL/GSSAPI (Kerberos), with `auto_referrals=False` and connect/receive timeouts so it never hangs chasing referrals or a slow DC. SYSVOL is read over SMB using the same credentials (Kerberos supported).

---

## 🔎 What It Detects

JIThunter prints a **posture panel** and a set of focused tables, most-actionable first:

1. **⏱️ Active elevated access (live now)** — live TTL member × unlocked machine: *"`bob` has local admin on `WEB01`, expires in `1h 30m`."*
2. **🎯 Requestable groups** — JIT-active or membership-delegated groups only, each with a concise grant and the DACL writer who can add you.
3. **🗺️ SYSVOL attack surface** — group → machine local admin, with source (GPP machine/user, Restricted Groups) and GPO.
4. **🗝️ Membership writers** — the consolidated *"which account do I target"* list.
5. **🕵️ JIT manager / approval engine** — the identity behind the writes (host / approval web URL / gMSA hosts) with evidence, plus product fingerprints.
6. **🕰️ Recent membership changes** (`--history`) — replication-metadata forensics.

The **posture panel** carries the definitive facts: **PAM feature**, **PAM bastion trust**, **shadow principals** (+ time-bound), **live TTL** count, **active elevated access** count, and **tiering hardening** (Protected Users, AuthN silos).

---

## 🧭 Reading the "JIT manager" confidence

Because almost every service account has an SPN, being an SPN-bearing writer is **not** enough for "high". Confidence is **evidence-based**:

| Confidence | Meaning |
| --- | --- |
| `high` | Corroborated — a **gMSA**, a **product fingerprint** match, writes a group that is **JIT-active now**, has an **HTTP/WSMAN portal SPN**, or writes **several** requestable groups. |
| `medium` | Writes ≥ 2 requestable groups, or exposes a web-portal SPN. |
| `low` | A lone delegation, no corroboration — **hidden by default** (`--show-low` to list). |

Every identity row shows the exact **evidence** for its rating, so the result is judgeable, not a blanket "high".

---

## 📤 Exports

```bash
python jithunter.py ... --export findings.csv     # CSV  (sectioned)
python jithunter.py ... --export findings.json    # JSON (structured, canonical)
python jithunter.py ... --export report.html      # HTML (self-contained, shareable)
python jithunter.py ... --export out --format json
```

- **JSON** — the canonical document. Additive schema (`requestable_groups`, `membership_writers`, `jit_manager`, `active_access`, `pam_bastion_trust`, `tiering`, `history`, …); each DACL approver carries `sid`/`name`/`dn`/`type`/`right`, each JIT-manager identity carries `confidence`/`evidence`.
- **CSV** — the attack-paths table plus clearly-labelled sections: `requestable_group`, `active_access`, `membership_writer`, `jit_manager_identity` / `jit_manager_product`.
- **HTML** — a single self-contained dark report: live-access, requestable groups, membership writers, JIT-manager identity + fingerprints, machine attack surface, and TTL memberships.

---

## 🎛️ CLI Reference

Rich help by default:

```bash
python jithunter.py --help
```

| Flag | Description |
| --- | --- |
| `-d, --domain` | Domain, e.g. `corp.com` **(required)** |
| `-u, --username` | Authentication account **(required)** |
| `--dc-ip` | DC IP address or hostname **(required)** |
| `-p, --password` | Password |
| `-H, --hashes` | NT hash, or `LM:NT` |
| `-k, --kerberos` | Kerberos via `KRB5CCNAME` |
| `--ssl` | Force LDAPS (636) |
| `--search-base DN` | Scope LDAP enumeration to a DN (focused audits) |
| `--no-sysvol` | Skip SYSVOL SMB parsing (LDAP only) |
| `--fast` | Skip the domain-wide membership-DACL sweep (very large domains) |
| `--include-privileged` | Do not filter privileged trustees (Domain Admins, SYSTEM…) |
| `--verbose` | Show all workflow-group categories (default: request/approve) |
| `--history` | Replication-metadata recent-change forensics (heavier) |
| `--show-low` | Show low-confidence JIT-manager candidates |
| `--export FILE` | Export results to a file |
| `--format {csv,json,html}` | Export format (auto-detected from the extension) |

---

## ⚠️ Caveats & Limitations

- **The approval workflow is not in AD.** The web app's business logic (which human approves which request), resource-level grants (SQL `sysadmin`, app roles), and runtime activity beyond the TTL snapshot / replication history simply aren't stored in the directory. JIThunter surfaces the *account and host behind the writes* — pivot from there.
- **Live TTL memberships are ephemeral.** They are only visible while an access window is open; a quiet scan does not mean JIT is unused.
- **A SYSVOL group→machine mapping is infrastructure, not proof of JIT** — it shows a group *can* grant local admin, not that a workflow is wired to it.
- **The default sweep reads every group's membership DACL.** Fine for typical domains (hundreds–few thousand groups); use `--fast` on very large directories.
- **Foreign / cross-domain trustees** that a single DC can't resolve are shown by **SID**, marked `unresolved`.
- **Workflow request/approve classification is a name/description heuristic** — indicative only; the DACL-based approvers are authoritative.
- **Kerberos needs the DC FQDN** (not a bare IP) for the SPN to match.

---

## 🗺️ Roadmap Ideas

- LAPS deployment (`ms-Mcs-AdmPwd` / `msLAPS-Password`) and who can read it
- GPP **Scheduled Tasks** in SYSVOL that add/remove group members (home-grown JIT)
- Cross-domain / foreign principal resolution (Global Catalog)
- BloodHound-friendly export
- Transitive privileged-nesting resolution

PRs welcome 😉

---

## ❤️ Credits

Built by **@Gromak123** and **LLM**.
If you use JIThunter in a writeup, talk, or CTF: a mention is always appreciated.
