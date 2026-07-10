#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# JIThunter - READ-ONLY posture and attack-surface scanner for Just-In-Time (JIT)
# / Privileged Access Management (PAM) in an Active Directory domain.
# By: @Gromak123
# Version: 1.6
#
# JIT leaves no single authoritative marker in AD, so this tool aggregates several
# signals of varying reliability and correlates them into a posture + attack
# surface report:
#
#   1. PAM enabled       (reliable)  - msDS-EnabledFeature on the Partitions object
#                                       lists the PAM feature DN -> JIT is possible.
#   2. Shadow principals (reliable)  - CN=Shadow Principal Configuration container
#                                       (bastion/MIM PAM implementation). Their
#                                       memberships are also read with LINK_TTL.
#   3. Live TTL memberships (reliable but ephemeral) - temporary group memberships
#                                       exposed via the LDAP_SERVER_LINK_TTL control;
#                                       only visible while an access window is open.
#   4. SYSVOL group->machine mapping (infrastructure) - GPP Groups.xml (machine and
#                                       user) and Restricted Groups (GptTmpl.inf) map
#                                       a group to local Administrators on targets.
#   5. Naming heuristics (indicative) - request/approve/la_/admin group patterns.
#
# On top of the signals, JIThunter adds factual correlations:
#   - Approvers of a requestable group are read from the group's DACL (who can write
#     its 'member' attribute), not guessed from names - this is the authoritative
#     approver source. See collect_group_dacls().
#   - Live TTL memberships are joined with the group->machine mapping to show who
#     holds elevated access right now and until when. See correlate_active_access().
#
# The approval workflow itself (e.g. a web app) is NOT visible from AD - but the
# service account the app uses to write memberships IS visible in the DACL, and is
# the more valuable finding. JIThunter pivots from that account to locate the JIT
# manager itself: its SPNs reveal the host and (for HTTP SPNs) the approval web-app
# URL, and if it is a gMSA, msDS-GroupMSAMembership names the servers that run it.
# A domain-wide fingerprint scan additionally flags known PAM/JIT products
# (MIM, CyberArk, Delinea, BeyondTrust, One Identity, Netwrix/StealthBits, ...).
# See detect_jit_manager().
#
# Read-only tool: no LDAP writes, no SMB writes, no account changes. It reads and
# reports; exploitation stays manual and separate.
#
# Dependencies: ldap3, impacket, rich (rich-argparse optional)
#   pip install ldap3 impacket rich rich-argparse

import argparse
import csv
import html
import io
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS, BASE, SUBTREE, LEVEL
except ImportError:
    print("[!] Missing module 'ldap3': pip install ldap3", file=sys.stderr)
    sys.exit(1)

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    print("[!] Missing module 'impacket': pip install impacket", file=sys.stderr)
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.markup import escape as rich_escape
except ImportError:
    print("[!] Missing module 'rich': pip install rich", file=sys.stderr)
    sys.exit(1)

try:
    from rich_argparse import RawDescriptionRichHelpFormatter as _HelpFormatter
    _HelpFormatter.styles["argparse.groups"] = "bold magenta"
    _HelpFormatter.styles["argparse.args"] = "green"
    _HelpFormatter.styles["argparse.metavar"] = "bold cyan"
    _HelpFormatter.styles["argparse.prog"] = "bold magenta"
except ImportError:
    from argparse import RawDescriptionHelpFormatter as _HelpFormatter


TOOL_NAME = "JIThunter"
AUTHOR = "@Gromak123"
VERSION = "1.6"

# --- Constants --------------------------------------------------------------
# PAM optional-feature identity (fixed across all domains).
PAM_FEATURE_GUID = "ec43e873-cce8-4640-b4ab-07ffe4ab5bcd"
PAM_FEATURE_NAME = "Privileged Access Management Feature"

# LDAP extended control that exposes link TTLs on the 'member' attribute.
# Without it, a temporary membership is indistinguishable from a permanent one.
LDAP_SERVER_LINK_TTL_OID = "1.2.840.113556.1.4.2309"

# Network timeouts (seconds). Keep the tool from hanging on an unreachable or slow
# DC - important when running across different AD environments.
LDAP_TIMEOUT = 30
SMB_TIMEOUT = 30

# Built-in local Administrators group SID (target of local-admin GPP mappings).
ADMINISTRATORS_SID = "S-1-5-32-544"

# trustAttributes bit set on the trustedDomain object of a MIM/PAM bastion trust
# (New-PAMTrust). Its presence is definitive proof of a PAM bastion deployment.
TRUST_ATTRIBUTE_PIM_TRUST = 0x00000400

# schemaIDGUID of the 'member' attribute. Verified against MS-ADA1 (Attributes A-L,
# "member") and confirmed by the round-trip test in tests/test_jithunter.py. NOTE:
# this same GUID is also the rightsGuid of the "Self-Membership" validated write
# (CN=Self-Membership), so a WriteProperty over 'member' (arbitrary write, mask bit
# ADS_RIGHT_DS_WRITE_PROP 0x20) and a Self-Membership validated write (add/remove
# self only, mask bit ADS_RIGHT_DS_SELF 0x08) are told apart by the access-mask bit,
# not by the ObjectType GUID. Only the former makes a general approver.
MEMBER_ATTR_GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"

# Access-mask bits (MS-DTYP / ADS_RIGHTS_ENUM) used to classify a group DACL ACE.
GENERIC_ALL          = 0x10000000
GENERIC_WRITE        = 0x40000000
WRITE_DACL           = 0x00040000  # WRITE_DAC
WRITE_OWNER          = 0x00080000
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_SELF       = 0x00000008  # validated write (e.g. Self-Membership)
INHERITED_ACE        = 0x10          # ACE header flag

# Well-known highly-privileged trustees filtered from the approver list by default
# (they can write any group's membership anyway - noise, like RBCDiscover hides it).
# Shown with --include-privileged.
WELL_KNOWN_PRIVILEGED_SIDS = {
    "S-1-5-18",      # Local SYSTEM
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-32-548",  # BUILTIN\Account Operators
    "S-1-5-32-551",  # BUILTIN\Backup Operators
    "S-1-3-0",       # Creator Owner
    "S-1-5-10",      # Principal Self (Self-Membership trustee)
    "S-1-5-9",       # Enterprise Domain Controllers
}
# Domain-relative RIDs that are always highly privileged.
WELL_KNOWN_PRIVILEGED_RIDS = {
    512,  # Domain Admins
    516,  # Domain Controllers
    518,  # Schema Admins
    519,  # Enterprise Admins
    520,  # Group Policy Creator Owners
}
# Friendly names for a few well-known SIDs (display only).
WELL_KNOWN_SID_NAMES = {
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-5-10": "NT AUTHORITY\\SELF",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
}

# Naming heuristics for workflow groups. Indicative only, never authoritative.
KW_REQUEST = ("request", "_req", "req_", "jitreq", "pam_req")
KW_APPROVE = ("approve", "approv", "_appr", "appr_", "reviewer")
KW_LOCALADMIN = ("la_", "_la", "localadmin", "local_admin")
KW_PRIVILEGED = ("admin", "tier0", "tier1", "tier-0", "tier-1", "priv", "pim", "pam", "jit")

# Groups that ARE (or protect) high privilege. A requestable group nested into one of
# these, or protected by SDProp (adminCount=1), grants privilege even without a SYSVOL
# machine mapping. RIDs are domain-relative; the S-1-5-32-* are BUILTIN aliases.
PRIVILEGED_GROUP_RIDS = {512, 516, 518, 519, 520, 521, 526, 527}
PRIVILEGED_BUILTIN_SIDS = {
    "S-1-5-32-544",  # Administrators
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators
    "S-1-5-32-551",  # Backup Operators
    "S-1-5-32-552",  # Replicator
}

# Known PAM/JIT product fingerprints, matched (indicative) against indexed AD
# attributes (sAMAccountName / servicePrincipalName / cn). Specific tokens only,
# to keep false positives low. Used to locate the JIT manager / approval engine.
JIT_VENDOR_FINGERPRINTS = (
    ("Microsoft MIM / FIM PAM", ("mimservice", "fimservice", "forefrontidentity",
                                 "microsoftidentitymanager", "mimsync", "mimportal")),
    ("CyberArk", ("cyberark", "pvwa", "psmapp", "psmgw", "cyberark-cpm")),
    ("Delinea / Thycotic Secret Server", ("delinea", "thycotic", "secretserver")),
    ("BeyondTrust", ("beyondtrust", "powerbroker", "beyondinsight", "bomgar")),
    ("One Identity Safeguard / Active Roles", ("safeguard", "oneidentity", "activeroles",
                                               "questars", "quest-ars")),
    ("Netwrix / StealthBits Privilege Secure (SbPAM)", ("sbpam", "stealthbits", "netwrix",
                                                        "privilegesecure")),
    ("ManageEngine PAM360 / ADManager", ("pam360", "manageengine", "admanager", "adselfservice")),
    ("Silverfort", ("silverfort",)),
    ("tenfold", ("tenfoldsecurity",)),
    ("Admin By Request", ("adminbyrequest",)),
    ("senhasegura", ("senhasegura",)),
    ("WALLIX Bastion", ("wallix",)),
    ("Fudo Security", ("fudosecurity",)),
    ("ARCON PAM", ("arconpam",)),
    ("Bravura / Hitachi ID", ("bravura", "hitachiid")),
    ("Saviynt", ("saviynt",)),
    ("Okta / osync", ("oktaprovisioning",)),
)
# Weaker generic tokens - only trusted with corroborating context (a writer, an SPN,
# or a serviceConnectionPoint), never on their own domain-wide, to avoid noise.
JIT_GENERIC_TOKENS = ("justintime", "just-in-time", "-jit-", "_jit_", "privaccess",
                      "bastion", "pam-", "-pam", "pimsvc")

# SPN classes that indicate a web/remote-management front end (the approval portal).
JIT_WEB_SPN_CLASSES = ("http", "https", "wsman", "httpsvc", "termsrv")

console = Console()


# ============================================================================
#  ldap3 value helpers (robust against scalar/list return quirks)
# ============================================================================
def _first(value, default=None):
    if value is None:
        return default
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if item is not None:
                return item
        return default
    return value


def _to_text(value, default=""):
    value = _first(value, default)
    if value is None:
        return default
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _iter_values(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [v for v in value if v is not None]
    return [value]


def _attr(entry, name):
    return (entry.get("attributes") or {}).get(name)


def _raw_attr(entry, name):
    """First raw (bytes) value of an attribute - used for binary blobs like
    nTSecurityDescriptor that must not go through ldap3's text formatting."""
    return _first((entry.get("raw_attributes") or {}).get(name))


def _ensure_parent(path):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)


def _is_privileged_sid(sid):
    """True for well-known highly-privileged trustees (SYSTEM, Administrators,
    Domain/Enterprise/Schema Admins, ...). Filtered from approvers by default."""
    if not sid:
        return False
    s = sid.upper()
    if s in WELL_KNOWN_PRIVILEGED_SIDS:
        return True
    m = re.match(r'^S-1-5-21-\d+-\d+-\d+-(\d+)$', s)
    if m and int(m.group(1)) in WELL_KNOWN_PRIVILEGED_RIDS:
        return True
    return False


def _wellknown_sid_name(sid):
    """Friendly name for a well-known SID, else '' (caller falls back to the SID)."""
    if not sid:
        return ""
    return WELL_KNOWN_SID_NAMES.get(sid.upper(), "")


def _sid_string_to_bytes(sid):
    """Canonical SID string -> binary, for objectSid LDAP filters. None on failure."""
    try:
        from impacket.ldap import ldaptypes
        s = ldaptypes.LDAP_SID()
        s.fromCanonical(sid)
        return s.getData()
    except Exception:
        return None


def _principal_type(classes, has_spn=False):
    """Classify a principal from its objectClass (and SPN presence) so a pentester
    can tell at a glance what to target. gMSA and SPN-bearing users are the classic
    approval 'service accounts'."""
    cl = [str(c).lower() for c in _iter_values(classes)]
    if "msds-groupmanagedserviceaccount" in cl:
        return "gMSA"
    if "computer" in cl:
        return "computer"
    if "group" in cl:
        return "group"
    if "user" in cl:
        return "service account" if has_spn else "user"
    return cl[-1] if cl else ""


_TTL_RX = re.compile(r'^<TTL=(\d+)>,(.+)$', re.IGNORECASE)


def _parse_ttl_member(value):
    """Split a LINK_TTL member value '<TTL=seconds>,DN' -> (dn, ttl_seconds).

    A plain member without the TTL prefix returns (dn, None) - permanent link.
    """
    text = _to_text(value)
    match = _TTL_RX.match(text)
    if match:
        return match.group(2), int(match.group(1))
    return text, None


def _human_ttl(seconds):
    """Human-readable countdown, e.g. 5400 -> '1h 30m'."""
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return "?"
    if seconds < 0:
        return "expired"
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


# ============================================================================
#  LDAP connection
# ============================================================================
def connect_ldap(dc_host, domain, username, password=None, nt_hash=None,
                 use_kerberos=False, use_ssl=False):
    """Bind to LDAP and return (conn, base_dn, config_nc).

    NTLM for password/hash (avoids simple-bind rejection on hardened DCs);
    SASL/GSSAPI for Kerberos (uses KRB5CCNAME).
    """
    port = 636 if use_ssl else 389
    server = Server(dc_host, port=port, use_ssl=use_ssl, get_info=ALL,
                    connect_timeout=LDAP_TIMEOUT)

    # auto_referrals=False: never chase referrals to other DCs/domains - they hang
    # or fail unpredictably across environments and we always target one DC.
    common = dict(auto_bind=False, auto_referrals=False, receive_timeout=LDAP_TIMEOUT)
    if use_kerberos:
        conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS,
                          **common)
    elif nt_hash:
        lm = "aad3b435b51404eeaad3b435b51404ee"
        creds = nt_hash if ":" in nt_hash else f"{lm}:{nt_hash}"
        conn = Connection(server, user=f"{domain}\\{username}", password=creds,
                          authentication=NTLM, **common)
    else:
        conn = Connection(server, user=f"{domain}\\{username}", password=password,
                          authentication=NTLM, **common)

    if not conn.bind():
        raise RuntimeError(f"LDAP bind failed: {conn.result}")

    # server.info can be None if RootDSE read was blocked; fall back to the domain.
    other = getattr(server.info, "other", None) or {}
    base_dn = _to_text(other.get("defaultNamingContext"))
    if not base_dn:
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    config_nc = _to_text(other.get("configurationNamingContext"))
    if not config_nc:
        config_nc = "CN=Configuration," + base_dn
    return conn, base_dn, config_nc


# ============================================================================
#  Signal 1 - PAM feature enabled
# ============================================================================
def check_pam_enabled(conn, config_nc):
    """Return (enabled: bool, scopes: list[str]).

    PAM is enabled when the Partitions object's msDS-EnabledFeature attribute
    lists the PAM feature DN (this is what Get-ADOptionalFeature computes as
    EnabledScopes). We match on the feature name/GUID to be robust.
    """
    partitions_dn = f"CN=Partitions,{config_nc}"
    try:
        conn.search(partitions_dn, "(objectClass=*)", search_scope=BASE,
                    attributes=["msDS-EnabledFeature"])
    except Exception:
        return False, []
    scopes = []
    for entry in conn.response:
        if entry.get("type") != "searchResEntry":
            continue
        for dn in _iter_values(_attr(entry, "msDS-EnabledFeature")):
            dn = _to_text(dn)
            if PAM_FEATURE_NAME.lower() in dn.lower():
                scopes.append(dn)
    # Fallback: match by feature GUID on the optional-feature object itself.
    if not scopes:
        feat_dn = (f"CN={PAM_FEATURE_NAME},CN=Optional Features,"
                   f"CN=Directory Service,CN=Windows NT,CN=Services,{config_nc}")
        try:
            conn.search(feat_dn, "(objectClass=msDS-OptionalFeature)",
                        search_scope=BASE,
                        attributes=["msDS-OptionalFeatureGUID", "name"])
            # Presence of the object does not prove enablement; only report if the
            # Partitions link was found above. So we leave scopes empty here.
        except Exception:
            pass
    return (len(scopes) > 0), scopes


# ============================================================================
#  Certain PAM/tiering facts (definitive, read once)
# ============================================================================
def check_pam_trust(conn, base_dn):
    """Detect a MIM/PAM bastion trust. A trust created by New-PAMTrust carries the
    trustAttributes PIM bit (0x400) - its presence is definitive proof of a PAM
    bastion forest. Returns list of {partner, flat, direction, attributes}. Certain.
    """
    out = []
    try:
        entries = conn.extend.standard.paged_search(
            f"CN=System,{base_dn}", "(objectClass=trustedDomain)", search_scope=LEVEL,
            attributes=["trustPartner", "flatName", "trustDirection", "trustAttributes"],
            paged_size=100, generator=True)
    except Exception:
        return out
    for e in entries:
        if e.get("type") != "searchResEntry":
            continue
        a = e.get("attributes") or {}
        try:
            attr_val = int(_to_text(a.get("trustAttributes")) or 0)
        except (TypeError, ValueError):
            attr_val = 0
        if attr_val & TRUST_ATTRIBUTE_PIM_TRUST:
            try:
                direction = int(_to_text(a.get("trustDirection")) or 0)
            except (TypeError, ValueError):
                direction = 0
            out.append({"partner": _to_text(a.get("trustPartner")),
                        "flat": _to_text(a.get("flatName")),
                        "direction": direction, "attributes": attr_val})
    return out


def check_tiering_posture(conn, base_dn, config_nc):
    """Read certain privileged-account hardening facts that accompany a real JIT /
    tiering model: Protected Users membership and Authentication Policy Silos.

    Returns {protected_users: int|None, authn_silos: [{name, enforced}]}. All facts,
    not guesses (the objects either exist or they don't).
    """
    result = {"protected_users": None, "authn_silos": []}

    # Protected Users (RID 525): members get hardened Kerberos (no NTLM/RC4/deleg).
    try:
        conn.search(base_dn, "(&(objectClass=group)(sAMAccountName=Protected Users))",
                    search_scope=SUBTREE, attributes=["member"])
        for e in conn.response:
            if e.get("type") != "searchResEntry":
                continue
            result["protected_users"] = len(_iter_values(_attr(e, "member")))
    except Exception:
        pass

    # Authentication Policy Silos: confine tier-0 accounts to their tier.
    silo_container = f"CN=AuthN Policy Configuration,CN=Services,{config_nc}"
    try:
        entries = conn.extend.standard.paged_search(
            silo_container, "(objectClass=msDS-AuthNPolicySilo)", search_scope=SUBTREE,
            attributes=["cn", "msDS-AuthNPolicySiloEnforced"],
            paged_size=100, generator=True)
        for e in entries:
            if e.get("type") != "searchResEntry":
                continue
            a = e.get("attributes") or {}
            enforced = _to_text(a.get("msDS-AuthNPolicySiloEnforced")).upper() in ("TRUE", "1")
            result["authn_silos"].append({"name": _to_text(a.get("cn")),
                                          "enforced": enforced})
    except Exception:
        pass
    return result


# ============================================================================
#  Signal 2 - Shadow principals (bastion/MIM PAM)
# ============================================================================
def find_shadow_principals(conn, config_nc):
    """Enumerate shadow principals (msDS-ShadowPrincipal objects).

    The 'member' attribute is read with the LINK_TTL control so that any temporary
    (time-bound) shadow membership surfaces its remaining TTL; permanent members
    have no TTL. Returns dicts with 'members' (plain DNs) and 'member_ttls'
    (list of {member_dn, ttl_seconds, expires_human}) for the time-bound ones.
    """
    container = f"CN=Shadow Principal Configuration,CN=Services,{config_nc}"
    control = [(LDAP_SERVER_LINK_TTL_OID, False, None)]
    results = []
    try:
        entries = conn.extend.standard.paged_search(
            container, "(objectClass=msDS-ShadowPrincipal)",
            search_scope=SUBTREE,
            attributes=["cn", "msDS-ShadowPrincipalSid", "member"],
            controls=control, paged_size=200, generator=True)
    except Exception:
        return results  # container absent -> no bastion PAM
    for e in entries:
        if e.get("type") != "searchResEntry":
            continue
        attrs = e.get("attributes") or {}
        sid_raw = _first(attrs.get("msDS-ShadowPrincipalSid"))
        members, member_ttls = [], []
        for m in _iter_values(attrs.get("member")):
            dn, ttl = _parse_ttl_member(m)
            members.append(dn)
            if ttl is not None:
                member_ttls.append({"member_dn": dn, "ttl_seconds": ttl,
                                    "expires_human": _human_ttl(ttl)})
        results.append({
            "name": _to_text(attrs.get("cn")),
            "sid": _sid_to_str(sid_raw),
            "members": members,
            "member_ttls": member_ttls,
        })
    return results


def _sid_to_str(raw):
    """Best-effort conversion of a binary SID to string."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    try:
        from impacket.ldap import ldaptypes
        return ldaptypes.LDAP_SID(data=raw).formatCanonical()
    except Exception:
        return str(raw)


# ============================================================================
#  Signal 3 - Live temporary (TTL) memberships
# ============================================================================
def find_ttl_memberships(conn, base_dn):
    """Find active temporary group memberships using the LINK_TTL control.

    Returns list of {group, group_dn, member_dn, ttl_seconds}. Only memberships
    that are ACTIVE at scan time are visible (an approved JIT request in flight).
    """
    control = [(LDAP_SERVER_LINK_TTL_OID, False, None)]
    results = []
    try:
        entries = conn.extend.standard.paged_search(
            base_dn, "(&(objectClass=group)(member=*))", search_scope=SUBTREE,
            attributes=["cn", "sAMAccountName", "distinguishedName", "objectSid", "member"],
            controls=control, paged_size=200, generator=True)
    except Exception as exc:
        console.print(f"[yellow][~][/] LINK_TTL search failed: {exc}")
        return results
    for e in entries:
        if e.get("type") != "searchResEntry":
            continue
        attrs = e.get("attributes") or {}
        gdn = _to_text(attrs.get("distinguishedName"))
        gsam = _to_text(attrs.get("sAMAccountName"))
        gname = gsam or _to_text(attrs.get("cn")) or gdn
        gsid = _sid_to_str(_first(attrs.get("objectSid")))
        for m in _iter_values(attrs.get("member")):
            member_dn, ttl = _parse_ttl_member(m)
            if ttl is not None:
                results.append({
                    "group": gname, "group_dn": gdn,
                    "group_sam": gsam, "group_sid": gsid,
                    "member_dn": member_dn,
                    "ttl_seconds": ttl,
                })
    return results


# ============================================================================
#  Signal 4 - Workflow groups (naming heuristics + member resolution)
# ============================================================================
def collect_group_index(conn, base_dn):
    """Build lookup maps and gather all groups for later resolution.

    Returns (dn_to_name, groups, sid_to_name):
      dn_to_name  : lower(DN) -> sAMAccountName
      groups      : list of {name, dn, sid, description, members(DNs)}
      sid_to_name : upper(SID) -> sAMAccountName (used to resolve DACL trustees)
    """
    dn_to_name = {}
    sid_to_name = {}
    groups = []
    entries = conn.extend.standard.paged_search(
        base_dn, "(|(objectClass=user)(objectClass=group))",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "distinguishedName", "objectClass",
                    "member", "memberOf", "description", "objectSid", "adminCount"],
        paged_size=500, generator=True)
    for e in entries:
        if e.get("type") != "searchResEntry":
            continue
        attrs = e.get("attributes") or {}
        dn = _to_text(attrs.get("distinguishedName"))
        name = _to_text(attrs.get("sAMAccountName")) or dn
        sid = _sid_to_str(_first(attrs.get("objectSid")))
        if dn:
            dn_to_name[dn.lower()] = name
        if sid:
            sid_to_name[sid.upper()] = name
        classes = [str(c).lower() for c in _iter_values(attrs.get("objectClass"))]
        if "group" in classes:
            groups.append({
                "name": name, "dn": dn, "sid": sid,
                "description": _to_text(attrs.get("description")),
                "members": [_to_text(m) for m in _iter_values(attrs.get("member"))],
                "memberof": [_to_text(m).lower() for m in _iter_values(attrs.get("memberOf"))],
                "admincount": str(_to_text(attrs.get("adminCount"))) == "1",
            })
    return dn_to_name, groups, sid_to_name


def categorize_group(name, description):
    """Return a set of heuristic categories for a group."""
    text = f"{name} {description}".lower()
    cats = set()
    if any(k in text for k in KW_REQUEST):
        cats.add("request")
    if any(k in text for k in KW_APPROVE):
        cats.add("approve")
    if any(k in text for k in KW_LOCALADMIN):
        cats.add("localadmin")
    if any(k in text for k in KW_PRIVILEGED):
        cats.add("privileged")
    return cats


def find_workflow_groups(groups, dn_to_name):
    """Classify groups by heuristic and resolve their members to names."""
    findings = []
    for g in groups:
        cats = categorize_group(g["name"], g["description"])
        if not cats:
            continue
        members = [dn_to_name.get(m.lower(), m) for m in g["members"]]
        findings.append({
            "name": g["name"], "dn": g["dn"],
            "categories": sorted(cats),
            "description": g["description"],
            "members": members,
        })
    return findings


# ============================================================================
#  Authoritative approvers - group membership DACL analysis
# ============================================================================
#  An "approver" of a requestable group is not a name pattern: it is anyone who
#  can write that group's 'member' attribute. This is the RBCD logic (who can
#  write msDS-AllowedToActOnBehalfOfOtherIdentity on a computer) applied to the
#  'member' attribute of a group. We read nTSecurityDescriptor and collect the
#  trustees holding a write-equivalent right over membership.
#
#  IMPORTANT: when approval is brokered by a web app, the principal in the DACL is
#  the app's *service account*, not the human approver - and that account is the
#  more valuable finding: whoever controls it can self-approve without ever going
#  through the app. It is surfaced distinctly (see the 'right' field and the note
#  under the attack-surface table).
# ============================================================================
def _extract_membership_writers(sd_bytes, member_guid=MEMBER_ATTR_GUID):
    """Parse a security descriptor and return (approvers, self_members).

    approvers    : [{sid, right}] - trustees who can write arbitrary 'member'
                   values (GenericAll/GenericWrite/WriteDacl/WriteOwner, or
                   WriteProperty over all attributes / the 'member' attribute).
    self_members : [{sid}] - trustees holding only the Self-Membership validated
                   write (can add/remove ONLY themselves - NOT general approvers).

    Deny ACEs are skipped. Inherited ACEs are kept and marked because they are
    still effective on the group and matter for attack-surface auditing.
    """
    from impacket.ldap import ldaptypes
    from impacket.uuid import bin_to_string

    approvers, self_members = [], []
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)

    # The OWNER of the object always holds implicit READ_CONTROL + WRITE_DAC
    # (MS-DTYP): it can rewrite the DACL and grant itself membership. So a
    # non-default owner is an authoritative approver just like a DACL writer. This
    # is read from the security descriptor's OwnerSid (sdflags 0x07 includes it).
    try:
        owner = sd['OwnerSid']
        if owner is not None and not isinstance(owner, bytes):
            approvers.append({"sid": owner.formatCanonical(),
                              "right": "Owner (implicit WriteDacl)", "inherited": False,
                              "owner": True})
    except Exception:
        pass

    dacl = sd['Dacl']
    if dacl is None:
        return approvers, self_members

    allow_types = (ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE,
                   ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE)
    for ace in dacl.aces:
        try:
            if ace['AceType'] not in allow_types:
                continue  # only ALLOW ACEs grant rights
            inherited = bool(ace['AceFlags'] & INHERITED_ACE)
            body = ace['Ace']
            mask = body['Mask']['Mask']
            sid = body['Sid'].formatCanonical()

            def add_approver(right):
                approvers.append({"sid": sid, "right": right,
                                  "inherited": inherited})

            def add_self_member():
                self_members.append({"sid": sid, "inherited": inherited})

            # ObjectType is only present on object ACEs when the flag is set;
            # its absence means the right applies to ALL properties.
            has_object_type = False
            obj_guid = None
            if ace['AceType'] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                if body['Flags'] & ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
                    has_object_type = True
                    obj_guid = bin_to_string(body['ObjectType']).lower()

            # Full-control rights - relevant regardless of attribute.
            if mask & GENERIC_ALL:
                add_approver("GenericAll"); continue
            if mask & GENERIC_WRITE:
                add_approver("GenericWrite"); continue
            if mask & WRITE_DACL:
                add_approver("WriteDacl"); continue
            if mask & WRITE_OWNER:
                add_approver("WriteOwner"); continue

            # WriteProperty: writes-all (no ObjectType) or specifically 'member'.
            if mask & ADS_RIGHT_DS_WRITE_PROP:
                if not has_object_type:
                    add_approver("WriteProperty (all)"); continue
                if obj_guid == member_guid:
                    add_approver("WriteProperty (member)"); continue

            # Self-Membership validated write: add/remove SELF only, not others.
            if mask & ADS_RIGHT_DS_SELF:
                if (not has_object_type) or obj_guid == member_guid:
                    add_self_member()
        except Exception:
            continue  # one malformed ACE must not abort DACL parsing
    return approvers, self_members


def resolve_principals(conn, base_dn, sids):
    """Batch-resolve SIDs -> {name, dn, type} via objectSid LDAP search.

    Catches trustees the initial user/group sweep missed: service accounts, gMSAs,
    computer accounts, or principals in a nested container. Best-effort, chunked,
    fails soft. (Foreign-domain SIDs still won't resolve against one DC.)
    """
    from ldap3.utils.conv import escape_bytes
    out = {}
    uniq = sorted({s.upper() for s in sids if s})
    for i in range(0, len(uniq), 20):
        parts = []
        for s in uniq[i:i + 20]:
            b = _sid_string_to_bytes(s)
            if b is not None:
                parts.append(f"(objectSid={escape_bytes(b)})")
        if not parts:
            continue
        filt = "(|" + "".join(parts) + ")" if len(parts) > 1 else parts[0]
        try:
            conn.search(base_dn, filt, search_scope=SUBTREE,
                        attributes=["sAMAccountName", "distinguishedName",
                                    "objectClass", "objectSid", "servicePrincipalName"])
        except Exception:
            continue
        for e in conn.response:
            if e.get("type") != "searchResEntry":
                continue
            attrs = e.get("attributes") or {}
            sid = _sid_to_str(_first(attrs.get("objectSid")))
            if not sid:
                continue
            has_spn = bool(_iter_values(attrs.get("servicePrincipalName")))
            out[sid.upper()] = {
                "name": _to_text(attrs.get("sAMAccountName")),
                "dn": _to_text(attrs.get("distinguishedName")),
                "type": _principal_type(attrs.get("objectClass"), has_spn=has_spn),
            }
    return out


def _read_group_sds(conn, base_dn, dns):
    """Bulk-read nTSecurityDescriptor for the given group DNs, chunked into
    distinguishedName OR-filters to minimise round-trips. Returns lower(DN) -> raw
    SD bytes. Missing DNs (unreadable / not returned) are simply absent."""
    from ldap3.protocol.microsoft import security_descriptor_control
    from ldap3.utils.conv import escape_filter_chars
    controls = security_descriptor_control(sdflags=0x07)  # OWNER|GROUP|DACL, no SACL
    out = {}
    dns = [d for d in dns if d]
    for i in range(0, len(dns), 20):
        chunk = dns[i:i + 20]
        clauses = "".join(f"(distinguishedName={escape_filter_chars(d)})" for d in chunk)
        filt = ("(|" + clauses + ")") if len(chunk) > 1 else clauses
        try:
            conn.search(base_dn, filt, search_scope=SUBTREE,
                        attributes=["nTSecurityDescriptor", "distinguishedName"],
                        controls=controls)
        except Exception:
            continue
        for e in conn.response:
            if e.get("type") != "searchResEntry":
                continue
            d = _to_text(_attr(e, "distinguishedName"))
            raw = _raw_attr(e, "nTSecurityDescriptor")
            if isinstance(raw, str):
                raw = raw.encode("latin-1", errors="replace")
            if d and raw:
                out[d.lower()] = raw
    return out


def collect_group_dacls(conn, base_dn, target_groups, sid_to_name,
                        include_privileged=False, sd_cache=None):
    """Read each target group's DACL and derive the authoritative approver list.

    target_groups : list of {dn, name, sid}.
    sd_cache      : optional lower(DN) -> raw SD bytes already read (e.g. by --deep),
                    reused to avoid re-reading DACLs.
    Returns dn -> {name, sid, approvers, self_members, readable} where each approver
    is {sid, name, dn, type, right, inherited, privileged}. Trustee SIDs are resolved
    to their account (name/DN/type) so a pentester can tell which account to actually
    target - e.g. the approval app's service account. 'readable' is False when the
    DACL could not be read (missing rights) so the caller can flag low confidence.
    """
    sd_cache = dict(sd_cache or {})
    # Bulk-read any DACLs we do not already have cached.
    missing = [tg["dn"] for tg in target_groups
               if tg.get("dn") and tg["dn"].lower() not in sd_cache]
    if missing:
        sd_cache.update(_read_group_sds(conn, base_dn, missing))

    # Pass 1: parse every target group's DACL, collecting trustee SIDs.
    parsed = {}   # dn -> (tg, approvers_raw, self_raw)
    all_sids = set()
    for tg in target_groups:
        dn = tg.get("dn")
        if not dn:
            continue
        sd_bytes = sd_cache.get(dn.lower())
        if not sd_bytes:
            parsed[dn] = (tg, None, None)  # DACL unreadable (rights?) - flag later
            continue
        try:
            appr_raw, self_raw = _extract_membership_writers(sd_bytes)
        except Exception:
            parsed[dn] = (tg, None, None)
            continue
        parsed[dn] = (tg, appr_raw, self_raw)
        for a in appr_raw:
            all_sids.add(a["sid"])
        for s in self_raw:
            all_sids.add(s["sid"])

    # Pass 2: resolve every trustee SID richly (name + DN + TYPE). We resolve even
    # SIDs the initial sweep already named, because that sweep does not fetch
    # objectClass/SPN - without this a service-account writer would show an empty
    # type and never be flagged as the account worth targeting. Well-known SIDs
    # (SYSTEM, Administrators, ...) have no resolvable domain object, so skip them.
    to_resolve = [s for s in all_sids if not _wellknown_sid_name(s)]
    resolved = resolve_principals(conn, base_dn, to_resolve)

    def describe(sid):
        r = resolved.get(sid.upper())
        if r and (r.get("name") or r.get("dn")):
            return r.get("name") or sid, r.get("dn", ""), r.get("type", "")
        nm = sid_to_name.get(sid.upper())
        if nm:
            return nm, "", ""
        wk = _wellknown_sid_name(sid)
        if wk:
            return wk, "", "well-known"
        return sid, "", "unresolved"

    out = {}
    for dn, (tg, appr_raw, self_raw) in parsed.items():
        if appr_raw is None:
            out[dn] = {"name": tg.get("name", ""), "sid": tg.get("sid", ""),
                       "approvers": [], "self_members": [], "readable": False}
            continue
        approvers = []
        for a in appr_raw:
            name, tdn, ttype = describe(a["sid"])
            approvers.append({"sid": a["sid"], "name": name, "dn": tdn, "type": ttype,
                              "right": a["right"], "inherited": a.get("inherited", False),
                              "owner": a.get("owner", False),
                              "privileged": _is_privileged_sid(a["sid"])})
        self_members = []
        for s in self_raw:
            name, tdn, ttype = describe(s["sid"])
            self_members.append({"sid": s["sid"], "name": name, "dn": tdn, "type": ttype,
                                 "inherited": s.get("inherited", False)})
        out[dn] = {"name": tg.get("name", ""), "sid": tg.get("sid", ""),
                   "approvers": approvers, "self_members": self_members, "readable": True}
    return out


def aggregate_membership_writers(attack_paths):
    """Collapse per-path DACL approvers into a de-duplicated target list: each
    principal that can write membership, with the strongest right and everything it
    ultimately unlocks. This is the actionable 'who do I target' view - the answer
    is often an approval service account, not anyone in a workflow group."""
    # Strength order for picking the most powerful right per principal.
    order = {"GenericAll": 5, "Owner (implicit WriteDacl)": 4, "WriteOwner": 4,
             "WriteDacl": 3, "GenericWrite": 2,
             "WriteProperty (all)": 1, "WriteProperty (member)": 0}
    writers = {}
    for p in attack_paths:
        for a in p.get("approvers_dacl", []):
            key = a["sid"] or a["name"]
            w = writers.get(key)
            if w is None:
                w = {"name": a["name"], "sid": a["sid"], "dn": a.get("dn", ""),
                     "type": a.get("type", ""), "right": a["right"],
                     "inherited": a.get("inherited", False),
                     "privileged": a.get("privileged", False),
                     "groups": set(), "unlocks": set(), "jit_active": False}
                writers[key] = w
            new_strength = order.get(a["right"], -1)
            cur_strength = order.get(w["right"], -1)
            if new_strength > cur_strength:
                w["right"] = a["right"]
                w["inherited"] = a.get("inherited", False)
            elif new_strength == cur_strength and not a.get("inherited", False):
                w["inherited"] = False
            if p.get("group"):
                w["groups"].add(p["group"])
            # 'unlocks' = the machines those groups grant local admin on (short and
            # factual), NOT a blob of every grant string. A writer that can write a
            # group which is JIT-active right now is the strongest manager signal.
            for mach in p.get("machines", []):
                w["unlocks"].add(mach)
            if p.get("target_computer"):   # machine attack_paths compatibility
                w["unlocks"].add(p["target_computer"])
            if p.get("jit_active"):
                w["jit_active"] = True
    result = []
    for w in writers.values():
        w["groups"] = sorted(w["groups"])
        w["unlocks"] = sorted(w["unlocks"])
        w["write_count"] = len(w["groups"])
        result.append(w)
    # Service accounts / gMSAs first (the high-value targets), then by reach.
    def rank(w):
        return (0 if w["type"] in ("service account", "gMSA") else 1,
                -w["write_count"], w["name"].lower())
    return sorted(result, key=rank)


def resolve_target_groups(gpp_mappings, groups):
    """Map the groups referenced by SYSVOL mappings to their DNs (for DACL reads).

    Matches by SID first (authoritative), then by short sAMAccountName. Returns a
    de-duplicated list of {dn, name, sid}.
    """
    by_sid = {g["sid"].upper(): g for g in groups if g.get("sid")}
    by_name = {g["name"].lower(): g for g in groups if g.get("name")}
    resolved = {}
    for m in gpp_mappings:
        sid = (m.get("group_sid") or "").upper()
        name = (m.get("group_name") or "").split("\\")[-1].lower()
        g = by_sid.get(sid) or by_name.get(name)
        if g and g.get("dn"):
            resolved[g["dn"]] = {"dn": g["dn"], "name": g["name"], "sid": g.get("sid", "")}
    return list(resolved.values())


# ============================================================================
#  Requestable / privileged group discovery (broader than SYSVOL machine mapping)
# ============================================================================
#  A requestable JIT group need not map to local Administrators on a computer. It
#  may grant membership of a privileged AD group, or admin of a service (SQL, ...)
#  that AD cannot see. We therefore union several signals - each tagged with what it
#  grants and how confident we are - so a group like 'la_mssql' is not missed just
#  because it isn't in a SYSVOL Groups.xml.
# ============================================================================
def _is_privileged_group(group):
    """True if the group itself is a high-privilege group (by RID / BUILTIN SID)."""
    sid = (group.get("sid") or "").upper()
    if sid in PRIVILEGED_BUILTIN_SIDS:
        return True
    m = re.match(r'^S-1-5-21-\d+-\d+-\d+-(\d+)$', sid)
    return bool(m and int(m.group(1)) in PRIVILEGED_GROUP_RIDS)


def _privileged_group_index(groups):
    """lower(DN) -> display name, for groups that confer high privilege."""
    return {g["dn"].lower(): g["name"] for g in groups
            if g.get("dn") and _is_privileged_group(g)}


def collect_candidate_groups(groups, gpp_mappings, ttl_members):
    """Groups worth reading a DACL for, from FACTUAL signals only (no name guessing):

      - a group has a live TTL member right now (JIT is actively in use), or
      - a group is mapped to local Administrators on a machine via SYSVOL.

    Delegated groups (membership writable by a non-admin) are added separately by the
    default DACL sweep. Each candidate carries {dn, name, sid, grants, jit_active,
    sources}; grants use kind 'local_admin' (detail=machine) and 'jit_active'.
    """
    groups_by_sid = {g["sid"].upper(): g for g in groups if g.get("sid")}
    groups_by_name = {g["name"].lower(): g for g in groups if g.get("name")}
    by_dn = {}

    def cand(g):
        dn = g.get("dn")
        if not dn:
            return None
        c = by_dn.get(dn)
        if c is None:
            c = {"dn": dn, "name": g.get("name", ""), "sid": g.get("sid", ""),
                 "grants": [], "jit_active": False, "sources": set()}
            by_dn[dn] = c
        return c

    def add_grant(c, kind, detail):
        if not any(x["kind"] == kind and x["detail"] == detail for x in c["grants"]):
            c["grants"].append({"kind": kind, "detail": detail})

    # SYSVOL local-admin machine mappings.
    for m in gpp_mappings:
        g = (groups_by_sid.get((m.get("group_sid") or "").upper())
             or groups_by_name.get((m.get("group_name") or "").split("\\")[-1].lower()))
        c = cand(g) if g else None
        if c:
            add_grant(c, "local_admin", m.get("target_computer", ""))
            c["sources"].add("sysvol")

    # Live TTL groups (JIT active right now - the strongest fact).
    ttl_count = {}
    for t in ttl_members:
        g = (groups_by_sid.get((t.get("group_sid") or "").upper())
             or groups_by_name.get((t.get("group_sam") or t.get("group") or "").split("\\")[-1].lower()))
        c = cand(g) if g else None
        if c:
            c["jit_active"] = True
            c["sources"].add("ttl")
            ttl_count[c["dn"]] = ttl_count.get(c["dn"], 0) + 1
    for dn, n in ttl_count.items():
        add_grant(by_dn[dn], "jit_active", f"{n} live TTL member(s) now")

    for c in by_dn.values():
        c["sources"] = sorted(c["sources"])
    return list(by_dn.values())


def discover_delegated_groups(conn, base_dn, groups):
    """Read EVERY group's membership DACL in one bulk sweep (the default) and return
    (candidates, sd_cache). A candidate is any group with a non-inherited,
    non-privileged membership writer - i.e. membership delegated to a non-admin, the
    defining, factual trait of a requestable/JIT-managed group whatever its name.
    This is what finds requestable groups no naming heuristic would catch. --fast
    skips it. The returned sd_cache is reused so DACLs are not read twice.
    """
    dns = [g["dn"] for g in groups if g.get("dn")]
    sd_cache = _read_group_sds(conn, base_dn, dns)
    by_dn = {g["dn"].lower(): g for g in groups if g.get("dn")}
    candidates = []
    for low, raw in sd_cache.items():
        g = by_dn.get(low)
        if not g:
            continue
        try:
            appr, _ = _extract_membership_writers(raw)
        except Exception:
            continue
        delegated = [a for a in appr
                     if not a.get("inherited") and not _is_privileged_sid(a["sid"])]
        if delegated:
            candidates.append({
                "dn": g["dn"], "name": g["name"], "sid": g.get("sid", ""),
                "grants": [{"kind": "delegated",
                            "detail": "membership writable by a non-admin (DACL)"}],
                "jit_active": False, "sources": ["delegated"], "confidence": "confirmed",
            })
    return candidates, sd_cache


def merge_candidates(base, extra):
    """Merge extra candidate groups into base (by DN), unioning grants/sources."""
    by_dn = {c["dn"]: c for c in base}
    for c in extra:
        cur = by_dn.get(c["dn"])
        if cur is None:
            by_dn[c["dn"]] = dict(c)
            continue
        for gr in c.get("grants", []):
            if not any(x["kind"] == gr["kind"] and x["detail"] == gr["detail"]
                       for x in cur["grants"]):
                cur["grants"].append(gr)
        cur["sources"] = sorted(set(cur.get("sources", [])) | set(c.get("sources", [])))
        cur["jit_active"] = cur.get("jit_active") or c.get("jit_active")
        if c.get("confidence") == "confirmed":
            cur["confidence"] = "confirmed"
    return list(by_dn.values())


# ============================================================================
#  Signal 5 - SYSVOL group->machine mapping (GPP + Restricted Groups)
# ============================================================================
# SYSVOL sources parsed for a group -> local-Administrators mapping. GPP has a
# per-item FilterComputer; Restricted Groups do not (their scope is the OUs/sites
# the GPO is linked to - resolved separately from gPLink back-references).
_SYSVOL_SOURCES = (
    ("Machine\\Preferences\\Groups\\Groups.xml", "gpp_machine"),
    ("User\\Preferences\\Groups\\Groups.xml", "gpp_user"),
    ("Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf", "restricted_groups"),
)


def collect_sysvol_gpp(dc_host, domain, username, password=None, nt_hash=None,
                       use_kerberos=False):
    """Read SYSVOL and map groups to local Administrators on their targets.

    Sources (each mapping is tagged with 'source'):
      - GPP Groups.xml, machine side (gpp_machine)
      - GPP Groups.xml, user side    (gpp_user)
      - Restricted Groups GptTmpl.inf (restricted_groups)

    Returns list of {group_name, group_sid, target_computer, gpo_guid, source}.
    Restricted-group entries have no per-item computer filter; their
    target_computer is left as the sentinel '(GPO-linked scope)' and refined later
    by resolve_gpo_scope(). Read-only SMB access."""
    lmhash = nthash = ""
    if nt_hash:
        if ":" in nt_hash:
            lmhash, nthash = nt_hash.split(":", 1)
        else:
            nthash = nt_hash
    results = []
    try:
        smb = SMBConnection(dc_host, dc_host, timeout=SMB_TIMEOUT)
        if use_kerberos:
            # Reuse the KRB5CCNAME ticket cache, consistent with the LDAP bind.
            smb.kerberosLogin(username, password or "", domain, lmhash, nthash,
                              kdcHost=dc_host, useCache=True)
        else:
            smb.login(username, password or "", domain, lmhash, nthash)
    except Exception as exc:
        console.print(f"[yellow][~][/] SYSVOL SMB login failed: {exc}")
        return results

    share = "SYSVOL"
    policies_path = f"{domain}\\Policies"
    try:
        gpo_dirs = [f.get_longname() for f in smb.listPath(share, policies_path + "\\*")
                    if f.is_directory() and f.get_longname() not in (".", "..")]
    except Exception as exc:
        console.print(f"[yellow][~][/] Cannot list SYSVOL Policies: {exc}")
        smb.close()
        return results

    for gpo in gpo_dirs:
        for rel, source in _SYSVOL_SOURCES:
            remote = f"{policies_path}\\{gpo}\\{rel}"
            buf = io.BytesIO()
            try:
                smb.getFile(share, remote, buf.write)
            except Exception:
                continue  # this GPO has no such file
            data = buf.getvalue()
            if not data:
                continue
            try:
                if source == "restricted_groups":
                    results.extend(_parse_gpttmpl_inf(data, gpo, source))
                else:
                    results.extend(_parse_groups_xml(data, gpo, source))
            except Exception:
                continue  # one malformed policy file must not abort the run
    smb.close()
    return results


def _xml_local(tag):
    """ElementTree tag local-name helper, tolerant of XML namespaces."""
    return str(tag).rsplit("}", 1)[-1]


def _xml_children(el, name):
    return [c for c in list(el) if _xml_local(c.tag) == name]


def _xml_child(el, name):
    return _first(_xml_children(el, name))


def _truthy_xml_attr(value):
    return str(value or "").strip().lower() in ("1", "true", "yes")


def _short_list(values, limit=4):
    values = [str(v) for v in values if v]
    text = ", ".join(values[:limit])
    if len(values) > limit:
        text += f", +{len(values) - limit} more"
    return text


def _parse_groups_xml(data, gpo_guid, source="gpp_machine"):
    """Parse a GPP Groups.xml: find groups adding a member to local
    Administrators, with the computer filter (target machine)."""
    out = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return out
    for group in [el for el in root.iter() if _xml_local(el.tag) == "Group"]:
        props = _xml_child(group, "Properties")
        if props is None:
            continue
        if (group.get("action") or props.get("action") or "").upper() == "D":
            continue
        gsid = (props.get("groupSid") or "").strip()
        gname = (props.get("groupName") or "").strip()
        # Only interested in ACLs targeting local Administrators.
        if gsid != ADMINISTRATORS_SID and "administrators" not in gname.lower():
            continue
        # Member(s) being ADDed to local admin.
        added = []
        members_el = _xml_child(props, "Members")
        if members_el is not None:
            for m in _xml_children(members_el, "Member"):
                if (m.get("action") or "").upper() == "ADD":
                    added.append({"name": m.get("name") or "",
                                  "sid": m.get("sid") or ""})
        # Computer filter (which machines the GPO applies to).
        targets, excluded = [], []
        filters_el = _xml_child(group, "Filters")
        if filters_el is not None:
            for fc in _xml_children(filters_el, "FilterComputer"):
                if fc.get("name"):
                    if _truthy_xml_attr(fc.get("not")):
                        excluded.append(fc.get("name"))
                    else:
                        targets.append(fc.get("name"))
        for member in added:
            if targets:
                for tgt in targets:
                    out.append({"group_name": member["name"],
                                "group_sid": member["sid"],
                                "target_computer": tgt, "gpo_guid": gpo_guid,
                                "source": source})
            elif excluded:
                note = f"(ILT: all except {_short_list(excluded)})"
                out.append({"group_name": member["name"],
                            "group_sid": member["sid"],
                            "target_computer": note, "gpo_guid": gpo_guid,
                            "source": source,
                            "filter_note": f"excluded_computers={'; '.join(excluded)}"})
            else:
                out.append({"group_name": member["name"],
                            "group_sid": member["sid"],
                            "target_computer": "(no filter / all)",
                            "gpo_guid": gpo_guid, "source": source})
    return out


def _decode_inf(data):
    """GptTmpl.inf is usually UTF-16 LE (with BOM). Decode robustly to text."""
    if isinstance(data, str):
        return data
    for enc in ("utf-16", "utf-8-sig", "utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="replace")


def _is_administrators(token):
    """True if an INF principal token refers to the built-in Administrators group
    (by SID '*S-1-5-32-544' or by a name containing 'administrators')."""
    t = (token or "").strip().lstrip("*").strip()
    if t.upper() == ADMINISTRATORS_SID:
        return True
    return "administrators" in t.lower()


def _split_inf_list(value):
    """Split a comma-separated INF value into non-empty trimmed tokens."""
    return [tok.strip() for tok in (value or "").split(",") if tok.strip()]


def _principal_name_sid(token):
    """Interpret an INF principal token -> (name, sid).

    '*S-1-5-...' is a SID; 'DOMAIN\\group' or 'group' is a name.
    """
    t = (token or "").strip()
    if t.startswith("*") and re.match(r'^\*S-1-', t, re.IGNORECASE):
        return "", t.lstrip("*")
    if re.match(r'^S-1-', t, re.IGNORECASE):
        return "", t
    return t, ""


def _parse_gpttmpl_inf(data, gpo_guid, source="restricted_groups"):
    """Parse a Restricted Groups GptTmpl.inf [Group Membership] section.

    Two equivalent forms both mean "X becomes a local admin":
      <Administrators>__Members   = X, Y     (X, Y added to Administrators)
      <X>__Memberof               = <Administrators>   (X is a member of Admins)

    Returns list of {group_name, group_sid, target_computer, gpo_guid, source}.
    The target machine(s) are not encoded here (no per-item filter); resolved from
    gPLink later, so target_computer is the sentinel '(GPO-linked scope)'.
    """
    out = []
    text = _decode_inf(data)
    if not text:
        return out

    # Collect the [Group Membership] section's key=value pairs.
    entries = []
    in_section = False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        if s.startswith("[") and s.endswith("]"):
            in_section = (s.lower() == "[group membership]")
            continue
        if in_section and "=" in s:
            key, _, val = s.partition("=")
            entries.append((key.strip(), val.strip()))

    scope = "(GPO-linked scope)"
    for key, val in entries:
        low = key.lower()
        if low.endswith("__members") and _is_administrators(key[:-len("__Members")]):
            for token in _split_inf_list(val):
                name, sid = _principal_name_sid(token)
                out.append({"group_name": name, "group_sid": sid,
                            "target_computer": scope, "gpo_guid": gpo_guid,
                            "source": source})
        elif low.endswith("__memberof"):
            principal = key[:-len("__Memberof")]
            if any(_is_administrators(t) for t in _split_inf_list(val)):
                name, sid = _principal_name_sid(principal)
                out.append({"group_name": name, "group_sid": sid,
                            "target_computer": scope, "gpo_guid": gpo_guid,
                            "source": source})
    return out


def resolve_gpo_links(conn, base_dn):
    """Map GPO GUID (lowercase, no braces) -> list of linked container DNs.

    Best-effort: searches for objects carrying a gPLink and extracts the GPO GUIDs
    each links to. Used to give Restricted-Groups mappings a scope (the OUs/domain
    the GPO applies to), since they have no per-item computer filter.
    """
    links = {}
    try:
        entries = conn.extend.standard.paged_search(
            base_dn, "(gPLink=*)", search_scope=SUBTREE,
            attributes=["distinguishedName", "gPLink"],
            paged_size=200, generator=True)
    except Exception:
        return links
    guid_rx = re.compile(r'CN=\{([0-9A-Fa-f\-]+)\}', re.IGNORECASE)
    for e in entries:
        if e.get("type") != "searchResEntry":
            continue
        attrs = e.get("attributes") or {}
        dn = _to_text(attrs.get("distinguishedName"))
        gplink = _to_text(attrs.get("gPLink"))
        for guid in guid_rx.findall(gplink):
            links.setdefault(guid.lower(), []).append(dn)
    return links


def apply_gpo_scope(mappings, gpo_links):
    """Refine Restricted-Groups (and unfiltered GPP) targets using gPLink scope.

    Sets each affected mapping's 'scope' to the linked OUs/domain, and rewrites the
    '(GPO-linked scope)' sentinel target_computer to that scope, or to
    'GPO <guid> linked scope (unresolved)' when link resolution found nothing.
    """
    for m in mappings:
        guid = (m.get("gpo_guid") or "").strip().strip("{}").lower()
        linked = gpo_links.get(guid, [])
        needs_scope = (m.get("source") == "restricted_groups"
                       or m.get("target_computer") in ("(GPO-linked scope)", "(no filter / all)"))
        if not needs_scope:
            m.setdefault("scope", m.get("target_computer", ""))
            continue
        if linked:
            scope = "; ".join(linked)
        else:
            scope = f"GPO {m.get('gpo_guid', '?')} linked scope (unresolved)"
        m["scope"] = scope
        if m.get("target_computer") == "(GPO-linked scope)":
            m["target_computer"] = scope
    return mappings


# ============================================================================
#  Correlation - active access (live TTL x machine mapping)
# ============================================================================
def correlate_active_access(ttl_members, gpp_mappings, dn_to_name):
    """Join live TTL memberships (Signal 3) with the group->machine mapping
    (Signal 5): who holds elevated access on which machine, right now, and for
    how much longer.

    Returns list of {member, member_dn, group, target_computer, access,
    ttl_seconds, expires_human, source}.
    """
    # Prefer SID joins (authoritative), then fall back to short names for older
    # policy entries or forged/offline inputs that do not carry objectSid.
    by_sid = {}
    by_group = {}
    for m in gpp_mappings:
        sid = (m.get("group_sid") or "").upper()
        if sid:
            by_sid.setdefault(sid, []).append(m)
        gname = (m.get("group_name") or "").split("\\")[-1].lower()
        if gname:
            by_group.setdefault(gname, []).append(m)

    out = []
    for t in ttl_members:
        matches, seen = [], set()

        def add_matches(candidates):
            for candidate in candidates:
                key = (candidate.get("group_sid", "").upper(),
                       candidate.get("group_name", ""),
                       candidate.get("target_computer", ""),
                       candidate.get("gpo_guid", ""))
                if key not in seen:
                    seen.add(key)
                    matches.append(candidate)

        tsid = (t.get("group_sid") or "").upper()
        if tsid:
            add_matches(by_sid.get(tsid, []))
        if not matches:
            names = {
                (t.get("group") or "").split("\\")[-1].lower(),
                (t.get("group_sam") or "").split("\\")[-1].lower(),
            }
            for gname in [n for n in names if n]:
                add_matches(by_group.get(gname, []))

        for m in matches:
            member_name = dn_to_name.get(t["member_dn"].lower(),
                                         t["member_dn"].split(",")[0])
            out.append({
                "member": member_name,
                "member_dn": t["member_dn"],
                "group": t["group"],
                "target_computer": m.get("target_computer", ""),
                "access": "local Administrators",
                "ttl_seconds": t["ttl_seconds"],
                "expires_human": _human_ttl(t["ttl_seconds"]),
                "source": m.get("source", ""),
            })
    return out


# ============================================================================
#  Correlation - attack-surface paths
# ============================================================================
def build_attack_paths(workflow_groups, gpp_mappings, group_dacls=None,
                       target_groups=None, include_privileged=False):
    """Correlate requestable groups with their unlocked machines and the approvers
    who can grant them.

    Approvers come from the target group's DACL (authoritative - who can write its
    'member' attribute); the heuristic 'approve'-named group membership is kept as
    a clearly-labelled secondary hint only.

    Returns (paths, approvers, requesters, heuristic_approvers) where each path is
    {group, group_full, target_computer, access, approvers (authoritative names),
     approvers_dacl [{sid,name,right,inherited,privileged}],
     approvers_heuristic [names], self_members [{sid,name}], requesters,
     readable, source, scope, gpo_guid}.
    """
    group_dacls = group_dacls or {}
    target_groups = target_groups or []

    # Index the DACL results by SID and short name for lookup per mapping.
    dacl_by_sid, dacl_by_name = {}, {}
    for tg in target_groups:
        info = group_dacls.get(tg.get("dn"))
        if not info:
            continue
        if tg.get("sid"):
            dacl_by_sid[tg["sid"].upper()] = info
        if tg.get("name"):
            dacl_by_name[tg["name"].lower()] = info

    # Heuristic approvers/requesters from workflow group membership (secondary).
    heur_appr, requesters = [], []
    for g in workflow_groups:
        if "approve" in g["categories"]:
            heur_appr.extend(g["members"])
        if "request" in g["categories"]:
            requesters.extend(g["members"])
    heur_appr = sorted(set(heur_appr))
    requesters = sorted(set(requesters))

    paths = []
    for m in gpp_mappings:
        mapped_group = m.get("group_name", "")
        lookup_name = mapped_group.split("\\")[-1]
        info = (dacl_by_sid.get((m.get("group_sid") or "").upper())
                or dacl_by_name.get(lookup_name.lower()))
        group_full = (mapped_group
                      or (info.get("name", "") if info else "")
                      or m.get("group_sid", ""))
        gname = group_full.split("\\")[-1]
        approvers_dacl, self_members = [], []
        dacl_readable = None
        if info:
            dacl_readable = info.get("readable", True)
            for a in info["approvers"]:
                if a.get("privileged") and not include_privileged:
                    continue  # noise: SYSTEM/Domain Admins/... can write any group
                approvers_dacl.append(a)
            self_members = info.get("self_members", [])
        # Authoritative names if the DACL was readable. If a DACL read was attempted
        # and failed, keep the authoritative field empty and expose the heuristic
        # separately so exports do not silently guess.
        if info and dacl_readable:
            approver_names = sorted({a["name"] for a in approvers_dacl})
        elif info and dacl_readable is False:
            approver_names = []
        else:
            approver_names = heur_appr
        paths.append({
            "group": gname,
            "group_full": group_full,
            "target_computer": m.get("target_computer", ""),
            "access": "local Administrators",
            "approvers": approver_names,               # backward-compatible field
            "approvers_dacl": approvers_dacl,          # authoritative, detailed
            "approvers_heuristic": heur_appr,          # secondary name hint
            "self_members": self_members,              # self-only writers (note)
            "requesters": requesters,
            "readable": dacl_readable,
            "source": m.get("source", "gpp_machine"),
            "scope": m.get("scope", m.get("target_computer", "")),
            "gpo_guid": m.get("gpo_guid", ""),
        })

    # Flat authoritative approver set across all paths (falls back to heuristic).
    dacl_names = sorted({a["name"] for p in paths for a in p["approvers_dacl"]})
    approvers = dacl_names or heur_appr
    return paths, approvers, requesters, heur_appr


def build_requestable_groups(candidates, group_dacls, group_by_dn=None,
                             priv_index=None, include_privileged=False):
    """Fact-only requestable-group view. A group is included ONLY if it is actionable:
    it is JIT-active right now (a live TTL member) OR its membership is writable by a
    principal you could target (a DACL writer). Groups with no writer and no live TTL
    are dropped - they are not exploitable, so they are not shown.

    Each row: {group, group_dn, group_sid, jit_active, machines, privileged_of,
    grants_summary (short, factual), approvers_dacl, self_members, readable, sources}.
    """
    group_by_dn = group_by_dn or {}
    priv_index = priv_index or {}
    rows = []
    for c in candidates:
        info = group_dacls.get(c["dn"])
        approvers_dacl, self_members, readable = [], [], None
        if info:
            readable = info.get("readable", True)
            for a in info["approvers"]:
                if a.get("privileged") and not include_privileged:
                    continue
                approvers_dacl.append(a)
            self_members = info.get("self_members", [])
        jit_active = c.get("jit_active", False)
        # Actionable only: a writer you can target, or JIT happening right now.
        if not approvers_dacl and not jit_active:
            continue

        machines = sorted({g["detail"] for g in c.get("grants", [])
                           if g["kind"] == "local_admin" and g["detail"]})
        gobj = group_by_dn.get(c["dn"].lower())
        privileged_of = []
        if gobj:
            privileged_of = [priv_index[mo] for mo in gobj.get("memberof", [])
                             if mo in priv_index]
            if gobj.get("admincount"):
                privileged_of.append("adminCount (protected)")
        privileged_of = sorted(set(privileged_of))

        parts = []
        if jit_active:
            parts.append("JIT-active now")
        if machines:
            parts.append("local admin: " + _short_list(machines, 3))
        if privileged_of:
            parts.append("member of " + _short_list(privileged_of, 2))
        if not parts:
            parts.append("membership delegated (grant not confirmed in AD)")

        rows.append({
            "group": c["name"], "group_dn": c["dn"], "group_sid": c.get("sid", ""),
            "jit_active": jit_active,
            "machines": machines,
            "privileged_of": privileged_of,
            "grants_summary": "; ".join(parts),
            "sources": sorted(c.get("sources", [])),
            "approvers_dacl": approvers_dacl,
            "self_members": self_members,
            "readable": readable,
        })
    rows.sort(key=lambda r: (0 if r["jit_active"] else 1,
                             0 if r["machines"] else 1,
                             0 if r["approvers_dacl"] else 1,
                             r["group"].lower()))
    return rows


# ============================================================================
#  Recent-access forensics - replication metadata (--history)
# ============================================================================
#  Live TTL memberships only show what is active at scan time. Replication metadata
#  (msDS-ReplValueMetaData) on a group's 'member' linked values records the last
#  originating change per value - so it surfaces membership activity on groups that
#  unlock access: a short "who may have had elevated access lately" view. Read-only.
# ============================================================================
def _parse_repl_value_metadata(text):
    """Parse an msDS-ReplValueMetaData XML blob.

    Returns a list of {attribute, member_dn, version, created, deleted,
    last_change}. Tolerant of one or several DS_REPL_VALUE_META_DATA elements in
    one value, with or without an XML declaration.
    """
    out = []
    if not text:
        return out
    text = re.sub(r'<\?xml[^>]*\?>', '', text).strip()
    if not text:
        return out
    try:
        root = ET.fromstring(f"<root>{text}</root>")
    except ET.ParseError:
        return out

    def child_text(el, tag):
        c = el.find(tag)
        return c.text.strip() if c is not None and c.text else ""

    for el in root.iter():
        if not el.tag.startswith("DS_REPL_VALUE_META_DATA"):
            continue
        out.append({
            "attribute": child_text(el, "pszAttributeName"),
            "member_dn": child_text(el, "pszObjectDn"),
            "version": child_text(el, "dwVersion"),
            "created": child_text(el, "ftimeCreated"),
            "deleted": child_text(el, "ftimeDeleted"),
            "last_change": child_text(el, "ftimeLastOriginatingChange"),
        })
    return out


def collect_repl_history(conn, target_groups, dn_to_name):
    """Read msDS-ReplValueMetaData on each target group's 'member' links and report
    recent add/remove events. target_groups: list of {dn, name, sid}. Read-only.

    Returns list of {group, group_dn, member, member_dn, version, last_change,
    deleted}.
    """
    findings = []
    for tg in target_groups:
        dn = tg.get("dn")
        if not dn:
            continue
        try:
            conn.search(dn, "(objectClass=*)", search_scope=BASE,
                        attributes=["msDS-ReplValueMetaData"])
        except Exception:
            continue
        for e in conn.response:
            if e.get("type") != "searchResEntry":
                continue
            for val in _iter_values(_attr(e, "msDS-ReplValueMetaData")):
                for rec in _parse_repl_value_metadata(_to_text(val)):
                    if rec.get("attribute", "").lower() != "member":
                        continue
                    mdn = rec.get("member_dn", "")
                    findings.append({
                        "group": tg.get("name", "") or dn,
                        "group_dn": dn,
                        "member": dn_to_name.get(mdn.lower(), mdn.split(",")[0]),
                        "member_dn": mdn,
                        "version": rec.get("version", ""),
                        "last_change": rec.get("last_change", ""),
                        "deleted": rec.get("deleted", ""),
                    })
    return findings


# ============================================================================
#  JIT manager / approval engine detection
# ============================================================================
#  The approval workflow (a web app or a scheduled task) is not an AD object, but
#  the identity it uses to write group memberships IS - and it is the real target:
#  whoever controls it can self-approve. We pivot from that identity to locate the
#  manager itself (SPN host / approval web URL, gMSA host mapping), and separately
#  fingerprint known PAM/JIT products across the domain. Read-only.
# ============================================================================
def _derive_spn_targets(spns):
    """From SPNs derive (web_urls, hosts). An HTTP/WSMAN SPN points at the approval
    portal; every SPN host is where the identity runs / authenticates."""
    web, hosts = set(), set()
    for spn in spns:
        spn = _to_text(spn)
        if "/" not in spn:
            continue
        cls, rest = spn.split("/", 1)
        host = rest.split("/")[0].split(":")[0].strip()
        if not host:
            continue
        hosts.add(host)
        if cls.lower() in JIT_WEB_SPN_CLASSES:
            web.add(f"https://{host}/")
    return sorted(web), sorted(hosts)


def _sd_allowed_sids(sd_bytes):
    """Trustee SIDs granted access by a security descriptor's DACL (allow ACEs).

    Used on msDS-GroupMSAMembership: the principals allowed to retrieve a gMSA
    password are exactly the hosts/groups that run the service.
    """
    from impacket.ldap import ldaptypes
    out = []
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    except Exception:
        return out
    dacl = sd['Dacl']
    if not dacl:
        return out
    for ace in getattr(dacl, "aces", []):
        try:
            if ace['AceType'] in (ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE,
                                  ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
                out.append(ace['Ace']['Sid'].formatCanonical())
        except Exception:
            continue
    return out


def _match_pam_vendor(text, allow_generic=False):
    """First PAM/JIT fingerprint found in text -> (vendor, matched_token), else
    (None, None). Vendor tokens are matched separator-insensitively; the weaker
    generic tokens only when allow_generic is set (corroborating context)."""
    t = (text or "").lower()
    squashed = re.sub(r'[\s._\-]+', '', t)
    for vendor, tokens in JIT_VENDOR_FINGERPRINTS:
        for tok in tokens:
            tk = re.sub(r'[\s._\-]+', '', tok.lower())
            if tk and tk in squashed:
                return vendor, tok
    if allow_generic:
        for tok in JIT_GENERIC_TOKENS:
            if tok.lower() in t:
                return "generic JIT/PAM naming", tok
    return None, None


def enrich_jit_identities(conn, base_dn, membership_writers):
    """Pull the object behind each membership writer and derive where the JIT
    manager lives: SPN host(s) + approval web URL, and for a gMSA the servers
    allowed to retrieve its password (msDS-GroupMSAMembership). Read-only."""
    from ldap3.utils.conv import escape_bytes
    # A privileged writer (Domain Admins, SYSTEM, ...) is inherent admin power, not a
    # delegated JIT engine - exclude it so the identity table stays focused.
    candidates = [w for w in membership_writers if w.get("sid") and not w.get("privileged")]
    sids = sorted({w["sid"].upper() for w in candidates})
    if not sids:
        return []
    attrs = ["sAMAccountName", "distinguishedName", "objectClass", "objectSid",
             "servicePrincipalName", "description", "dNSHostName",
             "msDS-GroupMSAMembership", "userAccountControl"]
    objects = {}
    for i in range(0, len(sids), 20):
        parts = [f"(objectSid={escape_bytes(b)})"
                 for b in (_sid_string_to_bytes(s) for s in sids[i:i + 20]) if b is not None]
        if not parts:
            continue
        filt = "(|" + "".join(parts) + ")" if len(parts) > 1 else parts[0]
        try:
            conn.search(base_dn, filt, search_scope=SUBTREE, attributes=attrs)
        except Exception:
            continue
        for e in conn.response:
            if e.get("type") != "searchResEntry":
                continue
            sid = _sid_to_str(_first(_attr(e, "objectSid")))
            if sid:
                objects[sid.upper()] = e

    per_writer, gmsa_host_sids = {}, set()
    for w in candidates:
        sid = (w.get("sid") or "").upper()
        e = objects.get(sid)
        if not e:
            continue
        spns = [_to_text(s) for s in _iter_values(_attr(e, "servicePrincipalName"))]
        web, hosts = _derive_spn_targets(spns)
        typ = _principal_type(_attr(e, "objectClass"), has_spn=bool(spns))
        gmsa_sids = []
        raw_msa = _raw_attr(e, "msDS-GroupMSAMembership")
        if raw_msa:
            if isinstance(raw_msa, str):
                raw_msa = raw_msa.encode("latin-1", "replace")
            gmsa_sids = _sd_allowed_sids(raw_msa)
            gmsa_host_sids.update(gmsa_sids)
        per_writer[sid] = {
            "name": _to_text(_attr(e, "sAMAccountName")) or w.get("name", ""),
            "sid": sid,
            "dn": _to_text(_attr(e, "distinguishedName")) or w.get("dn", ""),
            "type": typ or w.get("type", ""),
            "spns": spns, "web_urls": web, "hosts": hosts,
            "description": _to_text(_attr(e, "description")),
            "dns": _to_text(_attr(e, "dNSHostName")),
            "unlocks": w.get("unlocks", []),
            "write_count": w.get("write_count", len(w.get("groups", []) or [])),
            "jit_active": w.get("jit_active", False),
            "privileged": w.get("privileged", False),
            "_gmsa_sids": gmsa_sids,
        }

    host_names = resolve_principals(conn, base_dn, sorted(gmsa_host_sids)) if gmsa_host_sids else {}
    identities = []
    for d in per_writer.values():
        gmsa_hosts = []
        for hs in d.pop("_gmsa_sids", []):
            r = host_names.get(hs.upper())
            gmsa_hosts.append((r or {}).get("name") or hs)
        d["gmsa_hosts"] = sorted(set(gmsa_hosts))
        d["confidence"], d["evidence"], d["vendor"] = _score_jit_identity(d)
        identities.append(d)
    rank = {"high": 0, "medium": 1, "low": 2}
    identities.sort(key=lambda x: (rank.get(x["confidence"], 3), x["name"].lower()))
    return identities


def _score_jit_identity(d):
    """Evidence-based confidence that a membership writer IS the JIT manager, rather
    than an incidental delegation. Returns (confidence, evidence[], vendor|"").

    The old rule ('any service account = high') produced false positives because
    almost every service account has an SPN. We now require corroboration:
    gMSA, a vendor name/SPN match, writing a group that is JIT-active right now, an
    approval web SPN, or writing membership on several requestable groups.
    """
    ev = []
    wc = d.get("write_count", 0)
    web = bool(d.get("web_urls"))
    vendor, _tok = _match_pam_vendor(
        " ".join([d.get("name", ""), d.get("dn", ""), " ".join(d.get("spns", []))]))
    if d.get("type") == "gMSA":
        ev.append("gMSA (dedicated managed identity)")
    if vendor:
        ev.append(f"name/SPN matches {vendor}")
    if d.get("jit_active"):
        ev.append("can write a group that is JIT-active right now")
    if web:
        ev.append("HTTP/WSMAN SPN (approval web portal)")
    if wc >= 3:
        ev.append(f"writes membership on {wc} requestable groups")
    elif wc == 2:
        ev.append("writes membership on 2 requestable groups")

    strong = (d.get("type") == "gMSA" or bool(vendor) or d.get("jit_active")
              or (wc >= 3 and (web or d.get("type") == "service account")))
    # A single delegation with no corroboration is only 'low' - even a service
    # account (almost all have an SPN). Medium needs breadth (>=2 groups) or a
    # web portal SPN.
    medium = wc >= 2 or web
    confidence = "high" if strong else ("medium" if medium else "low")
    if not ev:
        ev.append("can write group membership (single delegation, no corroboration)")
    return confidence, ev, (vendor or "")


def scan_pam_vendors(conn, base_dn):
    """Domain-wide fingerprint scan for known PAM/JIT products (indicative). Uses
    indexed attributes (sAMAccountName / cn / servicePrincipalName) to stay fast,
    plus serviceConnectionPoint objects. Read-only, fails soft."""
    tokens = sorted({t for _, toks in JIT_VENDOR_FINGERPRINTS for t in toks})
    attrs = ["sAMAccountName", "distinguishedName", "objectClass",
             "servicePrincipalName", "cn", "description", "dNSHostName"]
    found = {}
    for i in range(0, len(tokens), 10):
        clauses = "".join(f"(sAMAccountName=*{t}*)(cn=*{t}*)(servicePrincipalName=*{t}*)"
                          for t in tokens[i:i + 10])
        try:
            entries = conn.extend.standard.paged_search(
                base_dn, "(|" + clauses + ")", search_scope=SUBTREE,
                attributes=attrs, paged_size=200, generator=True)
        except Exception:
            continue
        for e in entries:
            if e.get("type") != "searchResEntry":
                continue
            a = e.get("attributes") or {}
            dn = _to_text(a.get("distinguishedName"))
            if not dn or dn in found:
                continue
            spns = [_to_text(s) for s in _iter_values(a.get("servicePrincipalName"))]
            text = " ".join([_to_text(a.get("sAMAccountName")), _to_text(a.get("cn")),
                             _to_text(a.get("description")), " ".join(spns), dn])
            vendor, tok = _match_pam_vendor(text)
            if not vendor:
                continue
            web, hosts = _derive_spn_targets(spns)
            found[dn] = {"vendor": vendor, "match": tok, "dn": dn,
                         "name": _to_text(a.get("sAMAccountName")) or _to_text(a.get("cn")),
                         "type": _principal_type(a.get("objectClass"), has_spn=bool(spns)),
                         "spns": spns, "web_urls": web, "hosts": hosts,
                         "dns": _to_text(a.get("dNSHostName"))}
    try:
        entries = conn.extend.standard.paged_search(
            base_dn, "(objectClass=serviceConnectionPoint)", search_scope=SUBTREE,
            attributes=["cn", "distinguishedName", "keywords", "serviceDNSName",
                        "serviceBindingInformation"], paged_size=200, generator=True)
        for e in entries:
            if e.get("type") != "searchResEntry":
                continue
            a = e.get("attributes") or {}
            dn = _to_text(a.get("distinguishedName"))
            if not dn or dn in found:
                continue
            text = " ".join([_to_text(a.get("cn")),
                             " ".join(_to_text(x) for x in _iter_values(a.get("keywords"))),
                             _to_text(a.get("serviceDNSName")),
                             " ".join(_to_text(x) for x in _iter_values(a.get("serviceBindingInformation"))),
                             dn])
            vendor, tok = _match_pam_vendor(text, allow_generic=True)
            if not vendor:
                continue
            dns = _to_text(a.get("serviceDNSName"))
            found[dn] = {"vendor": vendor, "match": tok, "dn": dn,
                         "name": _to_text(a.get("cn")), "type": "serviceConnectionPoint",
                         "spns": [], "web_urls": [], "hosts": [dns] if dns else []}
    except Exception:
        pass
    return sorted(found.values(), key=lambda x: (x["vendor"], (x["name"] or "").lower()))


def detect_jit_manager(conn, base_dn, membership_writers):
    """Locate the JIT manager / approval engine.

    Returns {'identities': [...], 'vendors': [...]}:
      identities - the accounts that actually write JIT memberships, enriched with
                   SPN host / approval web URL and gMSA host mapping (high confidence,
                   environment-agnostic);
      vendors    - domain-wide fingerprint hits for known PAM/JIT products (indicative).
    Read-only.
    """
    return {
        "identities": enrich_jit_identities(conn, base_dn, membership_writers),
        "vendors": scan_pam_vendors(conn, base_dn),
    }


# ============================================================================
#  Display
# ============================================================================
def print_banner():
    t = Text()
    t.append(f"{TOOL_NAME} ", style="bold magenta")
    t.append(f"v{VERSION}", style="magenta")
    t.append("   JIT / PAM posture and attack-surface scanner", style="dim")
    console.print(Panel(t, box=box.ROUNDED, border_style="magenta", padding=(0, 2)))


def _table(title, title_style="bold magenta", danger=False, expand=False):
    """Consistent bordered table with row separators (readable in a terminal).

    show_lines draws a rule between rows; rich auto-downgrades the box glyphs to
    ASCII (+/-/|) on legacy consoles (safe_box), so the separators survive
    everywhere. CLI strings elsewhere stay ASCII for the same reason.
    """
    return Table(
        title=title, title_style=title_style, title_justify="left",
        box=box.ROUNDED, show_lines=True, expand=expand, padding=(0, 1),
        header_style="bold white on red3" if danger else "bold cyan",
        border_style="red3" if danger else "grey42",
    )


def _legend(lines, title="notes"):
    """Render footnotes as a subtle panel instead of loose dim text."""
    if not lines:
        return
    body = Text()
    for i, ln in enumerate(lines):
        if i:
            body.append("\n")
        body.append(Text.from_markup(f"[grey62]-[/] {ln}"))
    console.print(Panel(body, title=title, title_align="left", box=box.ROUNDED,
                        border_style="grey37", padding=(0, 1)))


def _e(value):
    """Escape rich console markup in AD-derived text before it goes in a table
    cell. AD names/DNs/descriptions can contain '[' ']' which rich would otherwise
    parse as markup - at best mis-rendering, at worst raising MarkupError."""
    return rich_escape(str(value if value is not None else ""))


def print_posture(pam_enabled, pam_scopes, shadows, ttl_members, workflow_groups,
                  active_access=None, pam_trust=None, tiering=None):
    active_access = active_access or []
    pam_trust = pam_trust or []
    tiering = tiering or {}
    shadow_ttls = sum(len(s.get("member_ttls", [])) for s in shadows)
    body = Text()
    if pam_enabled:
        body.append("PAM feature: ", style="bold")
        body.append("ENABLED", style="bold green")
        body.append(f"  ({len(pam_scopes)} scope(s)) -> JIT is possible\n")
    else:
        body.append("PAM feature: ", style="bold")
        body.append("not enabled", style="yellow")
        body.append("  -> native JIT/temporary memberships unavailable\n")
    # PAM bastion trust - definitive (the PIM trustAttributes bit).
    body.append("PAM bastion trust: ", style="bold")
    if pam_trust:
        body.append("YES", style="bold green")
        body.append(f"  ({', '.join(t['partner'] for t in pam_trust)}) "
                    "-> MIM/PAM bastion confirmed\n")
    else:
        body.append("none", style="dim")
        body.append("  (no PIM-trust; not a MIM bastion deployment)\n")
    body.append(f"Shadow principals: ", style="bold")
    body.append(f"{len(shadows)}", style="cyan")
    body.append("  (bastion/MIM PAM indicator")
    if shadow_ttls:
        body.append(f", {shadow_ttls} time-bound", style="red")
    body.append(")\n")
    body.append(f"Live TTL memberships: ", style="bold")
    style = "bold red" if ttl_members else "dim"
    body.append(f"{len(ttl_members)}", style=style)
    body.append("  (active JIT windows at scan time)\n")
    body.append(f"Active elevated access (correlated): ", style="bold")
    style = "bold red" if active_access else "dim"
    body.append(f"{len(active_access)}", style=style)
    body.append("  (live TTL member x unlocked machine)\n")
    # Tiering hardening facts (accompany a mature JIT model).
    pu = tiering.get("protected_users")
    silos = tiering.get("authn_silos", [])
    if pu is not None or silos:
        body.append("Tiering hardening: ", style="bold")
        parts = []
        if pu is not None:
            parts.append(f"Protected Users={pu}")
        if silos:
            enf = sum(1 for s in silos if s.get("enforced"))
            parts.append(f"AuthN silos={len(silos)} ({enf} enforced)")
        body.append(", ".join(parts), style="cyan")
        body.append("\n")
    body.append(f"Workflow groups (heuristic): ", style="bold")
    body.append(f"{len(workflow_groups)}", style="cyan")
    console.print(Panel(body, title="JIT posture", border_style="magenta", box=box.ROUNDED))


def print_ttl_table(ttl_members):
    if not ttl_members:
        return
    table = _table("Active temporary memberships (LINK_TTL)", title_style="bold red")
    table.add_column("Group", style="yellow")
    table.add_column("Member", style="green")
    table.add_column("Expires in", style="bold red")
    for t in sorted(ttl_members, key=lambda x: x["ttl_seconds"]):
        table.add_row(_e(t["group"]), _e(t["member_dn"].split(",")[0]),
                      _human_ttl(t["ttl_seconds"]))
    console.print(table)


def print_shadow_ttls(shadows):
    """Time-bound (TTL) memberships on shadow principals, if any."""
    rows = [(s["name"], mt) for s in shadows for mt in s.get("member_ttls", [])]
    if not rows:
        return
    table = _table("Shadow principal time-bound memberships (LINK_TTL)",
                   title_style="bold red")
    table.add_column("Shadow principal", style="magenta")
    table.add_column("Member", style="green")
    table.add_column("Expires in", style="bold red")
    for sname, mt in sorted(rows, key=lambda x: x[1]["ttl_seconds"]):
        table.add_row(_e(sname), _e(mt["member_dn"].split(",")[0]), mt["expires_human"])
    console.print(table)


def print_active_access(active_access):
    """High-visibility real-time view: who holds elevated access right now."""
    if not active_access:
        return
    table = _table("ACTIVE ELEVATED ACCESS  (live right now)", title_style="bold red",
                   danger=True, expand=True)
    table.add_column("Member", style="bold green", no_wrap=True)
    table.add_column("Has admin on", style="bold yellow")
    table.add_column("Access", style="red")
    table.add_column("Via group", style="cyan")
    table.add_column("Expires in", style="bold red")
    for a in sorted(active_access, key=lambda x: x["ttl_seconds"]):
        table.add_row(_e(a["member"]), _e(a["target_computer"]), _e(a["access"]),
                      _e(a["group"]), a["expires_human"])
    console.print(table)


def print_workflow_table(workflow_groups, verbose=False):
    """Default view shows only the actors (request/approve groups). --verbose
    restores localadmin/privileged categories."""
    if not workflow_groups:
        return
    if verbose:
        shown = list(workflow_groups)
        title = "Workflow groups (heuristic - verbose)"
    else:
        shown = [g for g in workflow_groups
                 if {"request", "approve"} & set(g["categories"])]
        title = "Workflow groups (heuristic - request / approve)"
    if not shown:
        return
    table = _table(title)
    table.add_column("Group", style="green", no_wrap=True)
    table.add_column("Categories", style="blue")
    table.add_column("Members", style="dim")
    for g in sorted(shown, key=lambda x: x["name"]):
        members = ", ".join(g["members"][:6]) + (" ..." if len(g["members"]) > 6 else "")
        table.add_row(_e(g["name"]), _e(", ".join(g["categories"])), _e(members or "-"))
    console.print(table)
    _legend(["Request/approve here is a [italic]name/description heuristic[/] and can "
             "miss oddly-named groups.",
             "The authoritative approvers are read from group DACLs - see the "
             "[bold]Membership writers[/] table below."],
            title="workflow groups")


def _type_style(typ):
    """Highlight the high-value account types (the ones worth targeting)."""
    if typ in ("service account", "gMSA"):
        return f"[bold red]{typ}[/]"
    if typ == "unresolved":
        return "[dim]unresolved[/]"
    return _e(typ) if typ else "[dim]?[/]"


def _conf_style(conf):
    """Colour a confidence / certainty label consistently."""
    return {
        "high": "[bold red]high[/]", "medium": "[yellow]medium[/]", "low": "[dim]low[/]",
        "confirmed": "[bold green]confirmed[/]", "heuristic": "[yellow]heuristic[/]",
    }.get(conf, _e(conf or "-"))


def _approver_cell(path):
    """Approver column: authoritative DACL writers (name, type, right)."""
    dacl = path.get("approvers_dacl") or []
    if dacl:
        parts = []
        for a in dacl[:4]:
            name = rich_escape(str(a.get("name", "")))
            typ = f" [dim]{rich_escape(str(a.get('type')))}[/]" if a.get("type") else ""
            right = rich_escape(str(a.get("right", "")))
            priv = " [dim](priv)[/]" if a.get("privileged") else ""
            inh = " [dim](inherited)[/]" if a.get("inherited") else ""
            parts.append(f"[bold]{name}[/]{typ} [grey62]{right}[/]{priv}{inh}")
        cell = "\n".join(parts)
        if len(dacl) > 4:
            cell += f"\n[dim]... +{len(dacl) - 4} more[/]"
        return cell
    if path.get("readable") is False:
        return "[dim](DACL unreadable - insufficient rights)[/]"
    heur = path.get("approvers") or []
    if heur:
        txt = ", ".join(heur[:4]) + (" ..." if len(heur) > 4 else "")
        return f"[yellow]{txt}[/] [dim](heuristic only)[/]"
    return "[dim](none found)[/]"


def print_attack_paths(paths):
    if not paths:
        return
    table = _table("JIT attack surface  (SYSVOL group -> machine local admin)", expand=True)
    table.add_column("Requestable group", style="bold green", no_wrap=True)
    table.add_column("Unlocks (machine / scope)", style="bold yellow")
    table.add_column("Access", style="red")
    table.add_column("Approvers  (DACL: can write 'member')", style="blue")
    table.add_column("Source", style="dim", no_wrap=True)
    for p in sorted(paths, key=lambda x: (x["target_computer"], x["group"])):
        table.add_row(_e(p["group"]), _e(p["target_computer"]), _e(p["access"]),
                      _approver_cell(p), _e(p.get("source", "")))
    console.print(table)


def _req_approver_cell(r):
    """Approver cell for a requestable row - factual writers, or a clear reason."""
    if r.get("approvers_dacl"):
        return _approver_cell(r)
    if r.get("readable") is False:
        return "[dim](membership DACL not readable)[/]"
    if r.get("jit_active"):
        return "[dim](no non-admin writer - JIT active regardless)[/]"
    return "[dim]-[/]"


def print_requestable_groups(rows, include_privileged=False, fast=False):
    """Fact-only view: groups that are JIT-active now or whose membership is writable
    by a principal you can target. What it grants + who can add you. No name guessing."""
    if not rows:
        msg = ("No JIT-active groups and no delegated (non-admin writable) group "
               "memberships found.")
        if fast:
            msg += " (--fast skipped the full DACL sweep; drop it to scan every group.)"
        console.print(Panel(f"[yellow]{msg}[/]", border_style="yellow", box=box.ROUNDED))
        return
    table = _table("REQUESTABLE GROUPS  (JIT-active or membership delegated - facts only)",
                   title_style="bold red", expand=True)
    table.add_column("Group", style="bold green", no_wrap=True)
    table.add_column("JIT", no_wrap=True)
    table.add_column("Grants (what you get)", style="bold yellow")
    table.add_column("Who can add you  (DACL writer)", style="blue")
    for r in rows:
        jit = "[bold red]LIVE[/]" if r.get("jit_active") else ""
        table.add_row(_e(r["group"]), jit, _e(r.get("grants_summary", "-")),
                      _req_approver_cell(r))
    console.print(table)
    _legend([
        "Every row is a [bold]fact[/]: [bold red]LIVE[/] = a time-bound member exists "
        "right now; otherwise the membership is writable by the listed non-admin "
        "principal. Name heuristics are not used here.",
        "'Who can add you' is the group's DACL membership writer - the authoritative, "
        "targetable approver. See the Membership writers table for the consolidated list.",
    ], title="requestable groups")


def print_membership_writers(writers, include_privileged=False):
    """The actionable target list: every principal that can grant access, and the
    groups (and machines) that gets you. Answers 'which account do I go after?'."""
    shown = [w for w in writers if include_privileged or not w["privileged"]]
    hidden = len(writers) - len(shown)
    if not shown and not writers:
        return
    table = _table("MEMBERSHIP WRITERS  (who can grant access - your targets)",
                   title_style="bold red", expand=True)
    table.add_column("Principal", style="bold green", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Right", style="blue")
    table.add_column("Can add you to (groups -> machines)", style="yellow")
    table.add_column("SID / DN (target)", style="dim")
    for w in sorted(shown, key=lambda x: (0 if x["type"] in ("service account", "gMSA") else 1,
                                          -x.get("write_count", 0), x["name"].lower())):
        reach = _short_list(w.get("groups", []), 3)
        if w.get("unlocks"):
            reach += "  -> " + _short_list(sorted(w["unlocks"]), 2)
        ident = w["dn"] or w["sid"] or "-"
        right = w["right"] + (" (inherited)" if w.get("inherited") else "")
        table.add_row(_e(w["name"]), _type_style(w["type"]), _e(right),
                      _e(reach or "-"), _e(ident))
    if shown:
        console.print(table)
    notes = ["A writer is anyone who can add you to a requestable group - the "
             "[bold]authoritative approver[/], regardless of workflow-group names.",
             "[bold red]service account[/] / [bold red]gMSA[/] writers are the prize: "
             "controlling one lets you self-approve without the approval app or a human."]
    if hidden:
        notes.append(f"[dim]{hidden} privileged writer(s) hidden - use "
                     f"--include-privileged to show.[/]")
    _legend(notes, title="membership writers")


def print_jit_manager(detection, show_low=False):
    """Where the JIT manager lives: the approval-engine identity (SPN host / web
    portal / gMSA hosts, with the evidence for the confidence) and any fingerprinted
    PAM/JIT products. Low-confidence identities are hidden unless show_low."""
    identities = detection.get("identities", [])
    vendors = detection.get("vendors", [])
    shown = [d for d in identities if show_low or d.get("confidence") != "low"]
    hidden_low = len(identities) - len(shown)
    if not shown and not vendors:
        if hidden_low:
            console.print(f"[dim]- JIT manager: {hidden_low} low-confidence writer(s) "
                          f"only; nothing corroborated. Use --show-low to list them.[/]")
        return

    if shown:
        table = _table("JIT MANAGER / approval engine  (identity behind the writes)",
                       title_style="bold red", danger=True, expand=True)
        table.add_column("Account", style="bold green", no_wrap=True)
        table.add_column("Type", style="magenta")
        table.add_column("Conf.", no_wrap=True)
        table.add_column("Approval web app", style="bold cyan")
        table.add_column("Runs on / hosts", style="yellow")
        table.add_column("Why (evidence)", style="dim")
        for d in shown:
            web = "\n".join(d.get("web_urls", [])) or "-"
            hosts = sorted(set(list(d.get("hosts", [])) + list(d.get("gmsa_hosts", []))))
            hoststr = ", ".join(hosts[:4]) + (" ..." if len(hosts) > 4 else "")
            evidence = "\n".join(f"- {x}" for x in d.get("evidence", [])) or "-"
            table.add_row(_e(d["name"]), _type_style(d["type"]),
                          _conf_style(d.get("confidence", "")), _e(web),
                          _e(hoststr or "-"), _e(evidence))
        console.print(table)

    if vendors:
        table = _table("PAM / JIT product fingerprints  (domain-wide, indicative)")
        table.add_column("Product", style="bold magenta", no_wrap=True)
        table.add_column("Object", style="green")
        table.add_column("Type", style="blue")
        table.add_column("Host / URL", style="yellow")
        table.add_column("Matched", style="dim")
        for v in vendors:
            hu = "; ".join(v.get("web_urls") or v.get("hosts") or
                           ([v.get("dns")] if v.get("dns") else [])) or "-"
            table.add_row(_e(v["vendor"]), _e(v["name"]), _e(v["type"]),
                          _e(hu), _e(v.get("match", "")))
        console.print(table)

    notes = [
        "Confidence is [bold]evidence-based[/]: [bold red]high[/] needs corroboration "
        "(gMSA, a product match, writing a JIT-active group, an HTTP SPN, or writing "
        "several requestable groups) - a lone SPN account is only [dim]low[/].",
        "The identity's SPN/gMSA hosts are where the JIT manager runs; an HTTP SPN is "
        "the approval web portal. Product fingerprints are [italic]indicative[/], not proof.",
    ]
    if hidden_low:
        notes.append(f"[dim]{hidden_low} low-confidence writer(s) hidden - use "
                     f"--show-low to list them.[/]")
    _legend(notes, title="JIT manager")


def print_history(history):
    """Recent member-value changes from replication metadata (--history)."""
    if not history:
        console.print("[dim]- No replication metadata history for target groups.[/]")
        return
    table = _table("Recent membership changes (replication metadata)")
    table.add_column("Group", style="green", no_wrap=True)
    table.add_column("Member", style="yellow")
    table.add_column("Last change", style="cyan")
    table.add_column("Ver", style="dim")
    for h in sorted(history, key=lambda x: x.get("last_change", ""), reverse=True):
        table.add_row(_e(h["group"]), _e(h["member_dn"].split(",")[0] or h["member"]),
                      _e(h.get("last_change", "")), _e(h.get("version", "")))
    console.print(table)


# ============================================================================
#  Export
# ============================================================================
def export_results(path, fmt, report):
    fmt = fmt.lower()
    _ensure_parent(path)
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    elif fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            # Section 1: attack paths (unchanged leading columns for compatibility;
            # source/scope appended).
            w.writerow(["requestable_group", "target_computer", "access",
                        "approvers", "gpo_guid", "source", "scope"])
            for p in report["attack_paths"]:
                w.writerow([p["group"], p["target_computer"], p["access"],
                            "; ".join(p["approvers"]), p["gpo_guid"],
                            p.get("source", ""), p.get("scope", "")])
            # Section 1b: requestable groups (facts only: JIT-active or delegated).
            w.writerow([])
            w.writerow(["requestable_group", "group", "jit_active", "grants",
                        "machines", "member_of_privileged", "writers"])
            for r in report.get("requestable_groups", []):
                appr = "; ".join(f"{a['name']}({a.get('type','')}:{a['right']})"
                                 for a in r.get("approvers_dacl", []))
                w.writerow(["", r["group"], r.get("jit_active", False),
                            r.get("grants_summary", ""), "; ".join(r.get("machines", [])),
                            "; ".join(r.get("privileged_of", [])), appr])
            # Section 2: active elevated access (live now).
            w.writerow([])
            w.writerow(["active_access", "member", "target_computer", "access",
                        "via_group", "ttl_seconds", "expires"])
            for a in report.get("active_access", []):
                w.writerow(["", a["member"], a["target_computer"], a["access"],
                            a["group"], a["ttl_seconds"], a["expires_human"]])
            # Section 3: membership writers (actionable target list).
            w.writerow([])
            w.writerow(["membership_writer", "principal", "type", "right",
                        "groups", "machines", "sid", "dn", "privileged", "inherited"])
            for wr in report.get("membership_writers", []):
                w.writerow(["", wr["name"], wr.get("type", ""), wr["right"],
                            "; ".join(wr.get("groups", [])), "; ".join(wr.get("unlocks", [])),
                            wr.get("sid", ""), wr.get("dn", ""), wr.get("privileged", False),
                            wr.get("inherited", False)])
            # Section 4: JIT manager / approval engine.
            jm = report.get("jit_manager", {}) or {}
            w.writerow([])
            w.writerow(["jit_manager_identity", "account", "type", "confidence",
                        "web_app", "hosts", "evidence", "dn"])
            for d in jm.get("identities", []):
                hosts = sorted(set(list(d.get("hosts", [])) + list(d.get("gmsa_hosts", []))))
                w.writerow(["", d.get("name", ""), d.get("type", ""),
                            d.get("confidence", ""), "; ".join(d.get("web_urls", [])),
                            "; ".join(hosts), "; ".join(d.get("evidence", [])),
                            d.get("dn", "")])
            w.writerow([])
            w.writerow(["jit_manager_product", "vendor", "object", "type",
                        "host_or_url", "matched", "dn"])
            for v in jm.get("vendors", []):
                hu = "; ".join(v.get("web_urls") or v.get("hosts") or [])
                w.writerow(["", v.get("vendor", ""), v.get("name", ""), v.get("type", ""),
                            hu, v.get("match", ""), v.get("dn", "")])
    elif fmt == "html":
        _export_html(path, report)
    else:
        console.print(f"[red][!] Unknown format: {fmt}[/]")
        return False
    console.print(f"[green][+][/] Exported {fmt.upper()}: [bold]{path}[/]")
    return True


def _html_type(typ):
    if typ in ("service account", "gMSA"):
        return f"<span class='svc'>{html.escape(typ)}</span>"
    return html.escape(typ or "")


def _html_approvers(p):
    """Render authoritative DACL approvers (name + type + right), else hint."""
    dacl = p.get("approvers_dacl") or []
    if dacl:
        items = []
        for a in dacl:
            tag = " (priv)" if a.get("privileged") else ""
            inherited = " (inherited)" if a.get("inherited") else ""
            typ = f" {_html_type(a.get('type', ''))}" if a.get("type") else ""
            items.append(f"{html.escape(a['name'])}{typ} "
                         f"<span class='right'>{html.escape(a['right'])}"
                         f"{tag}{inherited}</span>")
        return "<br>".join(items)
    if p.get("readable") is False:
        return "<span class='heur'>(DACL unreadable)</span>"
    heur = p.get("approvers") or []
    if heur:
        return (f"<span class='heur'>{html.escape(', '.join(heur))} "
                f"(heuristic)</span>")
    return "(none found)"


def _export_html(path, report):
    m = report["meta"]
    pam = report["pam"]
    rows = []
    for p in sorted(report["attack_paths"], key=lambda x: (x["target_computer"], x["group"])):
        rows.append(f"<tr><td class='mono'>{html.escape(p['group'])}</td>"
                    f"<td class='tgt'>{html.escape(p['target_computer'])}</td>"
                    f"<td>{html.escape(p['access'])}</td>"
                    f"<td class='appr'>{_html_approvers(p)}</td>"
                    f"<td class='src'>{html.escape(p.get('source', ''))}</td></tr>")
    rows_html = "\n".join(rows) or "<tr><td colspan='5' class='empty'>No mapping found.</td></tr>"
    active_rows = "\n".join(
        f"<tr><td class='mono'>{html.escape(a['member'])}</td>"
        f"<td class='tgt'>{html.escape(a['target_computer'])}</td>"
        f"<td>{html.escape(a['access'])}</td>"
        f"<td>{html.escape(a['group'])}</td>"
        f"<td class='ttl'>{html.escape(a['expires_human'])}</td></tr>"
        for a in sorted(report.get("active_access", []), key=lambda x: x["ttl_seconds"])) or \
        "<tr><td colspan='5' class='empty'>No live elevated access at scan time.</td></tr>"
    ttl_rows = "\n".join(
        f"<tr><td class='mono'>{html.escape(t['group'])}</td>"
        f"<td>{html.escape(t['member_dn'].split(',')[0])}</td>"
        f"<td class='ttl'>{t['ttl_seconds']}s</td></tr>"
        for t in report["ttl_memberships"]) or \
        "<tr><td colspan='3' class='empty'>None active at scan time.</td></tr>"
    req_rows = "\n".join(
        f"<tr><td class='mono'>{html.escape(r.get('group', ''))}</td>"
        f"<td class='ttl'>{'LIVE' if r.get('jit_active') else ''}</td>"
        f"<td class='tgt'>{html.escape(r.get('grants_summary', '') or '-')}</td>"
        f"<td class='appr'>{_html_approvers(r)}</td></tr>"
        for r in report.get("requestable_groups", [])) or \
        "<tr><td colspan='4' class='empty'>No JIT-active or delegated groups found.</td></tr>"
    jm = report.get("jit_manager", {}) or {}
    jm_id_rows = "\n".join(
        f"<tr><td class='mono'>{html.escape(d.get('name', ''))}</td>"
        f"<td>{_html_type(d.get('type', ''))}</td>"
        f"<td class='src'>{html.escape(d.get('confidence', ''))}</td>"
        f"<td class='appr'>{'<br>'.join(html.escape(u) for u in d.get('web_urls', [])) or '-'}</td>"
        f"<td class='tgt'>{html.escape(', '.join(sorted(set(list(d.get('hosts', [])) + list(d.get('gmsa_hosts', []))))) or '-')}</td>"
        f"<td class='src'>{html.escape('; '.join(d.get('evidence', [])))}</td></tr>"
        for d in jm.get("identities", []) if d.get("confidence") != "low") or \
        "<tr><td colspan='6' class='empty'>No corroborated approval-engine identity resolved.</td></tr>"
    jm_vendor_rows = "\n".join(
        f"<tr><td class='mono'>{html.escape(v.get('vendor', ''))}</td>"
        f"<td>{html.escape(v.get('name', ''))}</td>"
        f"<td>{html.escape(v.get('type', ''))}</td>"
        f"<td class='tgt'>{html.escape('; '.join(v.get('web_urls') or v.get('hosts') or []) or '-')}</td>"
        f"<td class='src'>{html.escape(v.get('match', ''))}</td></tr>"
        for v in jm.get("vendors", [])) or \
        "<tr><td colspan='5' class='empty'>No known PAM/JIT product fingerprinted.</td></tr>"
    writers = report.get("membership_writers", [])
    if not report["meta"].get("include_privileged"):
        writers = [w for w in writers if not w.get("privileged")]
    def _reach(w):
        r = ", ".join(w.get("groups", []))
        if w.get("unlocks"):
            r += " -> " + ", ".join(sorted(w["unlocks"]))
        return r or "-"
    writer_rows = "\n".join(
        f"<tr><td class='mono'>{html.escape(w['name'])}</td>"
        f"<td>{_html_type(w.get('type', ''))}</td>"
        f"<td class='right'>{html.escape(w['right'])}"
        f"{' (inherited)' if w.get('inherited') else ''}</td>"
        f"<td class='tgt'>{html.escape(_reach(w))}</td>"
        f"<td class='mono'>{html.escape(w.get('dn') or w.get('sid') or '-')}</td></tr>"
        for w in writers) or \
        "<tr><td colspan='5' class='empty'>No membership writers resolved.</td></tr>"
    pam_txt = "ENABLED" if pam["enabled"] else "not enabled"
    pam_cls = "ok" if pam["enabled"] else "warn"
    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JIThunter report - {html.escape(m['domain'])}</title>
<style>
:root{{--bg:#14101c;--bg2:#1c1528;--card:#221a30;--line:#35294a;--violet:#9b6dff;
--txt:#e8e2f2;--dim:#9c93b0;--crit:#ff4d6d;--high:#ff9f43;--green:#3ddc84;--blue:#4da3ff;}}
*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(160deg,var(--bg),var(--bg2));
color:var(--txt);font-family:-apple-system,"Segoe UI",Roboto,sans-serif;padding:32px}}
.wrap{{max-width:1100px;margin:0 auto}}.logo{{font-size:26px;font-weight:800;
background:linear-gradient(90deg,var(--violet),#d9c2ff);-webkit-background-clip:text;
background-clip:text;color:transparent}}.tag{{color:var(--dim);font-size:13px;margin-left:10px}}
.meta{{display:flex;flex-wrap:wrap;gap:18px;margin:18px 0 24px;font-size:13px;color:var(--dim)}}
.meta b{{color:var(--txt)}}.post{{background:var(--card);border:1px solid var(--line);
border-radius:14px;padding:18px 22px;margin-bottom:24px;font-size:14px;line-height:1.9}}
.badge{{padding:2px 10px;border-radius:20px;font-weight:700;font-size:12px}}
.ok{{background:rgba(61,220,132,.15);color:var(--green)}}.warn{{background:rgba(255,159,67,.15);color:var(--high)}}
h2{{font-size:15px;color:var(--violet);margin:26px 0 10px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:14px;overflow:hidden;margin-bottom:10px}}
th{{text-align:left;padding:12px 16px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;
color:var(--dim);background:var(--bg2);border-bottom:1px solid var(--line)}}
td{{padding:12px 16px;border-bottom:1px solid var(--line);font-size:14px}}
tr:last-child td{{border-bottom:none}}tr:hover{{background:rgba(155,109,255,.06)}}
.mono{{font-family:"SF Mono",Consolas,monospace;font-size:13px}}.tgt{{color:#ffd479;font-weight:600}}
.appr{{color:var(--blue)}}.ttl{{color:var(--crit);font-weight:600}}
.right{{color:var(--dim);font-size:12px}}.heur{{color:var(--high)}}.src{{color:var(--dim);font-size:12px}}
.svc{{color:var(--crit);font-weight:700;font-size:12px}}
.empty{{text-align:center;color:var(--dim);padding:26px}}
.note{{color:var(--dim);font-size:12px;margin:2px 0 18px}}
.live th,.writers th{{background:rgba(255,77,109,.18);color:#ffd0d8}}
footer{{margin-top:24px;text-align:center;color:var(--dim);font-size:12px}}
</style></head><body><div class="wrap">
<div><span class="logo">JIThunter</span><span class="tag">JIT / PAM posture &amp; attack surface</span></div>
<div class="meta"><span>Domain: <b>{html.escape(m['domain'])}</b></span>
<span>DC: <b>{html.escape(m['dc'])}</b></span>
<span>Generated: <b>{html.escape(m['generated'])}</b></span></div>
<div class="post">
PAM feature: <span class="badge {pam_cls}">{pam_txt}</span>
&nbsp; PAM bastion trust: <span class="badge {'ok' if report.get('pam_bastion_trust') else 'warn'}">{'YES' if report.get('pam_bastion_trust') else 'none'}</span>
&nbsp; Shadow principals: <b>{report['shadow_count']}</b>
&nbsp; Live TTL memberships: <b>{len(report['ttl_memberships'])}</b>
&nbsp; Active elevated access: <b>{len(report.get('active_access', []))}</b>
&nbsp; Workflow groups: <b>{len(report['workflow_groups'])}</b>
</div>
<h2>Active elevated access (live now)</h2>
<table class="live"><thead><tr><th>Member</th><th>Has access on</th><th>Access</th><th>Via group</th><th>Expires in</th></tr></thead>
<tbody>{active_rows}</tbody></table>
<h2>Requestable groups &mdash; JIT-active or membership delegated (facts only)</h2>
<table><thead><tr><th>Group</th><th>JIT</th><th>Grants (what you get)</th><th>Who can add you (DACL writer)</th></tr></thead>
<tbody>{req_rows}</tbody></table>
<div class="note">Every row is a fact: <b>LIVE</b> = a time-bound member exists right now; otherwise the membership is writable by the listed non-admin principal. Name heuristics are not used.</div>
<h2>Membership writers &mdash; who can grant access (your targets)</h2>
<table class="writers"><thead><tr><th>Principal</th><th>Type</th><th>Right</th><th>Can add you to (groups &rarr; machines)</th><th>SID / DN (target)</th></tr></thead>
<tbody>{writer_rows}</tbody></table>
<div class="note">A writer is anyone who can add a user to a requestable group &mdash; the authoritative approver, regardless of workflow-group names. A <span class="svc">service account</span> / <span class="svc">gMSA</span> writer is the prize: controlling it lets you self-approve without the approval app or a human.</div>
<h2>JIT manager &mdash; approval engine identity (SPN host / web portal / gMSA hosts)</h2>
<table class="writers"><thead><tr><th>Account</th><th>Type</th><th>Conf.</th><th>Approval web app</th><th>Runs on / hosts</th><th>Why (evidence)</th></tr></thead>
<tbody>{jm_id_rows}</tbody></table>
<h2>PAM / JIT product fingerprints (domain-wide, indicative)</h2>
<table><thead><tr><th>Product</th><th>Object</th><th>Type</th><th>Host / URL</th><th>Matched</th></tr></thead>
<tbody>{jm_vendor_rows}</tbody></table>
<div class="note">The approval-engine identity writes group memberships &mdash; controlling it means self-approval. Its SPN/gMSA hosts are where the JIT manager runs; an HTTP SPN is the approval web portal. Product fingerprints are indicative name/SPN matches, not proof.</div>
<h2>Attack surface (group &rarr; machine)</h2>
<table><thead><tr><th>Requestable group</th><th>Unlocks (machine / scope)</th><th>Access</th><th>Approvers (DACL: can write member)</th><th>Src</th></tr></thead>
<tbody>{rows_html}</tbody></table>
<div class="note">Approvers are read from each group's DACL (who can write its 'member' attribute). Request/approve workflow-group names are only a heuristic hint.</div>
<h2>Active temporary memberships (LINK_TTL)</h2>
<table><thead><tr><th>Group</th><th>Member</th><th>TTL</th></tr></thead>
<tbody>{ttl_rows}</tbody></table>
<footer>Generated by {TOOL_NAME} {VERSION} by {AUTHOR}</footer>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


# ============================================================================
#  Main
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - JIT/PAM posture and attack-surface scanner (read-only).",
        formatter_class=_HelpFormatter,
        epilog=f"""Examples:
  # Full scan with a password
  jithunter.py -d corp.com -u mary -p '12Maintwelve' --dc-ip 192.168.70.100

  # With an NT hash, HTML report
  jithunter.py -d corp.com -u mary -H <NT> --dc-ip 192.168.70.100 --export report.html

  # LDAP only (skip SYSVOL SMB access)
  jithunter.py -d corp.com -u mary -p '...' --dc-ip 192.168.70.100 --no-sysvol

  # Include privileged trustees, full workflow view, recent-access forensics
  jithunter.py -d corp.com -u mary -p '...' --dc-ip 192.168.70.100 \\
      --include-privileged --verbose --history

  # Fast: skip the domain-wide membership-DACL sweep (large domains)
  jithunter.py -d corp.com -u mary -p '...' --dc-ip 192.168.70.100 --fast

Notes:
  * Approvers are read from each requestable group's DACL (who can write its
    'member' attribute) - this is authoritative. A DACL writer may be an approval
    app's SERVICE ACCOUNT rather than a human: controlling it enables self-approval.
  * Requestable groups are FACTS, not name guesses: a group is listed only if it is
    JIT-active now (a live TTL member) or its membership is writable by a non-admin
    (a targetable writer). By default every group's membership DACL is swept; --fast
    limits that to SYSVOL-mapped and JIT-active groups in very large domains.
  * JIThunter pivots from the writer to locate the JIT manager: its SPN reveals the
    host and (for HTTP SPNs) the approval web-app URL; a gMSA writer's allowed hosts
    (msDS-GroupMSAMembership) are the servers running it. Confidence is evidence-based
    (a lone service-account writer is 'low', not 'high'); --show-low lists those.
  * Live TTL memberships are only visible while an access window is open. A SYSVOL
    group->machine mapping alone is infrastructure, not proof that JIT is in use.
  * A PAM bastion trust (trustAttributes PIM bit 0x400) is DEFINITIVE proof of a
    MIM/PAM bastion; the group owner is an implicit membership writer (owns the SD).
""")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password")
    parser.add_argument("-H", "--hashes", help="NT hash or LM:NT")
    parser.add_argument("-k", "--kerberos", action="store_true", help="Kerberos via KRB5CCNAME")
    parser.add_argument("--dc-ip", required=True, help="Domain controller IP/hostname")
    parser.add_argument("--ssl", action="store_true", help="Force LDAPS (636)")
    parser.add_argument("--search-base",
                        help="LDAP search base override for scoped JIT audits "
                             "(default: domain naming context)")
    parser.add_argument("--no-sysvol", action="store_true",
                        help="Skip SYSVOL SMB parsing (group->machine mapping)")
    parser.add_argument("--include-privileged", action="store_true",
                        help="Include well-known privileged trustees (Domain/Enterprise "
                             "Admins, SYSTEM, Administrators) in the approver list")
    parser.add_argument("--verbose", action="store_true",
                        help="Show all workflow-group categories (default: request/approve only)")
    parser.add_argument("--history", action="store_true",
                        help="Read replication metadata for recent membership changes "
                             "on target groups (heavier, read-only)")
    parser.add_argument("--fast", action="store_true",
                        help="Skip the domain-wide membership-DACL sweep (only reads "
                             "DACLs of SYSVOL-mapped and JIT-active groups; use in very "
                             "large domains)")
    parser.add_argument("--show-low", action="store_true",
                        help="Show low-confidence JIT-manager candidates (uncorroborated)")
    parser.add_argument("--export", metavar="FILE", help="Export results to a file")
    parser.add_argument("--format", choices=["csv", "json", "html"],
                        help="Export format (auto-detected from extension if omitted)")
    args = parser.parse_args()

    if not any([args.password, args.hashes, args.kerberos]):
        parser.error("provide -p, -H or -k for authentication.")

    print_banner()

    try:
        console.print("[dim][*] Connecting to LDAP...[/]")
        conn, base_dn, config_nc = connect_ldap(
            args.dc_ip, args.domain, args.username,
            password=args.password, nt_hash=args.hashes,
            use_kerberos=args.kerberos, use_ssl=args.ssl)
    except Exception as exc:
        console.print(f"[bold red][!] Connection error:[/] {exc}")
        sys.exit(1)
    console.print(f"[green][+][/] Connected  |  base DN: [bold]{base_dn}[/]")
    scan_base = args.search_base or base_dn
    if args.search_base:
        console.print(f"[green][+][/] Scoped LDAP search base: [bold]{scan_base}[/]")

    # Signal 1: PAM enabled + certain PAM/tiering facts.
    console.print("[dim][*] Checking PAM optional feature, bastion trust, tiering...[/]")
    pam_enabled, pam_scopes = check_pam_enabled(conn, config_nc)
    pam_trust = check_pam_trust(conn, base_dn)
    tiering = check_tiering_posture(conn, base_dn, config_nc)

    # Signal 2: shadow principals.
    console.print("[dim][*] Enumerating shadow principals...[/]")
    shadows = find_shadow_principals(conn, config_nc)

    # Signal 3: live TTL memberships.
    console.print("[dim][*] Scanning for active temporary memberships (LINK_TTL)...[/]")
    ttl_members = find_ttl_memberships(conn, scan_base)

    # Signal 4: workflow groups.
    console.print("[dim][*] Classifying workflow groups...[/]")
    dn_to_name, groups, sid_to_name = collect_group_index(conn, scan_base)
    workflow_groups = find_workflow_groups(groups, dn_to_name)

    # Signal 5: SYSVOL group->machine mapping (GPP machine/user + Restricted Groups).
    gpp_mappings = []
    if not args.no_sysvol:
        console.print("[dim][*] Reading SYSVOL group-policy sources...[/]")
        gpp_mappings = collect_sysvol_gpp(
            args.dc_ip, args.domain, args.username,
            password=args.password, nt_hash=args.hashes,
            use_kerberos=args.kerberos)
        # Refine mapping scopes (Restricted Groups have no per-item filter).
        gpo_links = resolve_gpo_links(conn, scan_base)
        apply_gpo_scope(gpp_mappings, gpo_links)

    # Requestable groups - FACTS only (JIT-active now, or membership delegated to a
    # non-admin). No name guessing.
    candidate_groups = collect_candidate_groups(groups, gpp_mappings, ttl_members)
    sd_cache = {}
    if not args.fast:
        console.print("[dim][*] Sweeping group membership DACLs for delegations "
                      "(use --fast to skip)...[/]")
        deep_cands, sd_cache = discover_delegated_groups(conn, base_dn, groups)
        candidate_groups = merge_candidates(candidate_groups, deep_cands)

    candidate_targets = [{"dn": c["dn"], "name": c["name"], "sid": c.get("sid", "")}
                         for c in candidate_groups]
    machine_targets = resolve_target_groups(gpp_mappings, groups)

    # Authoritative approvers: who can write each candidate group's 'member' attribute.
    group_dacls = {}
    if candidate_targets:
        console.print(f"[dim][*] Reading DACLs on {len(candidate_targets)} candidate "
                      f"group(s) (authoritative approvers)...[/]")
        group_dacls = collect_group_dacls(
            conn, base_dn, candidate_targets, sid_to_name,
            include_privileged=args.include_privileged, sd_cache=sd_cache)

    # Correlations (no LDAP needed) - done while the connection is still open so the
    # JIT-manager pivot below can enrich the writers we derive here.
    group_by_dn = {g["dn"].lower(): g for g in groups if g.get("dn")}
    priv_index = _privileged_group_index(groups)
    active_access = correlate_active_access(ttl_members, gpp_mappings, dn_to_name)
    attack_paths, approvers, requesters, approvers_heuristic = build_attack_paths(
        workflow_groups, gpp_mappings, group_dacls=group_dacls,
        target_groups=machine_targets, include_privileged=args.include_privileged)
    requestable_groups = build_requestable_groups(
        candidate_groups, group_dacls, group_by_dn=group_by_dn, priv_index=priv_index,
        include_privileged=args.include_privileged)
    # Actionable target list: every principal that can grant access, deduplicated
    # across the full requestable set.
    membership_writers = aggregate_membership_writers(requestable_groups)

    # Locate the JIT manager / approval engine (pivot from the writers + fingerprints).
    console.print("[dim][*] Locating the JIT manager / approval engine...[/]")
    jit_manager = detect_jit_manager(conn, base_dn, membership_writers)

    # Recent-access forensics (optional, heavier).
    history = []
    if args.history and candidate_targets:
        console.print("[dim][*] Reading replication metadata (recent access)...[/]")
        history = collect_repl_history(conn, candidate_targets, dn_to_name)

    conn.unbind()

    # Display.
    console.print()
    print_posture(pam_enabled, pam_scopes, shadows, ttl_members, workflow_groups,
                  active_access, pam_trust=pam_trust, tiering=tiering)
    print_active_access(active_access)
    print_ttl_table(ttl_members)
    print_shadow_ttls(shadows)
    print_workflow_table(workflow_groups, verbose=args.verbose)
    print_requestable_groups(requestable_groups,
                             include_privileged=args.include_privileged, fast=args.fast)
    print_attack_paths(attack_paths)
    print_membership_writers(membership_writers,
                             include_privileged=args.include_privileged)
    print_jit_manager(jit_manager, show_low=args.show_low)
    if args.history:
        print_history(history)

    # Export.
    if args.export:
        fmt = args.format
        if not fmt:
            ext = os.path.splitext(args.export)[1].lower().lstrip(".")
            fmt = ext if ext in ("csv", "json", "html") else "csv"
        # Flatten DACL results keyed by group DN for the JSON export (completeness).
        group_dacls_export = [
            {"group": info.get("name", ""), "group_dn": dn, "group_sid": info.get("sid", ""),
             "approvers": info.get("approvers", []),
             "self_members": info.get("self_members", [])}
            for dn, info in group_dacls.items()
        ]
        report = {
            "meta": {"generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     "domain": args.domain, "dc": args.dc_ip, "base_dn": base_dn,
                     "search_base": scan_base,
                     "tool": TOOL_NAME, "version": VERSION,
                     "include_privileged": args.include_privileged},
            "pam": {"enabled": pam_enabled, "scopes": pam_scopes},
            "pam_bastion_trust": pam_trust,
            "tiering": tiering,
            "shadow_count": len(shadows),
            "shadow_principals": shadows,
            "ttl_memberships": ttl_members,
            "active_access": active_access,
            "workflow_groups": workflow_groups,
            "requestable_groups": requestable_groups,
            "group_dacls": group_dacls_export,
            "membership_writers": membership_writers,
            "jit_manager": jit_manager,
            "attack_paths": attack_paths,
            "approvers": approvers,
            "approvers_heuristic": approvers_heuristic,
            "requesters": requesters,
            "history": history,
        }
        export_results(args.export, fmt, report)


if __name__ == "__main__":
    main()
