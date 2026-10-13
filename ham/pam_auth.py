"""Password-only PAM verification and NSS group membership, on this node."""

from pathlib import Path
import os
import re
from .config import DEFAULT_CONFIG

PAM_DIR = Path("/etc/pam.d")


def settings(cfg):
    return cfg["local"].get("ui_auth") or DEFAULT_CONFIG["local"]["ui_auth"]


def member(username, group):
    """Return the NSS canonical name, or None. Include primary and SSSD groups."""
    try:
        import pwd
        import grp
        user = pwd.getpwnam(username)
        gid = grp.getgrnam(group).gr_gid
        if gid in os.getgrouplist(user.pw_name, user.pw_gid):
            return user.pw_name
    except Exception:  # NSS providers can also raise resolver-specific errors.
        pass
    return None


def validate(value):
    if not isinstance(value, dict) or value.get("mode") not in ("local", "pam"):
        raise ValueError("choose local or pam authentication")
    service, group = value.get("pam_service"), value.get("allowed_group")
    if not isinstance(service, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", service):
        raise ValueError("invalid PAM service name")
    if not isinstance(group, str) or not group.strip() or len(group) > 256 or \
            any(ord(c) < 32 for c in group):
        raise ValueError("invalid system group name")
    return {"mode": value["mode"], "pam_service": service, "allowed_group": group.strip()}


def diagnostics(value):
    errors = []
    members = set()
    try:
        value = validate(value)
        if not (PAM_DIR / value["pam_service"]).is_file():
            errors.append("PAM service file is missing: /etc/pam.d/" + value["pam_service"])
        import pam
        pam.pam()  # Also check that libpam can be loaded.
    except Exception:
        errors.append("PAM is unavailable; install python-pam and configure its service")
    try:
        import pwd
        import grp
        group = grp.getgrnam(value["allowed_group"])
        members.update(group.gr_mem)
        members.update(u.pw_name for u in pwd.getpwall() if u.pw_gid == group.gr_gid)
    except Exception:
        errors.append("the allowed system group cannot be resolved through NSS")
    return {"ready": not errors, "errors": errors, "members": sorted(members),
            "members_note": "NSS enumeration may omit domain members. Check a specific username; "
                            "membership alone does not prove PAM will allow sign-in."}


def authenticate(username, password, value):
    try:
        value = validate(value)
        if not (PAM_DIR / value["pam_service"]).is_file():
            return None  # Never fall through to PAM's default 'other' service.
        canonical = member(username, value["allowed_group"])
        if canonical:
            import pam
            # A new object per call: PAM handles and error state are not shared.
            if pam.pam().authenticate(canonical, password, service=value["pam_service"],
                                      resetcreds=False):
                return member(canonical, value["allowed_group"])
    except Exception:  # A broken PAM module must deny access, never use local admin.
        pass
    return None
