# PAM sign-in for the management panel

This fork supports local and domain OS accounts through Linux-PAM and NSS.
It changes sign-in to **the management panel**. The existing Users, Groups and
Single sign-on pages still protect published services.

All admitted users are panel administrators. The manager continues running as
its service user (normally root); it does not switch UID, open a PAM session,
establish Kerberos credentials or store system passwords.

## Install and enable

On Debian or Ubuntu, install from this fork:

```sh
curl -fsSL https://raw.githubusercontent.com/bapho-bush/haproxy-manager/main/install.sh | sudo bash
```

The installer and packages create an empty `haproxy-manager` system group and
install the PAM binding: `python3-pampy` on Debian/Ubuntu, `python3-pam` on
Fedora/RHEL/Rocky (EPEL is needed on Rocky/RHEL). These package names refer to
the [python-pam](https://github.com/FirefighterBlu3/python-pam) library, imported
as `pam`; Debian's separate `python3-pam` package is a different binding.
The Debian/Ubuntu installation also includes `python3-six`, required by Ubuntu's
older pampy binding even though its package does not declare that dependency.

Add an **existing** user to the group using the OS or domain administration
tools. For a local account:

```sh
sudo usermod -aG haproxy-manager your-user
id your-user
```

Use HTTPS for the panel before entering a system password. Sign in with the
existing local administrator and open **Settings → Web UI access → Panel
sign-in**. Choose **System account (PAM)**, service `haproxy-manager` and the
allowed group. Enter the current administrator's password (and TOTP/recovery
code if enabled), then the system account's username and password to test.

**Save** validates both accounts before saving. Success
ends every old session and signs this browser in as the tested system user.
Failure leaves the configuration, local TOTP state and session secret intact.
Reauthentication failures count toward the existing login rate limit.

In PAM mode the local administrator cannot sign in, and the first-run account
creation endpoint stays closed even when no local password hash exists. PAM
errors never fall back to local authentication. The dormant local account is
retained for deliberate recovery; do not distribute its credentials.

## PAM stacks and other Linux distributions

The installer creates `/etc/pam.d/haproxy-manager` only when that file does not
already exist. Debian/Ubuntu use:

```pam
auth include common-auth
account include common-account
```

Fedora/RHEL/Rocky use:

```pam
auth include system-auth
account include system-auth
```

This inherits the host's authentication and account policies. The application
requires both `pam_authenticate` and `pam_acct_mgmt` to succeed. Locked accounts,
expired accounts and expired passwords are denied at sign-in. Change passwords
with OS/domain tools: this version accepts one username and password, without
OTP challenges or password-change conversations. Panel-local TOTP applies only
to the local administrator, never to PAM users.

On another Linux distribution, install python-pam using its package manager or
the application's Python environment and configure a service in `/etc/pam.d/`
that includes that distribution's managed auth/account stacks. Select that
service in the UI. A missing service file or binding prevents enabling PAM;
the manager does not fall back to PAM's `other` stack. Do not replace managed
system stacks or hard-code `pam_unix` when domain authentication is required.

## SSSD, FreeIPA and Active Directory

The host must already resolve the account and group through NSS and authenticate
the account through its PAM stack. Test the exact domain names accepted by your
host, for example:

```sh
getent passwd 'alice@example.org'
getent group 'proxy-admins@example.org'
id 'alice@example.org'
```

Primary and supplementary groups are accepted using NSS `getgrouplist`, including
SSSD memberships. The session and profile use the canonical NSS username. The UI
shows enumerated group members and offers a specific username membership check.
SSSD often disables enumeration, so the displayed list may be incomplete. A
membership check is not a password/account-policy test.

Group membership is checked on every authenticated API request; removing access
revokes an open session on its next request. PAM account/password status is
checked at sign-in. Account locking alone does not revoke a previously issued
cookie; remove group membership to revoke access immediately. Sessions otherwise
retain the configured lifetime (12 hours by default).

Email and appearance preferences are stored separately per canonical username.
PAM settings and profiles are node-local and are not synced or exported with
shared configuration. Configure PAM, groups and NSS separately on each node.
API keys retain their existing use for peers and scripts; an API key alone
cannot change the panel's authentication mode.

## Return to local authentication or recover through SSH

To return through the UI, select **Local administrator** and provide the current
system user's credentials plus the retained local administrator's credentials
and second factor, if enabled. Successful switching rotates sessions again.

If the PAM configuration, group or domain service prevents sign-in, recover from
an administrative shell on that node. For the default install paths:

```sh
sudo systemctl stop haproxy-manager
sudo cp -a /var/lib/haproxy-manager/config.json /var/lib/haproxy-manager/config.json.before-pam-recovery

# Prompts privately; the password is piped, never placed in command arguments.
sudo bash -c 'read -rsp "New local admin password: " pw; echo; printf "%s" "$pw" | python3 /opt/haproxy-manager/app.py set-admin admin -'

# set-admin already rotated the signing secret; only change the login mode.
sudo python3 - <<'PY'
import json
from pathlib import Path
path = Path('/var/lib/haproxy-manager/config.json')
cfg = json.loads(path.read_text())
cfg['local'].setdefault('ui_auth', {})['mode'] = 'local'
path.write_text(json.dumps(cfg, indent=2) + '\n')
path.chmod(0o600)
PY
sudo systemctl start haproxy-manager
```

Stop if creating the local administrator fails; keep the service stopped and
repair the file from the backup. `set-admin` replaces the local account and its
old TOTP settings, consistent with the existing CLI recovery behavior. Adjust
paths and `HAM_DATA_DIR` if your installation uses a different data directory.

## Fork updates and validation

This fork defaults installation and update checks to
`bapho-bush/haproxy-manager`, with version `1.98.1`. `HAM_REPO` and `HAM_REF`
remain explicit overrides. Service units read `/etc/default/haproxy-manager`;
the updater passes the selected repository and branch to the installer. Updates
retain PAM mode, system stack customizations and profiles.

Run the focused regression and UI checks:

```sh
python3 tools/test-pam.py
LINKEDOM=/path/to/linkedom/esm/index.js bash tools/uitests/run-all.sh
```

Real PAM tests create users only in explicitly opted-in disposable containers:

```sh
for base in ubuntu:24.04 debian:13 fedora:43 rockylinux:9; do
    docker build --build-arg BASE="$base" -t ham-pam-test -f tools/pam-test.Dockerfile .
    docker run --rm -e HAM_PAM_NATIVE_TEST=1 -v "$PWD:/app:ro" ham-pam-test \
        python3 tools/test-pam.py --native
done
```

The native checks exercise real PAM password/account policies, primary and
supplementary groups, installation preservation and a fresh Python process.
Container checks do not establish acceptance on a production server or a real
SSSD domain. NSS/domain behavior also has isolated regression coverage; live
domain acceptance remains a deployment check.
