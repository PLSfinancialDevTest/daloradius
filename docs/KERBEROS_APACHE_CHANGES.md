# Kerberos SSO: Apache Changes Required for daloRADIUS Operators

This document captures the Apache-side changes required so Kerberos authentication works with the current daloRADIUS SSO integration.

## Scope

- Protects **operators UI** with Kerberos SSO.
- Apache authenticates the user and provides `REMOTE_USER`.
- PHP SSO helper maps `REMOTE_USER` to an operators account.

## Application-side dependencies (already in code)

The Apache config below is required because the application expects `REMOTE_USER`:

- `app/operators/login.php` includes `library/kerberos_sso.php` and auto-redirects when SSO succeeds.
- `app/operators/library/checklogin.php` includes `kerberos_sso.php` before normal login redirect logic.
- `app/operators/library/kerberos_sso.php` strips realm/domain and maps the user to `operators.username`.

## 1) Install/enable required Apache modules

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y libapache2-mod-auth-gssapi krb5-user
sudo a2enmod auth_gssapi headers rewrite ssl
sudo systemctl reload apache2
```

## 2) Service principal + keytab

Create an HTTP service principal for the web host and export keytab (example AD/KDC flow):

- Principal format: `HTTP/<fqdn>@YOUR.REALM`
- Keytab path example: `/etc/apache2/http.keytab`

Set permissions so Apache can read it:

```bash
sudo chown root:www-data /etc/apache2/http.keytab
sudo chmod 640 /etc/apache2/http.keytab
```

## 3) Kerberos client config on web server (`/etc/krb5.conf`)

Ensure realm/KDC mapping is correct for your domain. Minimum expected:

- `[libdefaults] default_realm = YOUR.REALM`
- `[realms]` entries with KDC/admin servers
- `[domain_realm]` mappings for your DNS domain

## 4) Apache vhost/location protection

Add Kerberos auth to the operators path in your SSL vhost (`:443`):

```apache
<VirtualHost *:443>
    ServerName radius.example.com
    DocumentRoot /var/www/daloradius

    SSLEngine on
    # ... existing cert directives ...

    <Location /app/operators>
        AuthType GSSAPI
        AuthName "Kerberos SSO"
        GssapiCredStore keytab:/etc/apache2/http.keytab
        GssapiAllowedMech krb5
        GssapiLocalName On
        GssapiSSLonly On
        GssapiBasicAuth Off

        # Optional: avoid session cookies if your policy prefers stateless negotiation
        # GssapiUseSessions Off

        # Require successful Kerberos auth
        Require valid-user

        # Optional directory group restriction (if using mod_authnz_ldap or equivalent authz integration):
        # Require ldap-group CN=Radius-Operators,OU=Groups,DC=example,DC=com
    </Location>

    # Ensure PHP receives REMOTE_USER consistently
    RewriteEngine On
    RewriteRule .* - [E=REMOTE_USER:%{REMOTE_USER}]
</VirtualHost>
```

## 5) (Optional) NTLM fallback policy

If you must support legacy clients, enable fallback intentionally and document risk. Preferred is Kerberos-only (`GssapiAllowedMech krb5`).

## 6) App/DB alignment required for SSO mapping

`kerberos_sso.php` normalizes:

- `user@REALM` -> `user`
- `DOMAIN\user` -> `user` (domain prefix stripped)

It strips `DOMAIN\` using `CONFIG_SSO_WINDOWS_DOMAIN` from `daloradius.conf.php`.

Therefore `dalooperators.username` must match normalized usernames.

## 7) Verification checklist

1. Apache config syntax:
   ```bash
   sudo apachectl -t
   ```
2. Reload Apache:
   ```bash
   sudo systemctl reload apache2
   ```
3. Confirm module load:
   ```bash
   apachectl -M | grep -E "auth_gssapi|ssl|rewrite"
   ```
4. Browser test (domain-joined client):
   - Open `https://<host>/app/operators/login.php`
   - Expect direct redirect to operators home (no local login form loop)
5. Confirm `REMOTE_USER` in Apache access logs (custom log format may be needed).
6. Confirm mapped operator exists in DB.

## 8) Sync daloRADIUS operators from the AD group

The application maps `REMOTE_USER` to `operators.username`, so users still need matching rows in the
`operators` and `operators_acl` tables. For environments where Apache authorization is tied to the AD-backed
Unix group, deploy the sync helper script from the repo:

`contrib/scripts/maintenance/sync-daloradius-operators-from-ad-group.sh`

Recommended deployment:

```bash
sudo install -o root -g root -m 750 \
  /var/www/daloradius/contrib/scripts/maintenance/sync-daloradius-operators-from-ad-group.sh \
  /usr/local/sbin/sync-daloradius-operators-from-ad-group.sh
```

What the script does:

- reads the AD-backed Unix group via `getent group`
- normalizes usernames the same way the SSO flow expects (`user@REALM` -> `user`, `DOMAIN\user` -> `user`)
- creates missing rows in `operators`
- grants full `operators_acl` access for synced operators

Example manual run:

```bash
sudo /usr/local/sbin/sync-daloradius-operators-from-ad-group.sh PLS-Store-Radius
```

If your Apache config uses a different group name, pass that group name to the script.

## 9) Cron job for recurring sync

Example cron entry to refresh operators every 15 minutes:

```cron
*/15 * * * * root /usr/local/sbin/sync-daloradius-operators-from-ad-group.sh PLS-Store-Radius >> /var/log/daloradius-operator-sync.log 2>&1
```

After AD group membership changes, you may also need to refresh SSSD cache and re-test login:

```bash
sudo sss_cache -E
getent group PLS-Store-Radius
```

## 10) Common failure modes

- **401 loop**: SPN/keytab mismatch or client not sending Kerberos ticket.
- **Authenticated but redirected to login**: `REMOTE_USER` missing or mapped username absent in operators table.
- **Authenticated but operator still missing**: run the sync script manually and confirm the expected group members are returned by `getent group`.
- **Works in one browser only**: browser trusted-URI/Kerberos settings not configured.
- **Intermittent failures**: clock skew between KDC, Apache host, and clients.

## 11) Security notes

- Use HTTPS only (`GssapiSSLonly On`).
- Keep keytab readable only by root + Apache group.
- Restrict `/app/operators` to required users/groups only.
- Keep local daloRADIUS operator password login available as break-glass if your policy requires it.

## 12) Change summary for PR description

When adding this to GitHub, include:

- Apache module enablement (`auth_gssapi`, `ssl`, `rewrite`)
- Vhost `<Location /app/operators>` Kerberos directives
- Keytab deployment path/permissions
- Realm/SPN assumptions
- User normalization behavior expected by `kerberos_sso.php`
- Operator sync script deployment path and cron schedule
