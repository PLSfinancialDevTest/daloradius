# Kerberos SSO: Apache Changes for daloRADIUS Operators

This document lists the Apache-side requirements to make Kerberos SSO work with operators login.

## Code dependencies

The application expects `REMOTE_USER` and uses:

- `app/operators/login.php`
- `app/operators/library/checklogin.php`
- `app/operators/library/kerberos_sso.php`

`kerberos_sso.php` normalizes:

- `user@REALM` -> `user`
- `DOMAIN\user` -> `user`

Windows domain stripping uses config key:

```php
$configValues['CONFIG_SSO_WINDOWS_DOMAIN'] = 'example';
```

## Apache modules

Enable required modules:

```bash
sudo apt-get install -y libapache2-mod-auth-gssapi krb5-user
sudo a2enmod auth_gssapi ssl rewrite headers
sudo systemctl reload apache2
```

## Keytab and principal

- Service principal: `HTTP/<fqdn>@YOUR.REALM`
- Keytab path example: `/etc/apache2/http.keytab`

Permissions:

```bash
sudo chown root:www-data /etc/apache2/http.keytab
sudo chmod 640 /etc/apache2/http.keytab
```

## Apache vhost example

```apache
<Location /app/operators>
    AuthType GSSAPI
    AuthName "Kerberos SSO"
    GssapiCredStore keytab:/etc/apache2/http.keytab
    GssapiAllowedMech krb5
    GssapiLocalName On
    GssapiSSLonly On
    GssapiBasicAuth Off
    Require valid-user

    # Optional group restriction example:
    # Require ldap-group CN=Radius-Operators,OU=Groups,DC=example,DC=com
</Location>

RewriteEngine On
RewriteRule .* - [E=REMOTE_USER:%{REMOTE_USER}]
```

## Server config requirement

Add this setting in `app/common/includes/daloradius.conf.php`:

```php
$configValues['CONFIG_SSO_WINDOWS_DOMAIN'] = 'plsfinancial';
```

Use your real domain prefix value.

## Verification checklist

1. `sudo apachectl -t`
2. `sudo systemctl reload apache2`
3. `apachectl -M | grep -E "auth_gssapi|ssl|rewrite"`
4. Open `/app/operators/login.php` from a domain-joined client and confirm SSO redirect.
5. Ensure mapped username exists in operators table.

## Syncing operators from the AD-backed group

When Apache access is restricted by an AD-backed Unix group, the matching daloRADIUS operator rows still need to
exist. The repo includes a helper script for that:

`contrib/scripts/maintenance/sync-daloradius-operators-from-ad-group.sh`

Deploy it to the server:

```bash
sudo install -o root -g root -m 750 \
  /var/www/daloradius/contrib/scripts/maintenance/sync-daloradius-operators-from-ad-group.sh \
  /usr/local/sbin/sync-daloradius-operators-from-ad-group.sh
```

Run it manually:

```bash
sudo /usr/local/sbin/sync-daloradius-operators-from-ad-group.sh PLS-Store-Radius
```

The script:

- reads the AD-backed group with `getent group`
- normalizes usernames to match `kerberos_sso.php`
- creates missing `operators` rows
- grants full `operators_acl` access

## Cron example

```cron
*/15 * * * * root /usr/local/sbin/sync-daloradius-operators-from-ad-group.sh PLS-Store-Radius >> /var/log/daloradius-operator-sync.log 2>&1
```

If group membership changes are not visible immediately, refresh SSSD cache:

```bash
sudo sss_cache -E
getent group PLS-Store-Radius
```
