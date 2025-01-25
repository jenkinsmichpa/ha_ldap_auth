# Home Assistant LDAP Authenticator
Performs LDAP authentication for Home Assistant through the command line authentication provider.

*I am not a software engineer and the security of this application is best-effort.*

## Function
 - Validates users against an LDAP/LDAPS server such as [Authentik](https://github.com/goauthentik/authentik).
 - Performs user and group membership meta checks.
 - Outputs process errors to stderr.
 - Self contained and works within HAOS.

## Usage
```bash
Usage: ha_ldap_auth [OPTIONS]

Options:
      --ldap-server-url <LDAP_SERVER_URL>
          URL of LDAP/LDAPS authentication server [default: ldaps://localhost:636]
      --ldap-user-dn <LDAP_USER_DN>
          Distinguished name of LDAP OU containing users [default: ou=users,dc=domain,dc=tld]
      --ldap-group-dn <LDAP_GROUP_DN>
          Distinguished name of LDAP OU containing groups [default: ou=groups,dc=domain,dc=tld]
      --ha-user-group <HA_USER_GROUP>
          Name of group containing Home Assistant Users [default: "Home Assistant Users"]
      --ha-admin-group <HA_ADMIN_GROUP>
          Name of group containing Home Assistant Admins [default: "Home Assistant Admins"]
      --ha-local-only-group <HA_LOCAL_ONLY_GROUP>
          Name of group containing Local Only Home Assistant Users [default: "Local Only Home Assistant Users"]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Home Assistant Configuration
 - Download the file to a persistent filepath and configure LDAP authentication parameters through the Home Assistant `configuration.yaml` file.
```yaml
homeassistant:
  auth_providers:
    - type: homeassistant
    - type: command_line
      command: /config/scripts/ha_ldap_auth
      args:
        [
          "--ldap-server-url",
          "ldaps://authentik.domain.tld",
          "--ldap-user-dn",
          "ou=users,dc=ldap,dc=domain,dc=tld",
          "--ldap-group-dn",
          "ou=groups,dc=ldap,dc=domain,dc=tld",
          "--ha-user-group",
          "Home Assistant Users",
          "--ha-admin-group",
          "Home Assistant Admins",
          "--ha-local-only-group",
          "Local Only Home Assistant Users"
        ]
      meta: true
```
