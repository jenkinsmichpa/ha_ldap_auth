use clap::Parser;
use lazy_static::lazy_static;
use ldap3::{ldap_escape, LdapConn, Scope, SearchEntry};
use regex::Regex;
use std::{env, process};

#[derive(Parser, Debug)]
#[command(name = "Home Assistant LDAP Authenticator")]
#[command(version = "1.0.0")]
#[command(about = "Performs LDAP searches to provide command line authentication to Home Assistant", long_about = None)]
struct Args {
    /// URL of LDAP/LDAPS authentication server
    #[arg(long, default_value_t = String::from("ldaps://localhost:636"))]
    ldap_server_url: String,

    /// Distinguished name of LDAP OU containing users
    #[arg(long, default_value_t = String::from("ou=users,dc=domain,dc=tld"))]
    ldap_user_dn: String,

    /// Distinguished name of LDAP OU containing groups
    #[arg(long, default_value_t = String::from("ou=groups,dc=domain,dc=tld"))]
    ldap_group_dn: String,

    /// Name of group containing Home Assistant Users
    #[arg(long, default_value_t = String::from("Home Assistant Users"))]
    ha_user_group: String,

    /// Name of group containing Home Assistant Admins
    #[arg(long, default_value_t = String::from("Home Assistant Admins"))]
    ha_admin_group: String,

    /// Name of group containing Local Only Home Assistant Users
    #[arg(long, default_value_t = String::from("Local Only Home Assistant Users"))]
    ha_local_only_group: String,
}

lazy_static! {
    static ref LDAP_OU_REGEX: Regex = Regex::new(r"^(ou|OU)=[^,]+,(?:(dc|DC)=[^,]+,?)+$").unwrap();
    static ref LDAP_FQDN_URL_REGEX: Regex = Regex::new(r"^ldaps?://(([a-z0-9][a-z0-9\-]*[a-z0-9])|[a-z0-9]+\.)*([a-z]+|xn\-\-[a-z0-9]+)\.?(:([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$").unwrap();
    static ref LDAP_IPv4_URL_REGEX: Regex = Regex::new(r"^ldaps?://(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(:([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$").unwrap();
    static ref LDAP_IPv6_URL_REGEX: Regex = Regex::new(r"^ldaps?://(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(:([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$").unwrap();
}

fn main() {
    let args = Args::parse();

    let username = match env::var("username") {
        Ok(username_result) => {
            if username_result.len() > 256 {
                eprintln!("Username exceeds 256 characters");
                process::exit(1)
            }
            username_result
        }
        Err(err) => {
            eprintln!(
                "Failed to retrieve 'username' from environment variables: {}",
                err
            );
            process::exit(1)
        }
    };

    let password = match env::var("password") {
        Ok(password_result) => {
            if password_result.len() > 256 {
                eprintln!("Password exceeds 256 characters");
                process::exit(1)
            }
            password_result
        }
        Err(err) => {
            eprintln!(
                "Failed to retrieve 'password' from environment variables: {}",
                err
            );
            process::exit(1)
        }
    };

    let ldap_server_url = &args.ldap_server_url;
    if !LDAP_FQDN_URL_REGEX.is_match(ldap_server_url)
        && !LDAP_IPv4_URL_REGEX.is_match(ldap_server_url)
        && !LDAP_IPv6_URL_REGEX.is_match(ldap_server_url)
    {
        eprintln!("Invalid LDAP server URL format: {}", ldap_server_url);
        process::exit(1);
    }

    let ldap_user_dn = &args.ldap_user_dn;
    if !LDAP_OU_REGEX.is_match(ldap_user_dn) {
        eprintln!("Invalid LDAP users DN format: {}", ldap_user_dn);
        process::exit(1);
    }

    let ldap_group_dn = &args.ldap_group_dn;
    if !LDAP_OU_REGEX.is_match(ldap_group_dn) {
        eprintln!("Invalid LDAP groups DN format: {}", ldap_group_dn);
        process::exit(1);
    }

    let ha_user_group = &args.ha_user_group;
    let ha_admin_group = &args.ha_admin_group;
    let ha_local_only_group = &args.ha_local_only_group;

    let ldap_username_relative_dn = format!("cn={}", ldap_escape(username));
    let ldap_username_dn = format!("{},{}", ldap_username_relative_dn, ldap_user_dn);

    let mut display_name = String::new();
    let mut groups = Vec::new();

    let mut ldap_connection = match LdapConn::new(ldap_server_url) {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("Failed to connect to LDAP server: {}", err);
            process::exit(1);
        }
    };

    match ldap_connection.simple_bind(&ldap_username_dn, &password) {
        Ok(ldap_bind_result) => {
            if let Err(err) = ldap_bind_result.success() {
                eprintln!("Failed to bind to LDAP: {}", err);
                process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("Error during LDAP bind: {}", err);
            process::exit(1);
        }
    }

    let ldap_entries = match ldap_connection.search(
        &ldap_username_dn,
        Scope::Subtree,
        &ldap_username_relative_dn,
        vec!["displayName", "memberOf"],
    ) {
        Ok(search_result) => match search_result.success() {
            Ok((search_result_entries, _)) => search_result_entries
                .into_iter()
                .map(SearchEntry::construct),
            Err(err) => {
                eprintln!("Search operation failed: {}", err);
                process::exit(1)
            }
        },
        Err(err) => {
            eprintln!("Failed to execute search: {}", err);
            process::exit(1)
        }
    };

    if let Err(err) = ldap_connection.unbind() {
        eprintln!("Failed to unbind LDAP connection: {}", err);
    }

    for ldap_entry in ldap_entries {
        if let Some(display_name_entries) = ldap_entry.attrs.get("displayName") {
            display_name = display_name_entries.first().cloned().unwrap_or_default();
        }
        if let Some(group_entries) = ldap_entry.attrs.get("memberOf") {
            groups.extend(group_entries.clone());
        }
    }

    if groups.contains(&format!("cn={},{}", ha_user_group, ldap_group_dn)) {
        println!("name = {}", display_name);
        if groups.contains(&format!("cn={},{}", ha_admin_group, ldap_group_dn)) {
            println!("group = system-admin");
        } else {
            println!("group = system-user");
        }
        if groups.contains(&format!("cn={},{}", ha_local_only_group, ldap_group_dn)) {
            println!("local_only = true");
        } else {
            println!("local_only = false");
        }
    } else {
        eprintln!("User does not belong to the required user group.");
    }
}
