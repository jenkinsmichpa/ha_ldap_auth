use clap::{Parser, crate_authors, crate_description, crate_version};
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry, dn_escape, ldap_escape};
use ldapdn::parse::dn_from_str;
use std::{collections::HashMap, env, process, time::Duration};
use url::Url;

#[derive(Parser, Debug)]
#[command(name = "Home Assistant LDAP Authenticator", version = crate_version!(), about = crate_description!(), author = crate_authors!(), long_about = None)]
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

    /// Disable TLS certificate verification (use with caution)
    #[arg(long, default_value_t = false)]
    tls_no_verify: bool,
}

fn get_env_var(name: &str) -> String {
    match env::var(name) {
        Ok(value) => {
            if value.is_empty() {
                eprintln!("{name} must not be empty");
                process::exit(1)
            }
            if value.len() > 256 {
                eprintln!("{name} exceeds 256 characters");
                process::exit(1)
            }
            value
        }
        Err(err) => {
            eprintln!("Failed to retrieve '{name}' from environment variables: {err}");
            process::exit(1)
        }
    }
}

fn is_valid_ldap_url(url_str: &str) -> bool {
    Url::parse(url_str).is_ok_and(|parsed| {
        let scheme = parsed.scheme();
        (scheme == "ldap" || scheme == "ldaps") && parsed.host_str().is_some()
    })
}

fn is_valid_ldap_dn(dn_str: &str) -> bool {
    dn_from_str(dn_str).all(|rdn| rdn.is_ok())
}

fn get_attr<'a>(attrs: &'a HashMap<String, Vec<String>>, name: &str) -> Option<&'a Vec<String>> {
    attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

fn connect_to_ldap(url: &str, no_tls_verify: bool) -> LdapConn {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(15))
        .set_no_tls_verify(no_tls_verify);
    match LdapConn::with_settings(settings, url) {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("Failed to connect to LDAP server: {err}");
            process::exit(1);
        }
    }
}

fn bind_to_ldap(conn: &mut LdapConn, dn: &str, password: &str) {
    match conn.simple_bind(dn, password) {
        Ok(result) => {
            if let Err(err) = result.success() {
                eprintln!("Failed to bind to LDAP: {err}");
                process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("Error during LDAP bind: {err}");
            process::exit(1);
        }
    }
}

fn search_ldap_entries(
    conn: &mut LdapConn,
    base_dn: &str,
    filter: &str,
    attrs: Vec<&str>,
) -> Vec<SearchEntry> {
    match conn
        .with_timeout(Duration::from_secs(30))
        .search(base_dn, Scope::Subtree, filter, attrs)
    {
        Ok(result) => match result.success() {
            Ok((entries, _)) => entries.into_iter().map(SearchEntry::construct).collect(),
            Err(err) => {
                eprintln!("Search operation failed: {err}");
                process::exit(1)
            }
        },
        Err(err) => {
            eprintln!("Failed to execute search: {err}");
            process::exit(1)
        }
    }
}

fn main() {
    let args = Args::parse();

    let username = get_env_var("username");
    let password = get_env_var("password");

    if !is_valid_ldap_url(&args.ldap_server_url) {
        eprintln!("Invalid LDAP server URL format: {}", args.ldap_server_url);
        process::exit(1);
    }

    if !is_valid_ldap_dn(&args.ldap_user_dn) {
        eprintln!("Invalid LDAP users DN format: {}", args.ldap_user_dn);
        process::exit(1);
    }
    if !is_valid_ldap_dn(&args.ldap_group_dn) {
        eprintln!("Invalid LDAP groups DN format: {}", args.ldap_group_dn);
        process::exit(1);
    }

    let ha_user_group = &args.ha_user_group;
    let ha_admin_group = &args.ha_admin_group;
    let ha_local_only_group = &args.ha_local_only_group;
    let ldap_user_dn = &args.ldap_user_dn;
    let ldap_group_dn = &args.ldap_group_dn;

    let ldap_username_relative_dn = format!("cn={}", dn_escape(&username));
    let ldap_username_dn = format!("{ldap_username_relative_dn},{ldap_user_dn}");

    let mut ldap_connection = connect_to_ldap(&args.ldap_server_url, args.tls_no_verify);
    bind_to_ldap(&mut ldap_connection, &ldap_username_dn, &password);

    let ldap_filter = format!("(cn={})", ldap_escape(&username));
    let ldap_entries = search_ldap_entries(
        &mut ldap_connection,
        &args.ldap_user_dn,
        &ldap_filter,
        vec!["displayName", "memberOf"],
    );

    if let Err(err) = ldap_connection.unbind() {
        eprintln!("Failed to unbind LDAP connection: {err}");
    }

    if ldap_entries.is_empty() {
        eprintln!("Could not retrieve attributes for user '{username}'; check LDAP permissions.");
        process::exit(1);
    }

    let mut display_name = String::new();
    let mut groups = Vec::new();
    for ldap_entry in ldap_entries {
        if let Some(display_name_entries) = get_attr(&ldap_entry.attrs, "displayName")
            && display_name.is_empty()
        {
            display_name = display_name_entries.first().cloned().unwrap_or_default();
        }
        if let Some(group_entries) = get_attr(&ldap_entry.attrs, "memberOf") {
            groups.extend(group_entries.clone());
        }
    }

    if display_name.is_empty() {
        display_name = username;
    }

    let is_user = groups.iter().any(|g| {
        g.eq_ignore_ascii_case(&format!("cn={},{ldap_group_dn}", dn_escape(ha_user_group)))
    });
    let is_admin = groups.iter().any(|g| {
        g.eq_ignore_ascii_case(&format!("cn={},{ldap_group_dn}", dn_escape(ha_admin_group)))
    });
    let is_local_only = groups.iter().any(|g| {
        g.eq_ignore_ascii_case(&format!(
            "cn={},{ldap_group_dn}",
            dn_escape(ha_local_only_group)
        ))
    });

    if is_user {
        println!("name = {display_name}");
        if is_admin {
            println!("group = system-admin");
        } else {
            println!("group = system-users");
        }
        if is_local_only {
            println!("local_only = true");
        } else {
            println!("local_only = false");
        }
    } else {
        eprintln!("User does not belong to the required user group.");
        process::exit(1);
    }
}
