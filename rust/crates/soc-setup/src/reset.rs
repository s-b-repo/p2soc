//! Local Vaultwarden account recovery. Back up the full SQLite database
//! before touching the account, and restart the service on every outcome.

use crate::cli::Flags;
use crate::error::TextResult;
use rusqlite::{Connection, OptionalExtension, params};
use soc_sys::{
    fsutil,
    run::{Runner, SystemRunner, argv},
};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn delete_account(conn: &mut Connection, email: &str) -> rusqlite::Result<bool> {
    conn.pragma_update(None, "foreign_keys", false)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let uuid: Option<String> = tx
        .query_row("SELECT uuid FROM users WHERE lower(email)=lower(?1)", params![email], |row| row.get(0))
        .optional()?;
    let Some(uuid) = uuid else { return Ok(false) };
    let references = {
        let mut stmt = tx.prepare(
            "SELECT t.name, fk.\"from\" FROM sqlite_master AS t JOIN pragma_foreign_key_list(t.name) AS fk
             WHERE t.type='table' AND t.name != 'users' AND lower(fk.\"table\") = 'users'",
        )?;
        stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (table, column) in references {
        tx.execute(&format!("DELETE FROM {} WHERE {}=?1", identifier(&table), identifier(&column)), params![uuid])?; // audit-allow: escaped schema identifiers only; the UUID is bound
    }
    tx.execute("DELETE FROM users WHERE uuid=?1", params![uuid])?;
    tx.commit()?;
    Ok(true)
}

fn systemctl(verb: &str) -> TextResult<()> {
    let out = SystemRunner
        .run(&argv(&["systemctl", verb, "vaultwarden.service"]), Duration::from_secs(60))
        .map_err(|e| e.to_string())?;
    if out.success() {
        Ok(())
    } else {
        Err(format!("systemctl {verb} vaultwarden.service failed: {}", out.stderr.trim()))
    }
}

fn data_folder() -> PathBuf {
    SystemRunner
        .run(
            &argv(&["systemctl", "show", "vaultwarden.service", "--property=Environment", "--value"]),
            Duration::from_secs(10),
        )
        .ok()
        .and_then(|out| {
            out.stdout
                .split_whitespace()
                .find_map(|part| part.strip_prefix("DATA_FOLDER=").filter(|v| v.starts_with('/')).map(PathBuf::from))
        })
        .unwrap_or_else(|| PathBuf::from("/var/lib/vaultwarden"))
}

fn backup_and_reset(db: &Path, email: &str) -> TextResult<bool> {
    let mut conn =
        Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(|e| e.to_string())?;
    let name = format!(
        "db.sqlite3.reset-bak-{}-{}",
        crate::util::utc_stamp(std::time::SystemTime::now()).replace(':', ""),
        std::process::id()
    );
    let backup = db.with_file_name(name);
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&backup).map_err(|e| e.to_string())?;
    conn.execute("VACUUM INTO ?1", [backup.to_string_lossy().as_ref()])
        .map_err(|e| format!("could not back up Vaultwarden: {e}"))?;
    file.sync_all().map_err(|e| e.to_string())?;
    println!("Vaultwarden database backup saved at {}", backup.display());
    delete_account(&mut conn, email).map_err(|e| e.to_string())
}

pub(crate) fn run(args: &[String]) -> TextResult<i32> {
    let flags = Flags::parse(args, &["--email"], &["--yes", "--dry-run"])?;
    let email = flags
        .one("--email")
        .filter(|s| s.contains('@') && !s.chars().any(char::is_whitespace))
        .ok_or("vault-reset requires --email")?;
    if flags.has("--dry-run") {
        println!("Would stop the local Vaultwarden, back up its SQLite database, and delete the account for {email}.");
        return Ok(0);
    }
    if fsutil::euid() != 0 {
        return Err("vault-reset needs root".into());
    }
    if !flags.has("--yes") {
        print!("Type {email} to permanently remove the account and its stored credentials: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
        if line.trim() != email {
            return Err("account reset cancelled".into());
        }
    }
    let _lock = // audit-allow: hold the lock until the service has restarted
        fsutil::exclusive_lock(Path::new("/run/systemd/system/soc-vault-signups.lock")).map_err(|e| e.to_string())?;
    let folder = data_folder();
    let db = folder.join("db.sqlite3");
    fsutil::open_regular(&db).map_err(|e| format!("{}: {e}", db.display()))?;
    systemctl("stop")?;
    let outcome = backup_and_reset(&db, email);
    let restarted = systemctl("start");
    match (outcome, restarted) {
        (Ok(deleted), Ok(())) => {
            println!("{}", if deleted { "Local account deleted." } else { "No matching local account." });
            Ok(0)
        }
        (Err(e), Ok(())) | (Ok(_), Err(e)) => Err(e),
        (Err(e), Err(start)) => Err(format!("{e}; {start}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_handles_unknown_related_tables_and_preserves_other_accounts() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (uuid TEXT PRIMARY KEY, email TEXT);
             CREATE TABLE \"future relations\" (owner TEXT REFERENCES users(uuid));
             INSERT INTO users VALUES ('1','a@example.test'),('2','b@example.test');
             INSERT INTO \"future relations\" VALUES ('1'),('2');",
        )
        .unwrap();
        assert!(delete_account(&mut conn, "A@example.test").unwrap());
        assert!(!delete_account(&mut conn, "a@example.test").unwrap());
        let left: String = conn.query_row("SELECT owner FROM \"future relations\"", [], |r| r.get(0)).unwrap();
        assert_eq!(left, "2");
    }
}
