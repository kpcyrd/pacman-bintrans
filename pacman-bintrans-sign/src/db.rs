use crate::archlinux::Pkg;
use crate::migrations;
use crate::schema::*;
use diesel::prelude::*;
use diesel::{Connection, SqliteConnection};
use pacman_bintrans_common::errors::*;

pub struct Database {
    db: SqliteConnection,
}

impl Database {
    pub fn open(path: &str) -> Result<Database> {
        let db = SqliteConnection::establish(path).context("Failed to connect to database")?;

        db.execute("PRAGMA busy_timeout = 10000")
            .context("Failed to set busy_timeout")?;
        db.execute("PRAGMA foreign_keys = ON")
            .context("Failed to enforce foreign keys")?;
        db.execute("PRAGMA journal_mode = WAL")
            .context("Failed to enable write ahead log")?;
        db.execute("PRAGMA synchronous = NORMAL")
            .context("Failed to enforce foreign keys")?;

        migrations::run(&db).context("Failed to run migrations")?;

        Ok(Database { db })
    }

    pub fn already_signed(&self, pkg: &Pkg) -> Result<Option<String>> {
        use crate::schema::pkgs::dsl::*;

        let row = pkgs
            .filter(sha256sum.eq(&pkg.sha256sum))
            .filter(filename.eq(&pkg.filename))
            .first::<SignatureRow>(&self.db)
            .optional()?;

        Ok(row.map(|r| r.signature))
    }

    pub fn insert_sig(&self, pkg: &Pkg, signature: String, uuid: Option<String>) -> Result<()> {
        let row = NewSignatureRow {
            sha256sum: pkg.sha256sum.clone(),
            filename: pkg.filename.clone(),
            signature,
            uuid: uuid.clone(),
        };

        let insert = diesel::insert_into(pkgs::table)
            .values(row)
            .execute(&self.db);

        use diesel::result::DatabaseErrorKind;

        match insert {
            Ok(_) => Ok(()),
            Err(diesel::result::Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
                // if uuid.is_some() try to update the row if the row doesn't have a uuid yet

                if let Some(my_uuid) = uuid {
                    use crate::schema::pkgs::dsl::*;

                    let target = pkgs
                        .filter(sha256sum.eq(&pkg.sha256sum))
                        .filter(filename.eq(&pkg.filename))
                        .filter(uuid.is_null());
                    diesel::update(target)
                        .set(uuid.eq(&my_uuid))
                        .execute(&self.db)?;
                }

                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(Identifiable, Queryable, AsChangeset, Clone, PartialEq, Debug)]
#[table_name = "pkgs"]
pub struct SignatureRow {
    pub id: i32,
    pub sha256sum: String,
    pub filename: String,
    pub signature: String,
    pub uuid: Option<String>,
}

#[derive(Insertable, PartialEq, Debug, Clone)]
#[table_name = "pkgs"]
pub struct NewSignatureRow {
    pub sha256sum: String,
    pub filename: String,
    pub signature: String,
    pub uuid: Option<String>,
}
