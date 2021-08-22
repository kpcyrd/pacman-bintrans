#![allow(unused_imports)]
use pacman_bintrans_common::errors::*;

use diesel::sqlite::*;

embed_migrations!();

pub fn run(conn: &SqliteConnection) -> Result<()> {
    embedded_migrations::run(conn)?;
    Ok(())
}
