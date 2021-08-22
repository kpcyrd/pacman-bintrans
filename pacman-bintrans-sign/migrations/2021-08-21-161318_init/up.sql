CREATE TABLE pkgs (
    id INTEGER NOT NULL PRIMARY KEY,
    sha256sum VARCHAR NOT NULL,
    filename VARCHAR NOT NULL,
    signature VARCHAR NOT NULL,
    uuid VARCHAR
);
CREATE UNIQUE INDEX pkgs_uniq ON pkgs(sha256sum, filename);
