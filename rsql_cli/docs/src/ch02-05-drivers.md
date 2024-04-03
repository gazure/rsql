## drivers

### Usage

```text
.drivers
```

### Description

The drivers command displays the available database drivers.

| Driver       | Description                                                                                     | URL                                                                           |
|--------------|-------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `libsql`     | LibSQL provided by [Turso](https://github.com/tursodatabase/libsql)                             | `libsql://<host>?[<memory=true>][&file=<database_file>][&auth_token=<token>]` |
| `mysql`      | MySQL provided by [SQLx](https://github.com/launchbadge/sqlx)                                   | `mysql://<user>[:<password>]@<host>[:<port>]/<database>`                      |
| `postgres`   | PostgreSQL driver provided by [rust-prostgres](https://github.com/sfackler/rust-postgres)       | `postgres://<user>[:<password>]@<host>[:<port>]/<database>?<embedded=true>`   |
| `postgresql` | PostgreSQL driver provided by [SQLx](https://github.com/launchbadge/sqlx)                       | `postgresql://<user>[:<password>]@<host>[:<port>]/<database>?<embedded=true>` |
| `rusqlite`   | SQLite provided by [Rusqlite](https://github.com/rusqlite/rusqlite?tab=readme-ov-file#rusqlite) | `rusqlite://?<memory=true>[&file=<database_file>]`                            |
| `sqlite`     | SQLite provided by [SQLx](https://github.com/launchbadge/sqlx)                                  | `sqlite://?<memory=true>[&file=<database_file>]`                              |

### Examples

Show the available drivers:

```text
.drivers
```