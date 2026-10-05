package audit

// Registered SQL drivers for the SQL sink. These are pure-Go, so the binary stays CGO-free.
// "pgx"/"postgres" is PostgreSQL, "mysql" is MySQL/MariaDB and "sqlite" is a local file.
import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)
