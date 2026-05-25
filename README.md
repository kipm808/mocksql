# mocksql

A lightweight, file-based mock SQL Server implementation for testing and development. mocksql implements the Tabular Data Stream (TDS) protocol and supports a comprehensive subset of T-SQL, making it compatible with standard SQL Server client libraries.

## Features

### Core Capabilities

- **TDS Protocol Implementation**: Full TDS 7.x/8.0 protocol support with TLS encryption
- **JSON-backed Storage**: Tables stored as simple JSON files for easy inspection and modification
- **Zero Configuration**: Automatically generates self-signed TLS certificates
- **Client Compatibility**: Works with standard SQL Server clients (ADO.NET, tiberius, pymssql, etc.)
- **Fast & Lightweight**: Perfect for integration tests, CI/CD pipelines, and local development

### Supported SQL Features

Based on **460+ integration tests** covering real-world use cases:

#### Query Operations

- **SELECT Statements**
  - `SELECT *` and column projections
  - Column aliases (`AS`)
  - `DISTINCT`
  - `TOP N` for limiting results
  - Expressions and literals in SELECT list
  - String concatenation

#### Filtering & Conditions

- **WHERE Clause**
  - Comparison operators: `=`, `!=`, `<>`, `<`, `>`, `<=`, `>=`
  - Logical operators: `AND`, `OR`, `NOT`
  - `IN` and `NOT IN` with lists
  - `BETWEEN` ranges
  - `IS NULL` and `IS NOT NULL`
  - `LIKE` pattern matching with wildcards (`%`, `_`) and `ESCAPE`
  - Complex nested conditions with parentheses

#### Sorting & Pagination

- **ORDER BY**
  - Ascending (`ASC`) and descending (`DESC`)
  - Multiple columns with mixed directions
  - Column position references
  - Order by expressions
  
- **Pagination**
  - `TOP N`
  - `OFFSET n ROWS FETCH NEXT m ROWS ONLY`

#### Joins

- `INNER JOIN`
- `LEFT JOIN` / `LEFT OUTER JOIN`
- `RIGHT JOIN` / `RIGHT OUTER JOIN`
- `FULL JOIN` / `FULL OUTER JOIN`
- `CROSS JOIN`
- Self joins
- Multiple table joins
- Join conditions with multiple predicates

#### Aggregation

- **Aggregate Functions**
  - `COUNT(*)` and `COUNT(column)`
  - `COUNT(DISTINCT column)`
  - `SUM()`
  - `AVG()`
  - `MIN()`
  - `MAX()`
  
- **GROUP BY**
  - Single and multiple columns
  - Expressions in GROUP BY
  
- **HAVING**
  - Filter aggregated results
  - All comparison operators with aggregates

#### Subqueries

- Subqueries in `WHERE` clause
- Subqueries with `IN` and `NOT IN`
- Scalar subqueries in SELECT list
- `EXISTS` and `NOT EXISTS`
- Correlated subqueries
- Nested subqueries
- Derived tables (subqueries in FROM)

#### Set Operations

- `UNION` (removes duplicates)
- `UNION ALL` (keeps duplicates)
- `INTERSECT`
- `EXCEPT`
- Set operations with `ORDER BY`
- Set operations with `WHERE` clauses

#### Advanced SQL

- **CASE Expressions**
  - Simple CASE
  - Searched CASE
  - Nested CASE expressions
  - CASE in SELECT, WHERE, and ORDER BY
  
- **Common Table Expressions (CTE)**
  - WITH clause
  - Named CTEs
  - Multiple CTEs
  
- **Functions**
  - `COALESCE()`
  - `ISNULL()`
  - `CAST()` type conversions
  - String functions (LENGTH, SUBSTRING, etc.)
  - Math functions (ABS, ROUND, etc.)
  
- **Table Constructors**
  - `VALUES` clause

#### Data Manipulation

- **INSERT**
  - Single row inserts
  - Multiple row inserts (`INSERT INTO ... VALUES (...), (...)`)
  - Column reordering
  - NULL value insertion
  
- **UPDATE**
  - Single and multiple column updates
  - UPDATE with WHERE conditions
  - Multiple row updates
  - SET to NULL
  
- **DELETE**
  - DELETE with WHERE conditions
  - DELETE all rows
  - DELETE with IN clause
  - DELETE with complex conditions

#### Schema Operations (DDL)

- `CREATE TABLE`
- `ALTER TABLE` (add/drop columns)
- `DROP TABLE` and `DROP TABLE IF EXISTS`
- `TRUNCATE TABLE`

#### Transactions (TCL)

- `BEGIN TRANSACTION` / `BEGIN TRAN`
- `COMMIT TRANSACTION` / `COMMIT`
- `ROLLBACK TRANSACTION` / `ROLLBACK`
- `SAVEPOINT`
- `ROLLBACK TO SAVEPOINT`
- `SET TRANSACTION ISOLATION LEVEL`

#### Access Control (DCL)

- `GRANT` (SELECT, INSERT, UPDATE, DELETE, ALL PRIVILEGES)
- `REVOKE` permissions

#### Parameterized Queries

Full support for parameterized queries via `sp_executesql` with the following data types:

- `INT`, `BIGINT`, `SMALLINT`
- `DECIMAL(p,s)`, `NUMERIC(p,s)`
- `FLOAT`, `REAL`
- `BIT`
- `MONEY`, `SMALLMONEY`
- `VARCHAR(n)`, `NVARCHAR(n)`
- `DATETIME`, `DATETIME2`
- `UNIQUEIDENTIFIER`
- `VARBINARY(n)`

#### NULL Handling

- Three-valued logic (TRUE, FALSE, NULL)
- NULL in arithmetic operations
- NULL in comparisons
- NULL in logical operations (AND, OR, NOT)
- `COALESCE()` and `ISNULL()` for NULL handling

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/kipm808/mocksql.git
cd mocksql/mocksql

# Build
cargo build --release

# Run
./target/release/mocksql
```

## Usage

### Starting the Server

```bash
# Run with default settings (data in ./data, daemon mode)
mocksql

# Specify custom data directory
mocksql /path/to/data

# Run in foreground (no daemon)
mocksql --no-daemon

# Enable trace logging (runs in foreground)
mocksql --trace

# Get help
mocksql --help
```

The server will:
- Listen on port **1433** (standard SQL Server port)
- Generate self-signed TLS certificates if not present
- Create default system views (sys.schemas, sys.tables, etc.)
- Store all table data as JSON files in the data directory

### Data Storage Format

Tables are stored as JSON files with the table name as the filename:

**users.json**
```json
[
  {"id": "1", "name": "Alice", "email": "alice@example.com"},
  {"id": "2", "name": "Bob", "email": "bob@example.com"}
]
```

### Connecting from Clients

#### .NET (C#)

```csharp
using Microsoft.Data.SqlClient;

var connString = "Server=localhost,1433;User Id=sa;Password=anypassword;TrustServerCertificate=true";
using var conn = new SqlConnection(connString);
conn.Open();

using var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
cmd.Parameters.AddWithValue("@id", 1);
var reader = cmd.ExecuteReader();
```

#### Rust (tiberius)

```rust
use tiberius::{Client, Config, AuthMethod};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

let mut config = Config::new();
config.host("localhost");
config.port(1433);
config.authentication(AuthMethod::sql_server("sa", "password"));
config.trust_cert();

let tcp = TcpStream::connect(config.get_addr()).await?;
let mut client = Client::connect(config, tcp.compat_write()).await?;

let rows = client.query("SELECT * FROM users", &[]).await?;
```

#### Python (pymssql)

```python
import pymssql

conn = pymssql.connect(
    server='localhost',
    port=1433,
    user='sa',
    password='password',
    database='master'
)

cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = %s", (1,))
rows = cursor.fetchall()
```

## Testing

The project includes comprehensive test suites:

### Integration Tests

Run the full Rust integration test suite (297 tests):

```bash
cd mocksql
cargo test --test integration
```

### SQL Test Suite

Run the SQL test client against a running server (460 tests):

```bash
# Start mocksql server first
mocksql --no-daemon /tmp/testdata &

# Run SQL tests
cd sqltests
cargo run

# Or in record mode to update expected outputs
cargo run -- --record
```

The SQL test suite includes:
- **DDL Operations** (6 tests): CREATE, ALTER, DROP, TRUNCATE
- **DCL Operations** (5 tests): GRANT, REVOKE
- **TCL Operations** (10 tests): Transactions, savepoints, rollback
- **SQL ACID Compliance** (18 tests): Standards compliance
- **Microsoft Documentation Examples** (22 tests): Common SQL patterns
- **Logic Tests** (27 tests): Operators, expressions, functions
- **Data Type Boundaries** (8 tests): Edge cases for numeric types
- **JOIN Variations** (6 tests): All join types
- **NULL Handling** (9 tests): Three-valued logic
- **Aggregate Functions** (8 tests): COUNT, SUM, AVG, MIN, MAX
- **CRUD Operations** (13 tests): INSERT, UPDATE, DELETE
- **WHERE Patterns** (9 tests): Complex filtering
- **ORDER BY** (6 tests): Sorting variations
- **CASE Expressions** (9 tests): Conditional logic
- **SELECT Variations** (8 tests): Query patterns
- **Integration Tests** (296 tests): Comprehensive feature coverage

## Architecture

### Protocol Implementation

mocksql implements the Microsoft Tabular Data Stream (TDS) protocol:

- **PreLogin**: Capability negotiation
- **Login**: Authentication (accepts any credentials)
- **SQL Batch**: Execute SQL statements
- **RPC**: Remote procedure calls (sp_executesql)
- **Attention**: Query cancellation support

### Token Types

- `0xAD`: LOGINACK (login acknowledgment)
- `0x81`: COLMETADATA (column definitions)
- `0xD1`: ROW (data rows)
- `0xFD`: DONE (completion token)
- `0xFE`: DONEPROC (stored procedure completion)
- `0xFF`: DONEINPROC (intermediate completion)
- `0xAA`: ERROR (error messages)
- `0xAB`: INFO (informational messages)

### Data Types Supported

- **Integer**: INT (0x26), BIGINT, SMALLINT
- **Floating Point**: FLOAT (0x3E), REAL
- **Decimal**: DECIMAL, NUMERIC with precision/scale
- **String**: VARCHAR, NVARCHAR (0xE7) with collation
- **Binary**: VARBINARY
- **Date/Time**: DATETIME, DATETIME2
- **Other**: BIT, MONEY, UNIQUEIDENTIFIER

## Performance Characteristics

mocksql is designed for testing, not production workloads:

- **Reads**: Fast (memory-mapped JSON files)
- **Writes**: Immediate JSON serialization (not optimized for high throughput)
- **Concurrency**: Multi-threaded, file-level locking
- **Scale**: Suitable for datasets up to ~100k rows per table

For performance testing or high-throughput scenarios, use a real SQL Server instance.

## Limitations

mocksql is a **testing tool**, not a production database. Known limitations:

- No persistent indexes (full table scans)
- No query optimizer (executes as parsed)
- Limited ACID guarantees (file-based locking)
- No replication, backup, or HA features
- Subset of T-SQL (core features only)
- No stored procedures, triggers, or views (except sys views)
- No foreign keys or constraints enforcement
- Authentication accepts any credentials

## Use Cases

mocksql is perfect for:

-  Integration testing SQL Server applications
-  CI/CD pipelines (fast, no Docker required)
-  Local development without SQL Server
-  Testing data access layers
-  Validating SQL syntax and queries
-  Debugging TDS protocol issues
-  Educational purposes

**Not suitable for:**
-  Production workloads
-  Performance benchmarking
-  Complex stored procedures
-  Large datasets (>1M rows)

## Contributing

Contributions are welcome! Areas for improvement:

- Additional SQL functions
- More data types
- Query optimization
- Better error messages
- Performance improvements
- Documentation

## License

[Add your license here]

## Acknowledgments

Built with:
- [tokio](https://tokio.rs/) - Async runtime
- [sqlparser](https://github.com/sqlparser-rs/sqlparser-rs) - SQL parsing
- [serde_json](https://github.com/serde-rs/json) - JSON serialization
- [rustls](https://github.com/rustls/rustls) - TLS implementation

## Related Projects

- [SQL Server](https://www.microsoft.com/sql-server) - The real thing
- [testcontainers](https://testcontainers.com/) - Docker-based testing
- [LocalDB](https://learn.microsoft.com/sql/database-engine/configure-windows/sql-server-express-localdb) - Lightweight SQL Server

---

**Note**: mocksql implements enough of SQL Server to be useful for testing, but it's not a complete implementation. For production use, please use Microsoft SQL Server or Azure SQL Database.
