import sqlglot
from sqlglot import exp

def analyze_migration(sql: str):
    """
    Parses SQL and detects dangerous schema changes.
    """
    warnings = []
    
    try:
        parsed_statements = sqlglot.parse(sql, dialect='postgres')
    except sqlglot.errors.ParseError as e:
        return [{"error": f"SQL Syntax Error: {str(e)}"}]

    for parsed in parsed_statements:
        if not parsed:
            continue

        if isinstance(parsed, exp.Alter):
            table_name = parsed.this.name
            raw_sql_upper = parsed.sql(dialect='postgres').upper()

            # RULE 1: Detect ALTER TABLE ... ADD COLUMN (without DEFAULT)
            for column_def in parsed.find_all(exp.ColumnDef):
                column_name = column_def.name
                data_type = column_def.args.get("kind")
                
                has_default = False
                for constraint in (column_def.args.get("constraints") or []):
                    if isinstance(constraint, exp.ColumnConstraint):
                        if isinstance(constraint.args.get("kind"), exp.DefaultColumnConstraint):
                            has_default = True
                            break
                
                if not has_default and data_type:
                    warnings.append({
                        "rule": "MISSING_DEFAULT",
                        "severity": "CRITICAL",
                        "message": f"Adding column '{column_name}' without a DEFAULT value will lock the table for writes while the database rewrites the underlying data.",
                        "unsafe_sql": parsed.sql(dialect='postgres'),
                        "safe_sql": generate_safe_add_column(table_name, column_name, data_type)
                    })

            # RULE 3: Detect ADD FOREIGN KEY without NOT VALID
            if "FOREIGN KEY" in raw_sql_upper and "NOT VALID" not in raw_sql_upper:
                constraint_name = "fk_constraint"
                for node in parsed.find_all(exp.Constraint):
                    if node.name:
                        constraint_name = node.name
                        break
                
                warnings.append({
                    "rule": "BLOCKING_FK_CONSTRAINT",
                    "severity": "HIGH",
                    "message": "Adding a Foreign Key will lock the table while it validates existing rows. Add as NOT VALID first, then validate concurrently.",
                    "unsafe_sql": parsed.sql(dialect='postgres'),
                    "safe_sql": generate_safe_fk_constraint(parsed, table_name, constraint_name)
                })

            # RULE 4: Detect ADD CHECK CONSTRAINT without NOT VALID
            if "CHECK" in raw_sql_upper and "NOT VALID" not in raw_sql_upper:
                constraint_name = "check_constraint"
                for node in parsed.find_all(exp.Constraint):
                    if node.name:
                        constraint_name = node.name
                        break
                
                warnings.append({
                    "rule": "BLOCKING_CHECK_CONSTRAINT",
                    "severity": "HIGH",
                    "message": "Adding a CHECK constraint will lock the table while it validates existing rows. Add as NOT VALID first, then validate concurrently.",
                    "unsafe_sql": parsed.sql(dialect='postgres'),
                    "safe_sql": generate_safe_check_constraint(parsed, table_name, constraint_name)
                })

            # RULE 5: Detect ALTER COLUMN TYPE (Table Rewrite)
            if "ALTER COLUMN" in raw_sql_upper and "TYPE" in raw_sql_upper:
                # Try to extract column name and new type using string manipulation for robustness
                col_name = "column"
                new_type = "TYPE"
                parts = raw_sql_upper.split("ALTER COLUMN")
                if len(parts) > 1:
                    type_parts = parts[1].split("TYPE")
                    if len(type_parts) > 1:
                        col_name = type_parts[0].strip()
                        new_type = type_parts[1].split(";")[0].strip()

                warnings.append({
                    "rule": "REWRITING_DATA_TYPE",
                    "severity": "CRITICAL",
                    "message": f"Changing the data type of '{col_name}' forces PostgreSQL to rewrite the entire table, causing prolonged locks and downtime.",
                    "unsafe_sql": parsed.sql(dialect='postgres'),
                    "safe_sql": generate_safe_alter_type(table_name, col_name, new_type)
                })

        # RULE 2: Detect CREATE INDEX without CONCURRENTLY
        if isinstance(parsed, exp.Create):
            if parsed.args.get("kind") == "INDEX":
                if not parsed.args.get("concurrently"):
                    warnings.append({
                        "rule": "NON_CONCURRENT_INDEX",
                        "severity": "HIGH",
                        "message": "Creating an index without CONCURRENTLY will lock the table for writes. Use CONCURRENTLY to build the index in the background.",
                        "unsafe_sql": parsed.sql(dialect='postgres'),
                        "safe_sql": generate_safe_create_index(parsed)
                    })
                        
    return warnings

# --- GENERATORS ---

def generate_safe_add_column(table_name, column_name, data_type):
    data_type_sql = data_type.sql(dialect='postgres')
    if "CHAR" in data_type_sql.upper() or "TEXT" in data_type_sql.upper():
        safe_sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {data_type_sql} DEFAULT '';"
    else:
        safe_sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {data_type_sql} DEFAULT 0;"
    return safe_sql

def generate_safe_create_index(parsed):
    parsed.set("concurrently", True)
    return parsed.sql(dialect='postgres')

def generate_safe_fk_constraint(parsed, table_name, constraint_name):
    unsafe_sql = parsed.sql(dialect='postgres')
    step1 = unsafe_sql.rstrip(';') + " NOT VALID;"
    step2 = f"ALTER TABLE {table_name} VALIDATE CONSTRAINT {constraint_name};"
    return f"{step1}\n{step2}"

def generate_safe_check_constraint(parsed, table_name, constraint_name):
    unsafe_sql = parsed.sql(dialect='postgres')
    step1 = unsafe_sql.rstrip(';') + " NOT VALID;"
    step2 = f"ALTER TABLE {table_name} VALIDATE CONSTRAINT {constraint_name};"
    return f"{step1}\n{step2}"

def generate_safe_alter_type(table_name, col_name, new_type):
    # The Expand-Contract Pattern (Zero Downtime)
    step1 = f"-- Step 1: Add new column\nALTER TABLE {table_name} ADD COLUMN {col_name}_new {new_type};"
    step2 = f"-- Step 2: Backfill data (Run in batches!)\nUPDATE {table_name} SET {col_name}_new = {col_name}::{new_type};"
    step3 = f"-- Step 3: Drop old column\nALTER TABLE {table_name} DROP COLUMN {col_name};"
    step4 = f"-- Step 4: Rename new column\nALTER TABLE {table_name} RENAME COLUMN {col_name}_new TO {col_name};"
    return f"{step1}\n{step2}\n{step3}\n{step4}"