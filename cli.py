import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from engine import analyze_migration

app = typer.Typer()
console = Console()

@app.command()
def check(file: str):
    """Check a SQL migration file for dangerous patterns."""
    # Read the SQL file
    try:
        with open(file, 'r') as f:
            sql = f.read()
    except FileNotFoundError:
        console.print(f"[bold red]Error: File '{file}' not found.[/bold red]")
        raise typer.Exit(code=1)

    if not sql.strip():
        console.print("[yellow]File is empty.[/yellow]")
        raise typer.Exit()

    # Run our engine!
    results = analyze_migration(sql)

    # Display results beautifully
    if not results:
        console.print(Panel("[bold green]✅ Migration looks safe! No dangerous patterns detected.[/bold green]", title="SafeMigrate", border_style="green"))
    else:
        console.print(Panel(f"[bold red]🚨 Found {len(results)} potential issue(s)![/bold red]", title="SafeMigrate", border_style="red"))
        
        for i, warning in enumerate(results, 1):
            # Format the SQL strings with syntax highlighting
            unsafe_syntax = Syntax(warning['unsafe_sql'], "sql", theme="monokai", line_numbers=False)
            safe_syntax = Syntax(warning['safe_sql'], "sql", theme="monokai", line_numbers=False)

            console.print(f"\n[bold yellow]---- Issue {i} ----[/bold yellow]")
            console.print(f"[bold]Rule:[/bold] {warning['rule']} | [bold]Severity:[/bold] [red]{warning['severity']}[/red]")
            console.print(f"[bold]Explanation:[/bold] {warning['message']}")
            
            console.print(Panel(unsafe_syntax, title="❌ Unsafe SQL", border_style="red"))
            console.print(Panel(safe_syntax, title="✅ Safe SQL", border_style="green"))

if __name__ == "__main__":
    app()