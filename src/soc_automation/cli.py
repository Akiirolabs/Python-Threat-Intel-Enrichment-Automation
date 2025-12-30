from __future__ import annotations

import asyncio
import typer
from rich.console import Console
from soc_automation.pipeline import run_pipeline

app = typer.Typer(add_completion=False)
console = Console()

@app.command()
def run(config: str = typer.Option("config/config.yaml", "--config", help="Path to config YAML")) -> None:
    """
    Run the SOC automation pipeline (ingest -> normalize -> enrich -> score -> casegen).
    """
    try:
        asyncio.run(run_pipeline(config))
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted.[/yellow]")

if __name__ == "__main__":
    app()

