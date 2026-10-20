from pathlib import Path
import sys
from typing import Annotated, Optional
import typer
from hashid.identify import identify

app = typer.Typer(
    name="hashid",
    help="Identify hash types and algorithms from hash strings.",
    add_completion=False,
)


def format_result(hash_value: str, result: list[str] | str | None) -> None:
    typer.secho(f"Analyzing: {hash_value}", bold=True)
    if isinstance(result, list):
        typer.secho("Possible hash types:", fg=typer.colors.GREEN)
        for algo in result:
            typer.echo(f"  - {algo}")
    elif isinstance(result, str):
        typer.secho(result, fg=typer.colors.YELLOW)
    else:
        typer.secho("No matching hash format found.", fg=typer.colors.RED)


@app.command()
def main(
    hash_value: Annotated[
        Optional[str],
        typer.Argument(
            help="Hash string to identify.",
            metavar="[HASH]",
        ),
    ] = None,
    file: Annotated[
        Optional[Path],
        typer.Option(
            "--file",
            "-f",
            help="File containing hashes to identify, one per line.",
        ),
    ] = None,
) -> None:
    if hash_value:
        format_result(hash_value, identify(hash_value))
        return

    if file:
        if not file.exists() or not file.is_file():
            typer.secho(f"Error: File '{file}' does not exist or is not a file.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

        lines = [line.strip() for line in file.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            typer.secho(f"Error: File '{file}' is empty.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

        for index, line in enumerate(lines):
            if index > 0:
                typer.echo()
            format_result(line, identify(line))
        return

    if not sys.stdin.isatty():
        input_data = sys.stdin.read().splitlines()
        hashes = [line.strip() for line in input_data if line.strip()]
        if hashes:
            for index, item in enumerate(hashes):
                if index > 0:
                    typer.echo()
                format_result(item, identify(item))
            return

    typer.secho("Error: Please specify a hash string, provide a file with --file, or pipe input via stdin.", fg=typer.colors.RED, err=True)
    typer.echo("Run 'hashid --help' for usage details.")
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
