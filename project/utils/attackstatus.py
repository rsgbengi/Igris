#!/usr/bin/env python3
import argparse
from cmd2.command_definition import with_default_category
from cmd2 import CommandSet, with_default_category, Cmd2ArgumentParser, with_argparser
from rich.console import Console
from rich.table import Table


@with_default_category("Utilities")
class AttackStatus(CommandSet):
    def __init__(self) -> None:
        super().__init__()

    def __create_table(self) -> Table:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Attack")
        table.add_column("Status")
        return table

    def __show_all(self) -> None:

        console = Console()
        table = self.__create_table()
        for attack, status in self._cmd.active_attacks.items():
            if status:
                table.add_row(f"[blue]{attack}[/blue]", "[green]Enable[/green]")
            else:
                table.add_row(f"[blue]{attack}[/blue]", "[red]Disable[/red]")

        console.print(table)

    def __show_one(self, attack: str) -> None:
        console = Console()
        table = self.__create_table()
        try:
            if self._cmd.active_attacks[attack]:
                table.add_row(attack, "[green]Enable[/green]")
            else:
                table.add_row(attack, "[red]Disable[/red]")
            console.print(table)
        except KeyError:
            self._cmd.error_logger.error("This attack does not exist")

    argParser = Cmd2ArgumentParser(
        description="""Command to show status of the attacks"""
    )

    display_options = argParser.add_argument_group(
        " Arguments for displaying information "
    )
    display_options.add_argument(
        "-SA",
        "--select_attack",
        action="store",
        help="Show status of a specific attack",
    )

    @with_argparser(argParser)
    def do_attack_status(self, args: argparse.Namespace) -> None:
        """[ Command to show active attacks ]

        Args:
            args (argparse.Namespace): [Arguments passed to the active_attacks command]
        """
        if args.select_attack:
            self.__show_one(args.select_attack)
        else:
            self.__show_all()
