from tracemalloc import start
from cmd2 import CommandSet, with_default_category
import cmd2
import argparse
from .dash_app import start_dashboard


@with_default_category("Utilities")
class DashboardCommand(CommandSet):
    argParser = cmd2.Cmd2ArgumentParser(
        description="""Tool to show information in a graph dashboard""",
        epilog="This command is not designed to use pipes(|) or redirections( >< ) when using the scan",
    )

    display_options = argParser.add_argument_group(
        " Arguments for displaying information "
    )
    display_options.add_argument(
        "-SS",
        "--show_settable",
        action="store_true",
        help="Show Settable variables for this command",
    )
    @cmd2.with_argparser(argParser)
    def do_dashboard(self, args: argparse.Namespace) -> None:
        lport = self._cmd.LPORT
        self._cmd.info_logger.debug(f"Starting dashboard command using user: {lport}")
        settable_variables_required = {
            "LPORT": lport,
        }
        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):
            start_dashboard(lport)
