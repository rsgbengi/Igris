from cmd2 import CommandSet, with_default_category
import cmd2
import argparse
from .dash_app import start_dashboard


@with_default_category("Utilities")
class DashboardCommand(CommandSet):
    argParser = cmd2.Cmd2ArgumentParser(
        description="""Tool to show information in a graph dashboard""",
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
        """Dashboard to visualize users and computers of a subnet.

        Args:
            args (argparse.Namespace): Arguments.
        """
        lport = self._cmd.LPORT
        self._cmd.info_logger.debug(f"Starting dashboard command using lport: {lport}")
        settable_variables_required = {
            "LPORT": lport,
        }
        if args.show_settable:
            self._cmd.show_settable_variables_necessary(settable_variables_required)
        elif self._cmd.check_settable_variables_value(settable_variables_required):
            if not self._cmd.igris_db.check_status():
                self._cmd.error_logger.error("The db has not finished starting")
                return
            start_dashboard(lport)
