from project import Igris_Shell
import sys

if __name__ == "__main__":
    Shell = Igris_Shell()
    # debugging
    Shell.debug = True
    sys.exit(Shell.cmdloop())
    print("prueba")
