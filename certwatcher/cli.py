import click
import logging

from .controller import CertWatcher
from termcolor import colored

RULE_LIST = []


@click.command()
@click.option('--rule-path', '-r', 'rpath', help='Path to rule directory')
@click.option('--schema-path', '-s', 'spath', help='Path to schema directory')
@click.option('--verbose', '-v', 'debug', is_flag=True, help='Enables debug output')
@click.option('--disable', '-d', 'disable', help='List containing names of disabled rules')
def cli(rpath, spath, debug, disable):
    if debug:
        logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)

    disable = disable.split(',')

    cw = CertWatcher(
        rpath=rpath,
        spath=spath,
        disable=disable
    )
    cw.import_json_rules('rules')
    cw.start_certstream()


if __name__ == '__main__':
    cli()
