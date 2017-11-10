import click
import logging

from .controller import CertWatcher


@click.command()
@click.option('--yara', '-y', 'yara', help='Path to yara rules directory.')
@click.option('--verbose', '-v', 'debug', is_flag=True, help='Enables debug output')
@click.option('--disable', '-d', 'disable', help='List containing filenames of disabled rules')
def cli(yara, debug, disable):
    if debug:
        logging.basicConfig(format='[%(levelname)s:certwatcher] %(asctime)s - %(message)s', level=logging.DEBUG, )
    else:
        logging.basicConfig(format='[%(levelname)s:certwatcher] %(asctime)s - %(message)s', level=logging.INFO)

    if disable:
        disable = disable.split(',')

    cw = CertWatcher(
        yara=yara,
        disable=disable
    )
    cw.start_certstream()


if __name__ == '__main__':
    cli()
