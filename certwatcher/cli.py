import click
import logging

from .controller import CertWatcher


@click.command()
@click.option('--rules', '-r', 'rulepath', help='Path to yaml rules directory.')
@click.option('--verbose', '-v', 'debug', is_flag=True, help='Enables debug output.')
def cli(debug, rulepath):
    if debug:
        logging.basicConfig(format='[%(levelname)s:certwatcher] %(asctime)s - %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='[%(levelname)s:certwatcher] %(asctime)s - %(message)s', level=logging.INFO)

    cw = CertWatcher(
        yaml=rulepath
    )
    cw.start_certstream()


if __name__ == '__main__':
    cli()
