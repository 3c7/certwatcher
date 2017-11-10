import certstream
import logging
import yara
import os

from .models import Rule
from glob import glob
from click import echo
from termcolor import colored


class CertWatcher:
    def __init__(self, **kwargs):
        if isinstance(kwargs.get('disable', None), list):
            self.disable = kwargs.get('disable', [])
        else:
            self.disable = []
        self.logger = logging.getLogger('certwatcher')
        self.rules = []
        self.filepath = kwargs.get('filepath', None)
        self.yara_path = kwargs.get('yara')

        # Load yara rules
        for file in glob('{}/*.yar'.format(self.yara_path)):
            base = os.path.basename(file)
            if base not in self.disable:
                rule = yara.compile(file)
                self.rules.append(Rule(base, rule))
                logging.debug('Added rule {}.'.format(base))
            else:
                logging.debug('Ignoring rule {}'.format(base))

    def callback(self, m, c):
        if len(self.rules) > 0:
            self.invoke_rules(m)

    def invoke_rules(self, message):
        for rule in self.rules:
            self.invoke_single_rule(message, rule)

    def invoke_single_rule(self, message, rule):
        for domain in message['data']['leaf_cert']['all_domains']:
            match = rule.yara_rule.match(data=domain)
            if match:
                echo('[{}] matches domain {}.'.format(match[0].rule, colored(domain, 'yellow')))

    def start_certstream(self):
        certstream.listen_for_events(message_callback=self.callback)
