import certstream
import logging
import io
import yaml

from .models import Rule
from glob import glob
from termcolor import colored

# Try to use libyaml bindings, if possible
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


class CertWatcher:
    def __init__(self, **kwargs):
        self.logger = logging.getLogger('certwatcher')
        self.filepath = kwargs.get('filepath', None)
        self.yaml_path = kwargs.get('yaml', None)
        self.yaml_rules = []

        if not self.yaml_path:
            self.logger.error('No ruleset provided. Please pass a path to the yaml ruleset via -r/--rules.')
            exit(code=1)

        # Load yaml rules
        if self.yaml_path:
            for file in glob('{}/*.yml'.format(self.yaml_path)):
                with io.open(file, 'r') as handle:
                    content = yaml.load(handle.read(), Loader=Loader)
                    rule = Rule(
                        name=content['name'],
                        description=content['description'],
                        color=content.get('color', 'yellow'),
                        strings=content['strings']
                    )
                    try:
                        self.yaml_rules.append(rule)
                        self.logger.info('## Added rule ##\nName: {}\nDescription:{}'.format(
                            rule.name,
                            rule.description
                        ))
                    except KeyError as ke:
                        self.logger.error('KeyError while handling {} ({}).'.format(file, ke))

    def callback(self, m, c):
        self.invoke_rules(m)

    def invoke_rules(self, message):
        for yaml_rule in self.yaml_rules:
            self.invoke_single_yaml_rule(message, yaml_rule)

    def invoke_single_yaml_rule(self, message, rule):
        for domain in message['data']['leaf_cert']['all_domains']:
            self.logger.debug('Checking {}...'.format(domain))
            for string in rule.strings:
                if domain.find(string) != -1:
                    self.logger.warning('{}: matches {}'.format(colored(domain, rule.color), rule.name))

    def start_certstream(self):
        certstream.listen_for_events(message_callback=self.callback)
