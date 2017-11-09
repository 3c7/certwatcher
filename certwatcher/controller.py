import io
import json
import certstream
import logging


from .models import Rule
from glob import glob
from jsonschema import validate, ValidationError
from click import echo
from termcolor import colored


class CertWatcher:
    def __init__(self, **kwargs):
        self.rules = []
        self.schemas = {}
        self.schema_path = kwargs.get('spath', 'schemas')
        self.rule_path = kwargs.get('rpath', 'rules')
        self.disable = kwargs.get('disable', [])

        for rule in self.disable:
            logging.debug('Ignoring rule {}.'.format(rule))

        # Append rules
        for rule in kwargs.get('rules', []):
            if isinstance(rule, Rule):
                if rule.name in self.rules:
                    continue
                self.rules.append(rule)
                logging.debug('Appended rule {}.'.format(rule.name))

        # Load schemas
        for schema in glob('{}/*.json'.format(self.schema_path)):
            with io.open(schema, 'r') as fh:
                dict_schema = json.loads(fh.read())
                self.schemas[dict_schema['title']] = dict_schema
                logging.debug('Found schema {}.'.format(dict_schema['title']))

    def import_json_rules(self, path):
        files = glob('{}/*.json'.format(path))
        for file in files:
            with io.open(file, 'r') as fh:
                dictrule = json.loads(fh.read())
                try:
                    validate(dictrule, self.schemas.get('Rule', {}))
                except ValidationError as e:
                    logging.error('Error while validating rule "{}": {}'.format(colored(dictrule['name']), e.message))

            if dictrule.get('name') not in self.disable:
                self.rules.append(Rule(
                    name=dictrule.get('name', None),
                    description=dictrule.get('description', None),
                    search_string=dictrule.get('searchString', None),
                    count=dictrule.get('count', None),
                    search_in=dictrule.get('searchIn', 'domain'),
                    color=dictrule.get('color', None)
                ))
                logging.debug('Added rule: {}'.format(dictrule['name']))

    def callback(self, m, c):
        if len(self.rules) > 0:
            self.invoke_rules(m)

    def invoke_rules(self, message):
        for rule in self.rules:
            self.invoke_single_rule(message, rule)

    def invoke_single_rule(self, message, rule):
        if rule.search_in == 'domain':
            domains = message['data']['leaf_cert']['all_domains']
            for dom in domains:
                if rule.invoke(dom):
                    echo('[Rule: {}] matches {}.'.format(rule.name, colored(dom, rule.color)))

    def start_certstream(self, cb=None):
        certstream.listen_for_events(message_callback=self.callback)
