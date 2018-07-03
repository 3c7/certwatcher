class Rule:
    def __init__(self, **kwargs):
        self.name = kwargs.get('name')
        self.description = kwargs.get('description', None)
        self.strings = kwargs.get('strings', None)
        self.color = kwargs.get('color', 'yellow')
        self.yara_rule = kwargs.get('yara_rule', None)
