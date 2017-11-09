class Rule:
    def __init__(self, search_string, count, search_in, **kwargs):
        self.name = kwargs.get('name', None)
        self.description = kwargs.get('description', None)
        self.search = search_string
        self.count = count
        self.search_in = search_in
        self.color = kwargs.get('color', 'yellow')

    def invoke(self, string):
        """
        Searches for `count` * `search_string` in `string`

        :param string:
        :type string: str
        :return: True if roule applies
        :rtype boolean:
        """
        if string.count(self.search) >= self.count:
            return True
        return False