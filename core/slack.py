import json
from urllib import request

from .exceptions import SlackSendFailed


class Slack:
    """"
    blocks_context = {
        'header': 'string',
        'sections': 'dict of items and value'
    }
    """
    def __init__(self, text, blocks_context=None):
        self.blocks_context = blocks_context
        self.text = text

    def get_payload(self):
        payload = {
            "text": self.text
        }
        if self.blocks_context:
            payload["blocks"] = self.generate_blocks()

        return payload

    def generate_blocks(self):
        """"
        blocks_context = {
            'header': 'string',
            'sections': 'dict of items and value'
        }
        """
        # 1. validate blocks_context
        if not self.blocks_context.get('sections', None):
            raise ValueError('blocks_context should have \'sections\' key')
        # 1. a if exists check if it is dict
        elif not isinstance(self.blocks_context.get('sections'), dict):
            raise TypeError('\'sections\' should be of type \'dict\'')


        blocks = []
        if 'header' in self.blocks_context:
            # 2. if header is not of type string
            if not isinstance(self.blocks_context.get('header'), str):
                raise TypeError('\'header\' should be of type \'dict\'')
            blocks.append({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": self.blocks_context.get('header'),
                    "emoji": True
                }
            })


        blocks.append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*{key}:*\n{value}"
                } for key, value in self.blocks_context.get('sections').items()
            ]
        })
        return blocks


    def send(self, hook_url):
        json_data = json.dumps(self.get_payload())
        req = request.Request(
            hook_url,
            data=json_data.encode('ascii'),
            headers={'Content-Type': 'application/json'}
        )
        try:
            resp = request.urlopen(req)
        except Exception as e:
            raise SlackSendFailed
