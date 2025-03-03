import logging
import requests
import json
import traceback
import os
from django.conf import settings


class SlackLogHandler(logging.Handler):
    def emit(self, record):
        if record.exc_info:
            webhook_url = settings.SLACK_WEBHOOK_URL
            message = {
                "text": "*Django Error Log*",
                "blocks": [
                        {
                        "type": "section", 
                        "text": {
                            "type": "mrkdwn", 
                            "text": f"*Route:* ```{record.getMessage()}```"
                            },
                        },   
                        {
                        "type": "section", 
                        "text": {
                            "type": "mrkdwn", 
                            "text": f"*Error:* ```{traceback.format_exc() }```"
                            },
                        },   
                ]
            }
            # Send the log entry to Slack
            requests.post(webhook_url, data=json.dumps(message), headers={"Content-Type": "application/json"})
