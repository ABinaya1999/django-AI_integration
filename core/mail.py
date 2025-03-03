from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import get_template
from university_attendance_management.core.utils import MicrosoftAuth

class BaseEmailMessage:
    template_name = None

    def __init__(self, context: dict, subject: str):
        self._subject = subject
        self._context = context

    def send_mail(self, to: list, body: str):
        # Send a test email with plain text content
        test_message = "This is a test email message."
        mail = EmailMessage(
            subject="Test Email - " + self._subject,
            body=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=to,
        )
        return mail.send(fail_silently=True)

    def send(self, to: list, *args, **kwargs):
        mail = EmailMessage(
            subject=self._subject,
            body=self._get_message(),
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=to,
            reply_to=kwargs.pop('reply_to', []),
        )
        mail.content_subtype = "html"
        return mail.send()

    def _get_message(self):
        return get_template(self.template_name).render(self._context)

def send_mail(to, subject, body):

    auth = MicrosoftAuth()

    # recipient_emails can be Array or single string
    auth.send_email(
        recipient_emails=to,
        subject=subject,
        body=body
    )
