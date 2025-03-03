from django.utils.translation import gettext_lazy as _
from rest_framework.fields import CharField, DecimalField

from . import validators


class PhoneNumberField(CharField):
    default_error_messages = {
        'invalid': _('Enter a valid phone number.')
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        validator = validators.PhoneNumberValidator(message=self.error_messages['invalid'])
        self.validators.append(validator)


class PasswordField(CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('style', {})

        kwargs['style']['input_type'] = 'password'
        kwargs['write_only'] = True

        super().__init__(**kwargs)


class AmountField(DecimalField):
    def __init__(self, max_digits=8, decimal_places=2, **kwargs):
        super().__init__(max_digits, decimal_places, **kwargs)
