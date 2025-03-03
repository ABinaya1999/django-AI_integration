from django.db.models import CharField, DecimalField
from django.utils.translation import gettext_lazy as _

from . import validators, form_fields


class PhoneNumberField(CharField):
    default_validators = [validators.validate_phone_number]
    description = _("Phone Number")

    def __init__(self, *args, **kwargs):
        # max_length=254 to be compliant with RFCs 3696 and 5321
        kwargs.setdefault('max_length', 20)
        super().__init__(*args, **kwargs)

    def formfield(self, **kwargs):
        # As with CharField, this will cause phone number validation to be performed
        # twice.
        return super().formfield(**{
            'form_class': form_fields.PhoneNumberField,
            **kwargs,
        })


class AmountField(DecimalField):
    default_validators = [validators.validate_amount]

    def __init__(self, allow_zero=False, *args, **kwargs):
        self.allow_zero = allow_zero
        kwargs.setdefault('max_digits', 8)
        kwargs.setdefault('decimal_places', 2)
        super().__init__(*args, **kwargs)
        self.validators.append(validators.AmountValidator(allow_zero=self.allow_zero))


class PercentageField(DecimalField):
    default_validators = [validators.validate_percentage]

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('max_digits', 5)
        kwargs.setdefault('decimal_places', 2)
        super().__init__(*args, **kwargs)
