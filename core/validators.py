from django.core.exceptions import ValidationError
from django.core.validators import _lazy_re_compile
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _

from .utils import is_email_disposable


@deconstructible
class Validator:
    message = None
    code = 'invalid'

    def __init__(self, message=None, code=None):
        if message is not None:
            self.message = message
        if code is not None:
            self.code = code

    def __call__(self, value):
        raise NotImplementedError("Subclasses should implement this!")

    def __eq__(self, other):
        return (
                isinstance(other, Validator) and
                (self.message == other.message) and
                (self.code == other.code)
        )


@deconstructible
class PhoneNumberValidator(Validator):
    message = _('Enter a valid phone number.')
    # phone_number_regex = _lazy_re_compile(r'^(\+977)([0-9]+)$')
    phone_number_regex = _lazy_re_compile(r'^\+977[0-9]+$')

    def __call__(self, value):
        if not value:
            raise ValidationError(self.message, code=self.code)

        if not self.phone_number_regex.match(value):
            raise ValidationError(self.message, code=self.code)


@deconstructible
class AmountValidator(Validator):
    message = _('Enter a valid amount.')

    def __init__(self, allow_zero=False, message=None, code=None):
        self.allow_zero = allow_zero
        super().__init__(message=message, code=code)

    def __call__(self, value):
        if not value:
            raise ValidationError(self.message, code=self.code)

        if not self.allow_zero and value == 0.00:
            raise ValidationError(_('Zero is not allowed.'), code=self.code)


@deconstructible
class ImageValidator(Validator):
    message = _('The maximum image file size that can be uploaded is 8MB')
    file_size = 8194304

    def __call__(self, value):
        if not value:
            raise ValidationError(self.message, code=self.code)

        if value.size > self.file_size:
            raise ValidationError(self.message, code=self.code)


@deconstructible
class VideoValidator(Validator):
    message = _('The maximum video file size that can be uploaded is 8MB')
    file_size = 8194304

    def __call__(self, value):
        if not value:
            raise ValidationError(self.message, code=self.code)

        if value.size > self.file_size:
            raise ValidationError(self.message, code=self.code)

        if hasattr(value.file, 'content_type') and value.file.content_type != 'video/mp4':
            raise ValidationError(_('Only mp4 files are allowed.'), code=self.code)


@deconstructible
class PercentageValidator(Validator):
    message = _('Enter a valid percentage.')

    def __call__(self, value):
        if not value:
            raise ValidationError(self.message, code=self.code)

        if value > 100.00:
            raise ValidationError(self.message, code=self.code)


@deconstructible
class DisposableEmailValidator(Validator):
    message = _('Disposable Email are not allowed.')

    def __call__(self, value):
        if not value:
            raise ValidationError(_('Enter a email.'), code=self.code)

        if is_email_disposable(value):
            raise ValidationError(self.message, code=self.code)


@deconstructible
class FullNameValidator(Validator):
    message = _('Enter a valid full-name.')
    fullname_regex = _lazy_re_compile(r'^[a-zA-Z]*\s[a-zA-Z]*$')

    def __init__(self, message=None, code=None):
        super().__init__(message=message, code=code)

    def __call__(self, value):
        if value:
            if not self.fullname_regex.match(value):
                raise ValidationError(self.message, code=self.code)


validate_amount = AmountValidator()
validate_disposable_email = DisposableEmailValidator()
validate_percentage = PercentageValidator()
validate_phone_number = PhoneNumberValidator()
validate_image = ImageValidator()
validate_video = VideoValidator()
validate_fullname = FullNameValidator()
