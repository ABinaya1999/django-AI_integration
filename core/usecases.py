from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import ValidationError

from .utils import update

User = get_user_model()


class BaseUseCase:
    """
    Base Use Case
    """

    def execute(self):
        self.is_valid()
        return self._factory()

    def _factory(self):
        raise NotImplementedError("Subclasses should implement this!")

    def is_valid(self):
        return True


class CreateUseCase(BaseUseCase):
    def __init__(self, serializer):
        self._serializer = serializer
        self._data = self._serializer.validated_data

    def execute(self):
        self.is_valid()
        return self._factory()


class UpdateUseCase(BaseUseCase):
    def __init__(self, serializer, instance):
        self._serializer = serializer
        self._data = serializer.validated_data
        self._instance = instance

    def execute(self):
        self.is_valid()
        self._factory()
        return self._instance

    def _factory(self):
        update(instance=self._instance, data=self._data, serializer_class=self._serializer)


class DeleteUseCase(BaseUseCase):

    def __init__(self, instance):
        self._instance = instance

    def execute(self):
        self.is_valid()
        self._factory()
        return self._instance

    def _factory(self):
        try:
            self._instance.archive()
        except DjangoValidationError as e:
            raise ValidationError(e.error_dict)
