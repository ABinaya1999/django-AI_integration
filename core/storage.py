import os

from django.conf import settings
from django.core.files import File
from django.core.files.storage import FileSystemStorage
from django.core.files.utils import validate_file_name

from .utils import reduce_image_size


class OverwriteStorage(FileSystemStorage):

    def save(self, name, content, max_length=None):
        """
        Save new content to the file specified by name. The content should be
        a proper File object or any Python file-like object, ready to be read
        from the beginning.
        """
        # Get the proper name for the file, as it will actually be saved.
        if name is None:
            name = content.name

        if not hasattr(content, "chunks"):
            content = File(content, name)

        content = reduce_image_size(image=File(content, name), quality=50)

        name = self.get_available_name(name, max_length=max_length)
        name = self._save(name, content)
        # Ensure that the name returned from the storage system is still valid.
        validate_file_name(name, allow_relative_path=True)
        return name

    def get_available_name(self, name, max_length=None):
        if self.exists(name):
            os.remove(os.path.join(settings.MEDIA_ROOT, name))
        return name
