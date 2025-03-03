import uuid

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import models
from django.utils import timezone
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _

from . import managers
from .utils import generate_random_string


class BaseModel(models.Model):
    """
    Base Model that will be used in this project
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    is_archived = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated = models.DateTimeField(auto_now_add=True, blank=True, null=True)

    class Meta:
        abstract = True

    objects = managers.BaseModelManager()

    def archive(self):
        if self.is_archived:
            raise DjangoValidationError({
                'non_field_errors': _('Failed - it is already archived.')
            })
        self.is_archived = True
        self.updated = timezone.now()
        self.save(update_fields=['is_archived', 'updated'])

    def restore(self):
        if not self.is_archived:
            raise DjangoValidationError({
                'non_field_errors': _('Failed - it is already restored.')
            })
        self.is_archived = False
        self.updated = timezone.now()
        self.save(update_fields=['is_archived', 'updated'])


class BasePublishModel(BaseModel):
    is_published = models.BooleanField(default=False)

    class Meta:
        abstract = True

    def publish(self):
        if self.is_published:
            raise DjangoValidationError({
                'non_field_errors': _('Failed - it is already published.')
            })
        self.is_published = True
        self.updated = timezone.now()
        self.save(update_fields=['is_published', 'updated'])

    def hide(self):
        if not self.is_published:
            raise DjangoValidationError({
                'non_field_errors': _('Failed - it is already hidden.')
            })
        self.is_published = False
        self.updated = timezone.now()
        self.save(update_fields=['is_published', 'updated'])


class BaseModelWithSlug(BaseModel):
    slug = models.SlugField(unique=True, max_length=100, blank=True)
    # List of common fields that might be used to generate slugs
    SLUG_FIELDS = ['title', 'name', 'heading', 'label', 'first_name']  # Extend this list as needed

    class Meta:
        abstract = True

    def get_slug_source(self):
        """Check for the first available slug field in SLUG_FIELDS."""
        for field in self.SLUG_FIELDS:
            if hasattr(self, field):
                value = getattr(self, field)
                if value:  # Ensure the field is not empty
                    return value
        return None

    def save(self, *args, **kwargs):
        if not self.slug:
            # Try to generate slug from common fields like 'title', 'name', etc.
            slug_source = self.get_slug_source()
            if slug_source:
                base_slug = slugify(slug_source)
            else:
                # Fallback to a random slug if no slug source is available
                base_slug = generate_random_string(length=8)

            # Always append a random string to make the slug unique
            self.slug = f"{base_slug}-{generate_random_string(length=3)}"

        # Ensure slug is unique by appending additional random characters if needed
        original_slug = self.slug
        counter = 1
        # Use the model's manager (self.__class__) instead of BaseModelWithSlug.objects
        while self.__class__.objects.filter(slug=self.slug).exists():
            self.slug = f"{original_slug}-{generate_random_string(3)}"
            counter += 1

        super().save(*args, **kwargs)
