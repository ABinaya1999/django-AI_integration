from django.contrib.admin import ModelAdmin


class ArchiveMixin:
    def archive(self, request, queryset):
        queryset.archive()

    def restore(self, request, queryset):
        queryset.restore()

    archive.short_description = 'Archive selected items'
    restore.short_description = 'Restore selected items'


class PublishMixin:
    def publish(self, request, queryset):
        queryset.publish()

    def hide(self, request, queryset):
        queryset.hide()

    publish.short_description = 'Publish selected items'
    hide.short_description = 'Hide selected items'


class BaseModelAdmin(ModelAdmin, ArchiveMixin):
    list_display = (
        'updated',
    )
    search_fields = (
        'id',
    )
    ordering = (
        '-created',
    )
    list_per_page = (
        25
    )
    actions = [
        'archive',
        'restore'
    ]
    readonly_fields = (
        'created',
        'updated'
    )
    list_filter = (
        'is_archived',
    )


class BasePublishModelAdmin(BaseModelAdmin, PublishMixin):
    actions = [
        'archive',
        'restore',
        'publish',
        'hide'
    ]
    readonly_fields = (
        'created',
        'updated'
    )
    list_filter = (
        'is_archived',
        'is_published'
    )
