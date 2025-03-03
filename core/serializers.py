import environ
from rest_framework import serializers

env = environ.Env()


class MessageResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class IdNameSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    name = serializers.CharField()


class GeolocationSerializer(serializers.Serializer):
    latitude = serializers.FloatField()
    longitude = serializers.FloatField()


class RelativeURLField(serializers.ImageField):
    def to_representation(self, value):
        if not value:
            return None
        return f'{env("BASE_URL")}{value.url}'


class BaseModelSerializer(serializers.ModelSerializer):
    class Meta:
        depth = 0  # Default depth for write operations

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Dynamically adjust Meta.depth for GET requests only
        request = self.context.get('request')
        if request and request.method == 'GET':
            self.Meta.depth = max(getattr(self.Meta, 'depth', 0), 1)  # Ensure at least 1 for GET
        else:
            self.Meta.depth = 0  # Explicitly set depth to 0 for non-GET methods

    def to_representation(self, instance):
        # Save the original depth
        original_depth = getattr(self.Meta, 'depth', None)

        # Adjust depth for representation if self.depth exists
        if hasattr(self, 'depth'):
            self.Meta.depth = self.depth

        # Call parent representation method
        representation = super().to_representation(instance)

        # Restore the original depth
        if original_depth is not None:
            self.Meta.depth = original_depth

        return representation
