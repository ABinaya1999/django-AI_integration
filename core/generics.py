from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import extend_schema
from rest_framework import generics, status
from rest_framework.response import Response

from .mixins import LoggingErrorsMixin
from .serializers import MessageResponseSerializer


class GenericAPIView(LoggingErrorsMixin, generics.GenericAPIView):
    logging_methods = ['GET']


class CreateAPIView(LoggingErrorsMixin, generics.CreateAPIView):
    logging_methods = ['POST']

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = self.perform_create(serializer)
        return self.response(
            result=result,
            serializer=serializer,
            status_code=status.HTTP_201_CREATED
        )

    def response(self, result, serializer, status_code):
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status_code, headers=headers)


class CreateWithMessageAPIView(CreateAPIView):
    message = _('Performed Successfully.')

    def response(self, result, serializer, status_code):
        return Response(
            {
                'message': self.message
            }, status=status.HTTP_200_OK
        )

    @extend_schema(responses=MessageResponseSerializer)
    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class ListAPIView(LoggingErrorsMixin, generics.ListAPIView):
    """
    Note: to disable pagination use "?pagination=False"
    """
    logging_methods = ['GET']
    enable_basic_list = False

    def filter_queryset(self, queryset):
        for backend in list(self.filter_backends):
            queryset = backend().filter_queryset(self.request, queryset, self)
        return self.custom_queryset(queryset)

    def custom_queryset(self, queryset):
        return queryset

    def get_serializer_class(self):
        if self.enable_basic_list:
            assert self.basic_list_serializer_class is not None, (
                "'%s' should either include a `basic_list_serializer_class` attribute, "
                "or override the `get_serializer_class()` method."
                % self.__class__.__name__
            )
            return self.basic_list_serializer_class
        return super().get_serializer_class()

    def get(self, request, *args, **kwargs):
        pagination = request.GET.get('pagination', 'true')
        if request.GET.get('basic_list', 'false').lower() == 'true':
            self.enable_basic_list = True
        if pagination.lower() == 'false':
            self.pagination_class = None
        return self.list(request, *args, **kwargs)


class UpdateAPIView(LoggingErrorsMixin, generics.UpdateAPIView):
    logging_methods = ['PUT', 'PATCH']

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return self.response(serializer=serializer)

    def response(self, serializer):
        return Response(serializer.data)


class UpdateWithMessageAPIView(UpdateAPIView):
    message = _('Updated successfully.')

    def response(self, serializer):
        return Response(
            {
                'message': self.message
            }, status=status.HTTP_200_OK
        )

    @extend_schema(responses=MessageResponseSerializer)
    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    @extend_schema(responses=MessageResponseSerializer)
    def patch(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)


def response(result, status_code):
    return Response(status=status_code)


class DestroyAPIView(LoggingErrorsMixin, generics.DestroyAPIView):
    logging_methods = ['DELETE']

    # permission_classes = (IsPortalOrAdminUser,)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        result = self.perform_destroy(instance)
        return response(result=result, status_code=status.HTTP_204_NO_CONTENT)


class RetrieveAPIView(LoggingErrorsMixin, generics.RetrieveAPIView):
    logging_methods = ['GET']


class UpdateRetrieveAPIView(LoggingErrorsMixin, generics.RetrieveUpdateDestroyAPIView):
    logging_methods = ['GET', 'PUT', 'PATCH', 'UPDATE']

class UserBasedSerializerMixin:
    """
    user_types_for_serializer_class should match exactly to the user model's user_type choices
    """
    user_types_for_serializer_class = []
    default_serializer_class = None

    def get_user_based_serializer_class(self):
        # 1. raise assert if default_serializer_class is not set
        assert self.default_serializer_class is not None, (
            f'{self.__class__.__name__} should include a `default_serializer_class` attribute'

        )
        requesting_user = self.request.user

        if requesting_user.is_authenticated:
            for user_type in self.user_types_for_serializer_class:
                assert hasattr(self, '{}_serializer_class'.format(user_type)) is not False, (
                    f'{self.__class__.__name__} should include a `{user_type}_serializer_class` attribute'
                )

                if requesting_user.user_type == user_type:
                    return getattr(self, '{}_serializer_class'.format(user_type))

        return self.default_serializer_class
