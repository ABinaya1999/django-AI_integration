from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response


class BaseModelViewSet(viewsets.ModelViewSet):
    def get_serializer_context(self):
        context = super().get_serializer_context()
        # Always include the request in the context
        context['request'] = self.request
        return context


    @action(detail=False, methods=['delete'])
    def bulk_delete(self, request, *args, **kwargs):
        """
        Custom action to delete multiple objects.
        Expects a list of IDs in the request body.
        """
        ids = request.data.get('ids', [])
        if not isinstance(ids, list):
            return Response(
                {"error": "Expected a list of IDs."},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.get_queryset().filter(id__in=ids)
        count = queryset.count()
        if count != len(ids):
            return Response(
                {"error": "Some IDs were not found or are invalid."},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset.delete()
        return Response(
            {"message": f"{count} objects deleted successfully."},
            status=status.HTTP_200_OK
        )
