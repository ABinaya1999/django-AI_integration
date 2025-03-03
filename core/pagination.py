from rest_framework.pagination import CursorPagination
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class CustomCursorPagination(CursorPagination):
    page_size_query_param = 'limit'
    page_size = 20

    def __init__(self):
        self.total_count = 0
        super(CustomCursorPagination, self).__init__()

    def paginate_queryset(self, queryset, request, view=None):
        self.total_count = queryset.count()
        # Ensure the paginator is set correctly by calling the superclass method
        return super().paginate_queryset(queryset, request, view=view)

    def get_paginated_response(self, data):
        print(self.total_count)
        # total_count = getattr(self.page.paginator, 'count', 0) if hasattr(self.page, 'paginator') else 0
        return Response({
            'total': self.total_count,  # Total number of records
            'next': self.get_next_link(),  # Link to the next page
            'previous': self.get_previous_link(),  # Link to the previous page
            'results': data  # Paginated results
        })


class UserCursorPagination(CustomCursorPagination):
    ordering = '-date_joined'


class CustomPagination(PageNumberPagination):
    page_size = 10  # Number of record to shown at one page
    # page_query_param = 'p' #default page lai change garcha
    page_size_query_param = 'records'  # client can decide the page size
    max_page_size = 15  # To limit the page size
