from django.conf import settings
from django.utils.timezone import now
from rest_framework_tracking.base_mixins import BaseLoggingMixin
# from rest_framework_tracking.mixins import LoggingMixin


class LoggingErrorsMixin():
    """
    Log only errors
    """

    def initial(self, request, *args, **kwargs):
        self.log = {
            'requested_at': now(),
            'data': self._clean_data(request.data)
        }

        super(BaseLoggingMixin, self).initial(request, *args, **kwargs)

        try:
            # Accessing request.data *for the first time* parses the request body, which may raise
            # ParseError and UnsupportedMediaType exceptions. It's important not to swallow these,
            # as (depending on implementation details) they may only get raised this once, and
            # DRF logic needs them to be raised by the view for error handling to work correctly.
            data = self.request.data.dict()
        except AttributeError:
            data = self.request.data
        self.log['data'] = self._clean_data(data)

    def should_log(self, request, response):
        if settings.DEBUG:
            return False
        else:
            if request.method not in self.logging_methods:
                return False
            return response.status_code >= 200
