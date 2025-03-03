from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import APIException, ErrorDetail
from rest_framework.views import exception_handler


class NoContent(APIException):
    status_code = status.HTTP_204_NO_CONTENT
    default_detail = _('Content temporarily unavailable, try again later.')
    default_code = 'no_content'


class SlackSendFailed(Exception):
    pass


def custom_exception_handler(exc, context):
    """
    Call REST framework's default exception handler first,
    to get the standard error response.

    :param exc:
    :param context:
    :return: custom response
    """
    response = exception_handler(exc, context)

    # Now add the HTTP status code to the response.
    if response is not None:
        customized_response = {'errors': []}
        for key, value in response.data.items():
            if isinstance(value, ErrorDetail):
                value = [value]
            if key == 'detail':
                error = {'field': 'non_field_errors', 'message': value}
            else:
                error = {'field': key, 'message': value}
            customized_response['errors'].append(error)

        response.data = customized_response

    return response
