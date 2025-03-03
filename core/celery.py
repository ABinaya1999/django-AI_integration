import celery


class BaseTaskWithRetry(celery.Task):
    autoretry_for = (Exception, KeyError)
    retry_backoff = 5
    retry_kwargs = {'max_retries': 5}
