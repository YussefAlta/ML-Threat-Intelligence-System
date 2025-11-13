"""
Utility module for API rate limiting, retry logic, and error handling.
"""
import time
import logging
from collections import deque
from typing import Optional, Callable, Any
from functools import wraps
import requests

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter using token bucket algorithm with sliding window."""
    
    def __init__(self, max_requests: int, window_seconds: int):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_times = deque()
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded."""
        now = time.time()
        
        # Remove requests older than the window
        while self.request_times and self.request_times[0] < now - self.window_seconds:
            self.request_times.popleft()
        
        # If we're at the limit, wait until the oldest request expires
        if len(self.request_times) >= self.max_requests:
            sleep_time = self.request_times[0] + self.window_seconds - now + 0.1
            if sleep_time > 0:
                logger.debug(f"Rate limit reached. Waiting {sleep_time:.2f} seconds...")
                time.sleep(sleep_time)
                # Clean up old requests after sleep
                now = time.time()
                while self.request_times and self.request_times[0] < now - self.window_seconds:
                    self.request_times.popleft()
        
        # Record this request
        self.request_times.append(time.time())
    
    def reset(self):
        """Reset the rate limiter."""
        self.request_times.clear()


def retry_with_backoff(
    max_retries: int = 5,
    backoff_multiplier: float = 2.0,
    initial_delay: float = 1.0,
    exceptions: tuple = (requests.RequestException,),
    retry_condition: Optional[Callable[[Exception], bool]] = None
):
    """
    Decorator for retrying API calls with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        backoff_multiplier: Multiplier for exponential backoff
        initial_delay: Initial delay in seconds before first retry
        exceptions: Tuple of exceptions to catch and retry on
        retry_condition: Optional function that takes an exception and returns True if should retry
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    # Check if we should retry based on custom condition
                    if retry_condition and not retry_condition(e):
                        logger.error(f"Non-retryable error in {func.__name__}: {str(e)}")
                        raise
                    
                    # Check if we've exhausted retries
                    if attempt >= max_retries:
                        logger.error(
                            f"Max retries ({max_retries}) exceeded for {func.__name__}. "
                            f"Last error: {str(e)}"
                        )
                        raise
                    
                    # For HTTP errors, check if it's retryable
                    if isinstance(e, requests.HTTPError):
                        response = getattr(e, 'response', None)
                        if response is not None:
                            status_code = response.status_code
                            # Don't retry on client errors (4xx) except 429 (rate limit) and 408 (timeout)
                            if 400 <= status_code < 500 and status_code not in (429, 408):
                                logger.error(
                                    f"Client error {status_code} in {func.__name__}: {str(e)}. "
                                    "Not retrying."
                                )
                                raise
                            # Don't retry on 5xx errors after max retries
                            if status_code >= 500:
                                logger.warning(
                                    f"Server error {status_code} in {func.__name__} (attempt "
                                    f"{attempt + 1}/{max_retries + 1}): {str(e)}"
                                )
                    
                    logger.warning(
                        f"Error in {func.__name__} (attempt {attempt + 1}/{max_retries + 1}): "
                        f"{str(e)}. Retrying in {delay:.2f} seconds..."
                    )
                    time.sleep(delay)
                    delay *= backoff_multiplier
            
            # Should not reach here, but just in case
            if last_exception:
                raise last_exception
                
        return wrapper
    return decorator


def is_retryable_http_error(response: requests.Response) -> bool:
    """
    Determine if an HTTP error is retryable.
    
    Args:
        response: HTTP response object
        
    Returns:
        True if the error is retryable, False otherwise
    """
    if response.status_code == 429:  # Rate limit
        return True
    if response.status_code == 408:  # Request timeout
        return True
    if 500 <= response.status_code < 600:  # Server errors
        return True
    return False


class APIClient:
    """Base API client with rate limiting and retry logic."""
    
    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        rate_limiter: Optional[RateLimiter] = None,
        max_retries: int = 5,
        backoff_multiplier: float = 2.0,
        timeout: int = 30
    ):
        """
        Initialize API client.
        
        Args:
            base_url: Base URL for the API
            api_key: Optional API key for authentication
            rate_limiter: Optional rate limiter instance
            max_retries: Maximum number of retries for failed requests
            backoff_multiplier: Exponential backoff multiplier
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.rate_limiter = rate_limiter
        self.max_retries = max_retries
        self.backoff_multiplier = backoff_multiplier
        self.timeout = timeout
        
        # Create session with default headers
        self.session = requests.Session()
        # Note: NIST API key is passed as a query parameter, not a header
        self.session.headers.update({
            'User-Agent': 'ML-Threat-Intelligence-System/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make an API request with rate limiting and retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (relative to base_url)
            params: Query parameters
            json_data: JSON body data
            **kwargs: Additional arguments to pass to requests
            
        Returns:
            Response object
        """
        delay = 1.0
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                # Apply rate limiting
                if self.rate_limiter:
                    self.rate_limiter.wait_if_needed()
                
                # Construct URL
                url = f"{self.base_url}/{endpoint.lstrip('/')}"
                
                # Add API key to params if provided (NIST API uses query parameter)
                request_params = dict(params) if params else {}
                if self.api_key:
                    request_params['apiKey'] = self.api_key
                
                # Make request
                response = self.session.request(
                    method=method,
                    url=url,
                    params=request_params,
                    json=json_data,
                    timeout=self.timeout,
                    **kwargs
                )
                
                # Check for rate limit errors
                if response.status_code == 429:
                    retry_after = response.headers.get('Retry-After')
                    if retry_after:
                        try:
                            wait_time = float(retry_after)
                            logger.warning(f"Rate limited. Waiting {wait_time} seconds (Retry-After header)...")
                            time.sleep(wait_time)
                            # Retry the request once more
                            response = self.session.request(
                                method=method,
                                url=url,
                                params=request_params,
                                json=json_data,
                                timeout=self.timeout,
                                **kwargs
                            )
                        except ValueError:
                            logger.warning(f"Invalid Retry-After header: {retry_after}")
                
                # Check for retryable errors
                if response.status_code >= 500:
                    # Server error - retry
                    if attempt < self.max_retries:
                        logger.warning(
                            f"Server error {response.status_code} (attempt {attempt + 1}/"
                            f"{self.max_retries + 1}). Retrying in {delay:.2f} seconds..."
                        )
                        time.sleep(delay)
                        delay *= self.backoff_multiplier
                        continue
                
                # Raise for HTTP errors (but not if we're going to retry)
                if response.status_code >= 400:
                    response.raise_for_status()
                
                return response
                
            except requests.RequestException as e:
                last_exception = e
                
                # Check if we should retry
                if attempt >= self.max_retries:
                    logger.error(
                        f"Max retries ({self.max_retries}) exceeded. Last error: {str(e)}"
                    )
                    raise
                
                # Check if it's a retryable error
                if isinstance(e, requests.HTTPError):
                    response = getattr(e, 'response', None)
                    if response and not is_retryable_http_error(response):
                        # Non-retryable error
                        logger.error(f"Non-retryable error {response.status_code}: {str(e)}")
                        raise
                
                logger.warning(
                    f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}): "
                    f"{str(e)}. Retrying in {delay:.2f} seconds..."
                )
                time.sleep(delay)
                delay *= self.backoff_multiplier
        
        # Should not reach here
        if last_exception:
            raise last_exception
        raise RuntimeError("Unexpected error in _make_request")
    
    def get(self, endpoint: str, params: Optional[dict] = None, **kwargs) -> requests.Response:
        """Make a GET request."""
        return self._make_request('GET', endpoint, params=params, **kwargs)
    
    def post(self, endpoint: str, params: Optional[dict] = None, json_data: Optional[dict] = None, **kwargs) -> requests.Response:
        """Make a POST request."""
        return self._make_request('POST', endpoint, params=params, json_data=json_data, **kwargs)

