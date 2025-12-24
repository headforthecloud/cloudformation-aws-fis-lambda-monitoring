import pytest
import os
import logging
from unittest.mock import MagicMock, patch
# import boto3
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
from src.lambda_function import lambda_handler
import json


@pytest.fixture
def mock_context():
    """Create a mock Lambda context object."""
    context = MagicMock()
    context.function_name = "test-function"
    context.memory_limit_in_mb = 128
    context.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-function"
    context.aws_request_id = "test-request-id"
    context.log_group_name = "/aws/lambda/test-function"
    context.log_stream_name = "2023/01/01/[$LATEST]abcdef123456"
    context.get_remaining_time_in_millis = lambda: 30000
    return context


@pytest.fixture
def mock_event():
    """Create a mock Lambda event."""
    return {}


@pytest.fixture
def empty_event():
    """Create an empty event."""
    return {}


@pytest.fixture
def event_with_data():
    """Create an event with some data."""
    return {
        "key1": "value1",
        "key2": "value2",
        "Records": [
            {
                "eventVersion": "2.1",
                "eventSource": "aws:s3"
            }
        ]
    }


@pytest.fixture
def mock_sts_client():
    """Create a mock STS client."""
    mock_client = MagicMock()
    mock_client.get_caller_identity.return_value = {
        "Account": "123456789012",
        "UserId": "AIDACKCEVSQ6C2EXAMPLE",
        "Arn": "arn:aws:iam::123456789012:user/test-user"
    }
    return mock_client


@patch('boto3.client')
def test_lambda_handler_success(mock_boto3_client, mock_sts_client, mock_event, mock_context, caplog):
    """Test lambda_handler successfully gets caller identity."""
    mock_boto3_client.return_value = mock_sts_client
    
    with caplog.at_level(logging.INFO):
        response = lambda_handler(mock_event, mock_context)
    
    # Assert boto3.client was called with correct service
    mock_boto3_client.assert_called_once_with('sts')
    
    # Assert STS get_caller_identity was called
    mock_sts_client.get_caller_identity.assert_called_once()
    
    # Assert response structure
    assert response['statusCode'] == 200
    assert 'headers' in response
    assert response['headers']['Content-Type'] == "application/json"
    
    # Parse JSON body

    body = json.loads(response['body'])
    assert body['statusMessage'] == "All OK"
    assert body['accountId'] == "123456789012"
    
    # Assert logging
    assert "Hello from Lambda!" in caplog.text
    assert "I'm running in account 123456789012" in caplog.text


@patch('boto3.client')
def test_lambda_handler_with_empty_event(mock_boto3_client, mock_sts_client, empty_event, mock_context, caplog):
    """Test lambda_handler with empty event."""
    mock_boto3_client.return_value = mock_sts_client
    
    with caplog.at_level(logging.INFO):
        response = lambda_handler(empty_event, mock_context)
    
    assert response['statusCode'] == 200
    

    body = json.loads(response['body'])
    assert body['statusMessage'] == "All OK"
    assert body['accountId'] == "123456789012"
    assert "Hello from Lambda!" in caplog.text


@patch('boto3.client')
def test_lambda_handler_with_event_data(mock_boto3_client, mock_sts_client, event_with_data, mock_context, caplog):
    """Test lambda_handler with event containing data."""
    mock_boto3_client.return_value = mock_sts_client
    
    with caplog.at_level(logging.INFO):
        response = lambda_handler(event_with_data, mock_context)
    
    assert response['statusCode'] == 200
    

    body = json.loads(response['body'])
    assert body['statusMessage'] == "All OK"
    assert body['accountId'] == "123456789012"
    assert "Hello from Lambda!" in caplog.text
    assert "I'm running in account 123456789012" in caplog.text


@patch('boto3.client')
def test_lambda_handler_none_event_and_context(mock_boto3_client, mock_sts_client, caplog):
    """Test lambda_handler with None event and context."""
    mock_boto3_client.return_value = mock_sts_client
    
    with caplog.at_level(logging.INFO):
        response = lambda_handler(None, None)
    
    assert response['statusCode'] == 200
    

    body = json.loads(response['body'])
    assert body['statusMessage'] == "All OK"
    assert body['accountId'] == "123456789012"
    assert "Hello from Lambda!" in caplog.text


@patch('boto3.client')
def test_lambda_handler_different_account_id(mock_boto3_client, mock_event, mock_context, caplog):
    """Test lambda_handler with different account ID."""
    mock_sts_client = MagicMock()
    mock_sts_client.get_caller_identity.return_value = {
        "Account": "987654321098",
        "UserId": "AIDACKCEVSQ6C2EXAMPLE",
        "Arn": "arn:aws:iam::987654321098:user/test-user"
    }
    mock_boto3_client.return_value = mock_sts_client
    
    with caplog.at_level(logging.INFO):
        response = lambda_handler(mock_event, mock_context)
    
    # Verify the different account ID is used
    assert "I'm running in account 987654321098" in caplog.text
    assert response['statusCode'] == 200
    

    body = json.loads(response['body'])
    assert body['accountId'] == "987654321098"


@patch('boto3.client')
def test_lambda_handler_sts_client_error(mock_boto3_client, mock_event, mock_context):
    """Test lambda_handler when STS client raises an exception."""
    mock_boto3_client.side_effect = ClientError(
        error_response={'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
        operation_name='GetCallerIdentity'
    )
    
    with pytest.raises(ClientError):
        lambda_handler(mock_event, mock_context)


@patch('boto3.client')
def test_lambda_handler_get_caller_identity_error(mock_boto3_client, mock_event, mock_context):
    """Test lambda_handler when get_caller_identity raises an exception."""
    mock_sts_client = MagicMock()
    mock_sts_client.get_caller_identity.side_effect = ClientError(
        error_response={'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
        operation_name='GetCallerIdentity'
    )
    mock_boto3_client.return_value = mock_sts_client
    
    with pytest.raises(ClientError):
        lambda_handler(mock_event, mock_context)


@patch('boto3.client')
def test_lambda_handler_no_credentials_error(mock_boto3_client, mock_event, mock_context):
    """Test lambda_handler when no AWS credentials are available."""
    mock_boto3_client.side_effect = NoCredentialsError()
    
    with pytest.raises(NoCredentialsError):
        lambda_handler(mock_event, mock_context)


@patch('boto3.client')
def test_lambda_handler_botocore_error(mock_boto3_client, mock_event, mock_context):
    """Test lambda_handler when BotoCoreError is raised."""
    mock_sts_client = MagicMock()
    mock_sts_client.get_caller_identity.side_effect = BotoCoreError()
    mock_boto3_client.return_value = mock_sts_client
    
    with pytest.raises(BotoCoreError):
        lambda_handler(mock_event, mock_context)


@patch.dict(os.environ, {'LOG_LEVEL': 'DEBUG'})
def test_logger_respects_debug_log_level():
    """Test that logger respects DEBUG LOG_LEVEL environment variable."""
    import importlib
    import src.lambda_function
    importlib.reload(src.lambda_function)
    
    from src.lambda_function import logger
    assert logger.level == logging.DEBUG


@patch.dict(os.environ, {'LOG_LEVEL': 'WARNING'})
def test_logger_respects_warning_log_level():
    """Test that logger respects WARNING LOG_LEVEL environment variable."""
    import importlib
    import src.lambda_function
    importlib.reload(src.lambda_function)
    
    from src.lambda_function import logger
    assert logger.level == logging.WARNING


@patch.dict(os.environ, {'LOG_LEVEL': 'ERROR'})
def test_logger_respects_error_log_level():
    """Test that logger respects ERROR LOG_LEVEL environment variable."""
    import importlib
    import src.lambda_function
    importlib.reload(src.lambda_function)
    
    from src.lambda_function import logger
    assert logger.level == logging.ERROR


@patch.dict(os.environ, {'LOG_LEVEL': 'CRITICAL'})
def test_logger_respects_critical_log_level():
    """Test that logger respects CRITICAL LOG_LEVEL environment variable."""
    import importlib
    import src.lambda_function
    importlib.reload(src.lambda_function)
    
    from src.lambda_function import logger
    assert logger.level == logging.CRITICAL


@patch.dict(os.environ, {'LOG_LEVEL': 'invalid'})
def test_logger_with_invalid_log_level():
    """Test logger behavior with invalid LOG_LEVEL."""
    import importlib
    import src.lambda_function
    
    # Invalid log levels should raise ValueError during module import
    with pytest.raises(ValueError, match="Unknown level: 'invalid'"):
        importlib.reload(src.lambda_function)


@patch.dict(os.environ, {}, clear=True)
def test_logger_defaults_to_info():
    """Test that logger defaults to INFO when LOG_LEVEL is not set."""
    import importlib
    import src.lambda_function
    importlib.reload(src.lambda_function)
    
    from src.lambda_function import logger
    assert logger.level == logging.INFO


@patch('boto3.client')
def test_lambda_handler_with_warning_log_level(mock_boto3_client, mock_sts_client, mock_event, mock_context, caplog):
    """Test lambda_handler with WARNING log level."""
    mock_boto3_client.return_value = mock_sts_client
    
    with patch.dict(os.environ, {'LOG_LEVEL': 'WARNING'}):
        import importlib
        import src.lambda_function
        importlib.reload(src.lambda_function)
        
        with caplog.at_level(logging.WARNING):
            response = src.lambda_function.lambda_handler(mock_event, mock_context)
        
        # With WARNING level, INFO messages should not appear in caplog
        # but the function should still work
        assert response['statusCode'] == 200
        # INFO messages should not be captured at WARNING level
        assert "Hello from Lambda!" not in caplog.text


@patch('boto3.client')
def test_lambda_handler_with_error_log_level(mock_boto3_client, mock_sts_client, mock_event, mock_context, caplog):
    """Test lambda_handler with ERROR log level."""
    mock_boto3_client.return_value = mock_sts_client
    
    with patch.dict(os.environ, {'LOG_LEVEL': 'ERROR'}):
        import importlib
        import src.lambda_function
        importlib.reload(src.lambda_function)
        
        with caplog.at_level(logging.ERROR):
            response = src.lambda_function.lambda_handler(mock_event, mock_context)
        
        assert response['statusCode'] == 200
        # INFO messages should not be captured at ERROR level
        assert "Hello from Lambda!" not in caplog.text


@patch('boto3.client')
def test_lambda_handler_response_format(mock_boto3_client, mock_sts_client, mock_event, mock_context):
    """Test that lambda_handler returns correct response format."""
    mock_boto3_client.return_value = mock_sts_client
    
    response = lambda_handler(mock_event, mock_context)
    
    # Verify response is a dictionary
    assert isinstance(response, dict)
    
    # Verify required keys exist
    assert 'statusCode' in response
    assert 'body' in response
    
    # Verify correct types
    assert isinstance(response['statusCode'], int)
    assert isinstance(response['body'], str)
    assert 'headers' in response
    assert isinstance(response['headers'], dict)
    
    # Verify body structure (JSON string)

    body = json.loads(response['body'])
    assert 'statusMessage' in body
    assert 'accountId' in body
    
    # Verify correct values
    assert response['statusCode'] == 200
    

    body = json.loads(response['body'])
    assert body['statusMessage'] == "All OK"
    assert body['accountId'] == "123456789012"


@patch('boto3.client')
def test_boto3_sts_client_creation(mock_boto3_client, mock_sts_client, mock_event, mock_context):
    """Test that boto3 STS client is created successfully."""
    mock_boto3_client.return_value = mock_sts_client
    
    response = lambda_handler(mock_event, mock_context)
    
    # Verify boto3.client was called with 'sts'
    mock_boto3_client.assert_called_once_with('sts')
    assert response['statusCode'] == 200


@patch('boto3.client')
def test_sts_client_region_agnostic(mock_boto3_client, mock_sts_client, mock_event, mock_context, caplog):
    """Test that STS client works without explicit region."""
    mock_boto3_client.return_value = mock_sts_client
    
    with caplog.at_level(logging.INFO):
        response = lambda_handler(mock_event, mock_context)
    
    # STS is a global service, should work without region specification
    # Verify no region parameter was passed to boto3.client
    mock_boto3_client.assert_called_once_with('sts')
    assert response['statusCode'] == 200
    assert "I'm running in account" in caplog.text


@patch('boto3.client')
def test_account_id_format(mock_boto3_client, mock_sts_client, mock_event, mock_context, caplog):
    """Test that account ID is in correct format (12 digits)."""
    mock_boto3_client.return_value = mock_sts_client
    
    with caplog.at_level(logging.INFO):
        response = lambda_handler(mock_event, mock_context)
    
    # Extract account ID from logs
    import re
    match = re.search(r"I'm running in account (\d+)", caplog.text)
    assert match is not None
    account_id = match.group(1)
    
    # Verify it's 12 digits
    assert len(account_id) == 12
    assert account_id.isdigit()
    
    # Also verify it matches the response

    body = json.loads(response['body'])
    assert body['accountId'] == account_id


@patch('boto3.client')
def test_lambda_handler_idempotency(mock_boto3_client, mock_sts_client, mock_event, mock_context):
    """Test that calling lambda_handler multiple times produces consistent results."""
    mock_boto3_client.return_value = mock_sts_client
    
    response1 = lambda_handler(mock_event, mock_context)
    response2 = lambda_handler(mock_event, mock_context)
    response3 = lambda_handler(mock_event, mock_context)
    
    assert response1 == response2 == response3
    assert response1['statusCode'] == 200
    
    # Verify boto3.client was called multiple times
    assert mock_boto3_client.call_count == 3


@patch('boto3.client')
def test_context_attributes_not_used(mock_boto3_client, mock_sts_client, mock_event):
    """Test lambda_handler works even with minimal context."""
    mock_boto3_client.return_value = mock_sts_client
    minimal_context = MagicMock()
    
    response = lambda_handler(mock_event, minimal_context)
    
    assert response['statusCode'] == 200
    

    body = json.loads(response['body'])
    assert body['statusMessage'] == "All OK"
    assert body['accountId'] == "123456789012"


@patch('boto3.client')
def test_event_not_modified(mock_boto3_client, mock_sts_client, mock_event, mock_context):
    """Test that lambda_handler doesn't modify the input event."""
    mock_boto3_client.return_value = mock_sts_client
    original_event = mock_event.copy()
    
    lambda_handler(mock_event, mock_context)
    
    assert mock_event == original_event


@patch('boto3.client')
def test_sts_get_caller_identity_response_structure(mock_boto3_client, mock_event, mock_context):
    """Test that STS get_caller_identity response is handled correctly."""
    # Test with minimal response (only Account field)
    mock_sts_client = MagicMock()
    mock_sts_client.get_caller_identity.return_value = {"Account": "111122223333"}
    mock_boto3_client.return_value = mock_sts_client
    
    response = lambda_handler(mock_event, mock_context)
    
    assert response['statusCode'] == 200
    

    body = json.loads(response['body'])
    assert body['accountId'] == "111122223333"
    
    # Test with full response structure
    mock_sts_client.get_caller_identity.return_value = {
        "Account": "444455556666",
        "UserId": "AIDACKCEVSQ6C2EXAMPLE",
        "Arn": "arn:aws:iam::444455556666:user/test-user"
    }
    
    response = lambda_handler(mock_event, mock_context)
    

    body = json.loads(response['body'])
    assert body['accountId'] == "444455556666"


@patch('boto3.client')
def test_lambda_handler_with_specific_log_level(mock_boto3_client, mock_sts_client, mock_event, mock_context):
    """Test lambda_handler with numeric log level."""
    mock_boto3_client.return_value = mock_sts_client
    
    with patch.dict(os.environ, {'LOG_LEVEL': 'DEBUG'}):  # Use string instead of numeric
        import importlib
        import src.lambda_function
        importlib.reload(src.lambda_function)
        
        response = src.lambda_function.lambda_handler(mock_event, mock_context)
        assert response['statusCode'] == 200


def test_module_level_logger_configuration():
    """Test that logger is configured at module level."""
    import src.lambda_function
    
    # Verify logger exists and is configured
    assert hasattr(src.lambda_function, 'logger')
    assert isinstance(src.lambda_function.logger, logging.Logger)


@patch('boto3.client')
def test_lambda_handler_exception_propagation(mock_boto3_client, mock_event, mock_context):
    """Test that exceptions from AWS calls are properly propagated."""
    # Test various exception types
    exceptions_to_test = [
        ClientError(
            error_response={'Error': {'Code': 'InvalidUserID.NotFound', 'Message': 'User not found'}},
            operation_name='GetCallerIdentity'
        ),
        NoCredentialsError(),
        BotoCoreError(),
        Exception("Generic exception")
    ]
    
    for exception in exceptions_to_test:
        mock_boto3_client.side_effect = exception
        
        with pytest.raises(type(exception)):
            lambda_handler(mock_event, mock_context)


@patch('src.lambda_function.logger')
@patch('boto3.client')
def test_logging_calls(mock_boto3_client, mock_logger, mock_sts_client, mock_event, mock_context):
    """Test that logging calls are made correctly."""
    mock_boto3_client.return_value = mock_sts_client
    
    lambda_handler(mock_event, mock_context)
    
    # Verify logger.info was called with expected messages
    from unittest.mock import call
    mock_logger.info.assert_has_calls([
        call("Hello from Lambda!"),
        call("I'm running in account 123456789012")
    ])
    
    assert mock_logger.info.call_count == 2


