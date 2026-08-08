---
title: "Error handling and core codes"
---

Typed API errors, stable HTTP bodies, redaction, protocol-specific bodies, and the complete core error catalog.

HTTP transports and the direct API share `contract.APIError`. It carries an HTTP status, stable code, public message, response headers, optional protocol wire body, and a server-only wrapped cause.

## Default wire shape

~~~json
{
  "code": "INVALID_EMAIL_OR_PASSWORD",
  "message": "Invalid email or password"
}
~~~

Unknown Go errors are redacted to status 500, code `INTERNAL_SERVER_ERROR`, and message `Internal Server Error`. The wrapped cause remains available to server logs and `errors.Is`/`errors.As` but is never serialized.

~~~go
result, err := auth.API().GetSession(ctx, input)
if err != nil {
    if apiErr, ok := contract.AsAPIError(err); ok {
        log.Printf("auth failure status=%d code=%s cause=%v",
            apiErr.Status, apiErr.Code, apiErr.Cause)
        return apiErr
    }
    return err
}
~~~

Do not return `Cause` to callers. It may contain database, cryptographic, provider, or network details.

## Protocol-specific errors

`APIError.WireBody` lets protocol endpoints retain typed status/code/message while emitting their standard JSON shape, such as OAuth 2.0 `{"error","error_description"}`. SAML exposes stable `saml.Error`/`saml.APIError` codes. SCIM and OAuth plugins use protocol-specific bodies where their specifications require them.

Plugin packages define additional error constants near their handlers and list relevant failures on their individual documentation pages. The table below is the complete root/core catalog.

## Core error catalog

The endpoint determines the HTTP status for a code; the same semantic code can be used in more than one route context.

| Code | Default public message |
| --- | --- |
| `ACCOUNT_NOT_FOUND` | Account not found |
| `ASYNC_VALIDATION_NOT_SUPPORTED` | Async validation is not supported |
| `BODY_MUST_BE_AN_OBJECT` | Body must be an object |
| `CALLBACK_URL_REQUIRED` | callbackURL is required |
| `CHANGE_EMAIL_DISABLED` | Change email is disabled |
| `CREDENTIAL_ACCOUNT_NOT_FOUND` | Credential account not found |
| `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED` | Cross-site navigation login blocked. This request appears to be a CSRF attack. |
| `EMAIL_ALREADY_VERIFIED` | Email is already verified |
| `EMAIL_CAN_NOT_BE_UPDATED` | Email can not be updated |
| `EMAIL_MISMATCH` | Email mismatch |
| `EMAIL_NOT_VERIFIED` | Email not verified |
| `FAILED_TO_CREATE_SESSION` | Failed to create session |
| `FAILED_TO_CREATE_USER` | Failed to create user |
| `FAILED_TO_CREATE_VERIFICATION` | Unable to create verification |
| `FAILED_TO_GET_SESSION` | Failed to get session |
| `FAILED_TO_GET_USER_INFO` | Failed to get user info |
| `FAILED_TO_UNLINK_LAST_ACCOUNT` | You can't unlink your last account |
| `FAILED_TO_UPDATE_USER` | Failed to update user |
| `FIELD_NOT_ALLOWED` | Field not allowed to be set |
| `ID_TOKEN_NOT_SUPPORTED` | id_token not supported |
| `INVALID_CALLBACK_URL` | Invalid callbackURL |
| `INVALID_EMAIL` | Invalid email |
| `INVALID_EMAIL_OR_PASSWORD` | Invalid email or password |
| `INVALID_ERROR_CALLBACK_URL` | Invalid errorCallbackURL |
| `INVALID_NEW_USER_CALLBACK_URL` | Invalid newUserCallbackURL |
| `INVALID_ORIGIN` | Invalid origin |
| `INVALID_PASSWORD` | Invalid password |
| `INVALID_REDIRECT_URL` | Invalid redirectURL |
| `INVALID_TOKEN` | Invalid token |
| `INVALID_USER` | Invalid user |
| `LINKED_ACCOUNT_ALREADY_EXISTS` | Linked account already exists |
| `METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED` | POST method requires deferSessionRefresh to be enabled in session config |
| `MISSING_FIELD` | Field is required |
| `MISSING_OR_NULL_ORIGIN` | Missing or null Origin |
| `PASSWORD_ALREADY_SET` | User already has a password set |
| `PASSWORD_TOO_LONG` | Password too long |
| `PASSWORD_TOO_SHORT` | Password too short |
| `PROVIDER_NOT_FOUND` | Provider not found |
| `SESSION_EXPIRED` | Session expired. Re-authenticate to perform this action. |
| `SESSION_NOT_FRESH` | Session is not fresh |
| `SOCIAL_ACCOUNT_ALREADY_LINKED` | Social account already linked |
| `TOKEN_EXPIRED` | Token expired |
| `USER_ALREADY_EXISTS` | User already exists. |
| `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` | User already exists. Use another email. |
| `USER_ALREADY_HAS_PASSWORD` | User already has a password. Provide that to delete the account. |
| `USER_EMAIL_NOT_FOUND` | User email not found |
| `USER_NOT_FOUND` | User not found |
| `VALIDATION_ERROR` | Validation Error |
| `VERIFICATION_EMAIL_NOT_ENABLED` | Verification email isn't enabled |


## Custom API errors

~~~go
err := contract.NewAPIError(
    contract.StatusForbidden,
    "ACCOUNT_SUSPENDED",
    "This account is suspended",
).WithHeaders(contract.NewHeaders(
    contract.HeaderField{Name: "Retry-After", Value: "3600"},
)).WithCause(internalCause)
~~~

`WithCause`, `WithHeaders`, and `WithWireBody` return independent copies. `contract.ResponseFromError` performs the final stable conversion to a transport-neutral response.
