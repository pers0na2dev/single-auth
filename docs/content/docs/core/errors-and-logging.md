---
title: "Errors and logging"
---

Typed API errors, wire redaction, the core error catalog, error pages, and logger thresholds.

Authentication failures cross the engine boundary as `*contract.APIError`. The server retains a cause for diagnostics while the wire response remains stable.

```go
result, err := auth.API().VerifyPassword(ctx, input)
if err != nil {
    apiErr, ok := contract.AsAPIError(err)
    if !ok {
        return fmt.Errorf("verify password: %w", err)
    }
    log.Printf("auth failure status=%d code=%s cause=%v", apiErr.Status, apiErr.Code, apiErr.Cause)
    return apiErr
}
_ = result
```

## `contract.APIError`

| Field | Meaning |
| --- | --- |
| `Status` | HTTP-compatible numeric status. Zero passed to `NewAPIError` becomes 500. |
| `Code` | Stable machine-readable identifier. |
| `Message` | Public message. |
| `Headers` | Ordered multi-value response headers. |
| `WireBody` | Optional protocol-specific JSON body overriding `{code,message}`. |
| `Cause` | Server-only wrapped error; never serialized. |

`WithCause`, `WithHeaders`, and `WithWireBody` return independent copies. `contract.AsAPIError` unwraps through `%w` chains.

`contract.ResponseFromError` serializes typed errors. An unknown error is always redacted to status 500:

```json
{
  "code": "INTERNAL_SERVER_ERROR",
  "message": "Internal Server Error"
}
```

Do not serialize `err.Error()` from an unknown error in application middleware. Use the already safe `contract.Response` returned by `Dispatch` or the transport adapter.

## Core error catalog

`singleauth.BaseErrorMessages` contains the Better Auth 1.6.26 base catalog and `ErrorMessage(code)` performs a lookup. The stable constants are:

| Constant | Code | Default message |
| --- | --- | --- |
| `ErrorUserNotFound` | `USER_NOT_FOUND` | User not found |
| `ErrorFailedToCreateUser` | `FAILED_TO_CREATE_USER` | Failed to create user |
| `ErrorFailedToCreateSession` | `FAILED_TO_CREATE_SESSION` | Failed to create session |
| `ErrorFailedToUpdateUser` | `FAILED_TO_UPDATE_USER` | Failed to update user |
| `ErrorFailedToGetSession` | `FAILED_TO_GET_SESSION` | Failed to get session |
| `ErrorInvalidPassword` | `INVALID_PASSWORD` | Invalid password |
| `ErrorInvalidEmail` | `INVALID_EMAIL` | Invalid email |
| `ErrorInvalidEmailOrPassword` | `INVALID_EMAIL_OR_PASSWORD` | Invalid email or password |
| `ErrorInvalidUser` | `INVALID_USER` | Invalid user |
| `ErrorSocialAccountAlreadyLinked` | `SOCIAL_ACCOUNT_ALREADY_LINKED` | Social account already linked |
| `ErrorProviderNotFound` | `PROVIDER_NOT_FOUND` | Provider not found |
| `ErrorInvalidToken` | `INVALID_TOKEN` | Invalid token |
| `ErrorTokenExpired` | `TOKEN_EXPIRED` | Token expired |
| `ErrorIDTokenNotSupported` | `ID_TOKEN_NOT_SUPPORTED` | id_token not supported |
| `ErrorFailedToGetUserInfo` | `FAILED_TO_GET_USER_INFO` | Failed to get user info |
| `ErrorUserEmailNotFound` | `USER_EMAIL_NOT_FOUND` | User email not found |
| `ErrorEmailNotVerified` | `EMAIL_NOT_VERIFIED` | Email not verified |
| `ErrorPasswordTooShort` | `PASSWORD_TOO_SHORT` | Password too short |
| `ErrorPasswordTooLong` | `PASSWORD_TOO_LONG` | Password too long |
| `ErrorUserAlreadyExists` | `USER_ALREADY_EXISTS` | User already exists. |
| `ErrorUserAlreadyExistsAnotherEmail` | `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` | User already exists. Use another email. |
| `ErrorEmailCannotBeUpdated` | `EMAIL_CAN_NOT_BE_UPDATED` | Email can not be updated |
| `ErrorChangeEmailDisabled` | `CHANGE_EMAIL_DISABLED` | Change email is disabled |
| `ErrorCredentialAccountNotFound` | `CREDENTIAL_ACCOUNT_NOT_FOUND` | Credential account not found |
| `ErrorSessionExpired` | `SESSION_EXPIRED` | Session expired. Re-authenticate to perform this action. |
| `ErrorFailedToUnlinkLastAccount` | `FAILED_TO_UNLINK_LAST_ACCOUNT` | You can't unlink your last account |
| `ErrorAccountNotFound` | `ACCOUNT_NOT_FOUND` | Account not found |
| `ErrorUserAlreadyHasPassword` | `USER_ALREADY_HAS_PASSWORD` | User already has a password. Provide that to delete the account. |
| `ErrorCrossSiteNavigationLoginBlocked` | `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED` | Cross-site navigation login blocked. This request appears to be a CSRF attack. |
| `ErrorVerificationEmailNotEnabled` | `VERIFICATION_EMAIL_NOT_ENABLED` | Verification email isn't enabled |
| `ErrorEmailAlreadyVerified` | `EMAIL_ALREADY_VERIFIED` | Email is already verified |
| `ErrorEmailMismatch` | `EMAIL_MISMATCH` | Email mismatch |
| `ErrorSessionNotFresh` | `SESSION_NOT_FRESH` | Session is not fresh |
| `ErrorLinkedAccountAlreadyExists` | `LINKED_ACCOUNT_ALREADY_EXISTS` | Linked account already exists |
| `ErrorInvalidOrigin` | `INVALID_ORIGIN` | Invalid origin |
| `ErrorInvalidCallbackURL` | `INVALID_CALLBACK_URL` | Invalid callbackURL |
| `ErrorInvalidRedirectURL` | `INVALID_REDIRECT_URL` | Invalid redirectURL |
| `ErrorInvalidErrorCallbackURL` | `INVALID_ERROR_CALLBACK_URL` | Invalid errorCallbackURL |
| `ErrorInvalidNewUserCallbackURL` | `INVALID_NEW_USER_CALLBACK_URL` | Invalid newUserCallbackURL |
| `ErrorMissingOrNullOrigin` | `MISSING_OR_NULL_ORIGIN` | Missing or null Origin |
| `ErrorCallbackURLRequired` | `CALLBACK_URL_REQUIRED` | callbackURL is required |
| `ErrorFailedToCreateVerification` | `FAILED_TO_CREATE_VERIFICATION` | Unable to create verification |
| `ErrorFieldNotAllowed` | `FIELD_NOT_ALLOWED` | Field not allowed to be set |
| `ErrorAsyncValidationNotSupported` | `ASYNC_VALIDATION_NOT_SUPPORTED` | Async validation is not supported |
| `ErrorValidation` | `VALIDATION_ERROR` | Validation Error |
| `ErrorMissingField` | `MISSING_FIELD` | Field is required |
| `ErrorMethodNeedsDeferredSession` | `METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED` | POST method requires deferSessionRefresh to be enabled in session config |
| `ErrorBodyMustBeObject` | `BODY_MUST_BE_AN_OBJECT` | Body must be an object |
| `ErrorPasswordAlreadySet` | `PASSWORD_ALREADY_SET` | User already has a password set |

Endpoints also use route- or protocol-specific codes such as `UNAUTHORIZED`, `NOT_FOUND`, `BAD_REQUEST`, provider token errors, and plugin codes. `auth.ErrorCodes()` returns an independent merged map of plugin `engine.ErrorDefinition` values; the base catalog remains available through the constants above.

## Error route

`GET /error` is the browser-facing error page. It reads `error` and optional `error_description`, sanitizes an unsafe code to `UNKNOWN`, and then:

- redirects to `OnAPIError.ErrorURL`, preserving both query fields, when configured;
- in explicit production mode, redirects to `/?error=...` unless `CustomizeDefaultErrorPage` is true;
- otherwise renders the built-in escaped HTML page using `AppName`.

`OnAPIError` configures this route; it is not a general error callback. Observe dispatcher errors through transport error observers, direct-call return values, hooks, and logging.

## Logger defaults

The logger's ordered levels are:

```text
debug < info < success < warn < error
```

The default threshold is `warn`. `success` is an emitted internal level but cannot be configured as a threshold. Invalid configured levels fail construction.

```go
Logger: logger.Options{
    Level: logger.Info,
    Log: func(level logger.Level, message string, args ...any) {
        slog.InfoContext(
            context.Background(),
            message,
            "authLevel", string(level),
            "args", fmt.Sprint(args...),
        )
    },
},
```

With the built-in writer:

- debug, info, and success go to stdout;
- warn and error go to stderr;
- output includes an UTC millisecond timestamp, uppercase level, and `[Better Auth]` label;
- color is detected for a terminal unless `DisableColors` explicitly overrides it.

`logger.Options.Disabled` suppresses all output. `Output`, `ErrorOutput`, and `Now` are primarily useful for hosts and deterministic tests.

A custom `Log` callback receives the unformatted message and original variadic arguments. Internal `success` events are reported to the callback as `info` because the public callback contract has no success level. The callback and custom writers must be concurrency-safe.

`logger.ValidLevel` validates a level and `logger.ShouldPublish` exposes threshold comparison. `logger.New` returns configuration errors; `logger.MustNew` panics.

## Transport error observers

Transport adapters return/write the stable response first and can call a configured error observer with the original error. Observers are for diagnostics and cannot replace the response. Avoid logging credential bodies, session cookies, authorization headers, OAuth tokens, verification tokens, or full provider responses.
