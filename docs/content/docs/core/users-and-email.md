---
title: "Users and email"
---

User profile updates, verification, email changes, and account deletion.

Core user records contain `id`, `name`, `email`, `emailVerified`, optional `image`, `createdAt`, and `updatedAt`. The final schema may add fields through `Options.Schema` and plugins. Only fields marked as input can be supplied by public update and sign-up routes.

## Updating a user

`POST /update-user` requires a valid session. It accepts `name`, `image`, and configured user input fields.

```json
{
  "name": "Ada Byron",
  "image": null,
  "locale": "en-GB"
}
```

An effective update must contain at least one allowed field. Email is deliberately rejected with `EMAIL_CAN_NOT_BE_UPDATED`; use the change-email flow. After persistence, secondary session payloads are refreshed and current session cookies are reissued so cached user data reflects the update.

`model.Value` preserves whether direct API fields are absent, explicitly null, or present:

```go
result, err := auth.API().UpdateUser(ctx, singleauth.UpdateUserInput{
    Name:  model.Present("Ada Byron"),
    Image: model.Null[string](),
    Headers: sessionHeaders,
})
```

## Email verification configuration

```go
EmailVerification: singleauth.EmailVerificationOptions{
    SendVerificationEmail: func(ctx context.Context, message singleauth.EmailVerificationMessage) error {
        return mailer.SendVerification(ctx, message.User.Email, message.URL)
    },
    SendOnSignUp:                boolPtr(true),
    SendOnSignIn:                true,
    AutoSignInAfterVerification: true,
    ExpiresIn:                  time.Hour,
    BeforeEmailVerification: func(ctx context.Context, user model.User) error {
        return audit.BeforeVerification(ctx, user.ID)
    },
    AfterEmailVerification: func(ctx context.Context, user model.User) error {
        return audit.AfterVerification(ctx, user.ID)
    },
},
```

The default token lifetime is one hour. No sender is installed by default. `SendOnSignUp` omitted follows `EmailAndPassword.RequireEmailVerification`; `SendOnSignIn` and auto sign-in are false by default.

Verification messages contain the current `model.User`, the complete URL, and the raw signed token. The token is a JWT containing a lowercased email and, for email changes, optional `updateTo` and `requestType` claims.

## Sending verification email

`POST /send-verification-email` accepts `email` and optional `callbackURL`. It allows an optional session:

- with a session, the supplied email must match the current user and must still be unverified;
- without a session, unknown users and already verified users follow a dummy token path and return the same `{status:true}` result;
- the unauthenticated path takes at least 500 milliseconds unless the request context is canceled, reducing account-enumeration timing differences.

A missing sender returns `VERIFICATION_EMAIL_NOT_ENABLED`. Do not wrap this endpoint with logic that reveals whether the address exists or is already verified.

## Verifying email

`GET /verify-email?token=...&callbackURL=...` validates redirect origin, signature, expiry, claim shape, and user existence. It then:

1. invokes `BeforeEmailVerification`;
2. sets `emailVerified=true`;
3. refreshes secondary cached user data;
4. invokes `AfterEmailVerification`;
5. optionally creates or refreshes a session when `AutoSignInAfterVerification` is enabled;
6. redirects to `callbackURL`, or returns `{status:true,user:null}`.

If the user is already verified, the route is idempotent: it redirects or returns success without changing the user. Invalid and expired tokens return `INVALID_TOKEN` or `TOKEN_EXPIRED`; when a callback is present the code is appended as its `error` query parameter.

Callback URLs must be a trusted absolute origin or a safe relative path. A relative path must begin with exactly one `/`, cannot contain a backslash or encoded slash/backslash, and is restricted to the supported safe character set.

## Changing email

Email change is disabled by default:

```go
User: singleauth.UserOptions{
    ChangeEmail: singleauth.ChangeEmailOptions{
        Enabled: true,
        SendChangeEmailConfirmation: func(
            ctx context.Context,
            message singleauth.ChangeEmailConfirmationMessage,
        ) error {
            return mailer.SendOldAddressConfirmation(
                ctx,
                message.User.Email,
                message.NewEmail,
                message.URL,
            )
        },
    },
},
```

`POST /change-email` requires an authoritative session and accepts `newEmail` plus optional `callbackURL`. The address is validated and lowercased. Supplying the current address is rejected.

The flow depends on configuration and current verification state:

- If the current email is unverified and `UpdateEmailWithoutVerification` is true, the email is updated immediately. If a verification sender exists, a verification message for the new address is also sent.
- If the current email is verified and both the verification sender and `SendChangeEmailConfirmation` exist, the old address receives a confirmation token. Consuming it sends a second verification token to the new address. The database email changes only after the second token is consumed.
- Otherwise, a verification token is sent to the new address and consumption updates the email.

When no permitted flow has a verification sender, the route returns `Verification email isn't enabled`. An already used email returns the same `{status:true}` shape after dummy token work, so callers cannot enumerate accounts.

Successful email changes refresh secondary user payloads and reissue session cookies. A verification callback may create a session when the token is valid but no session is present; if a session is present for a different user it returns `INVALID_USER`.

## Deleting a user

Deletion is also disabled by default. Disabled HTTP routes return 404.

```go
User: singleauth.UserOptions{
    DeleteUser: singleauth.DeleteUserOptions{
        Enabled:              true,
        DeleteTokenExpiresIn: 24 * time.Hour,
        SendDeleteAccountVerification: func(
            ctx context.Context,
            message singleauth.DeleteAccountMessage,
        ) error {
            return mailer.SendDeletionConfirmation(ctx, message.User.Email, message.URL)
        },
        BeforeDelete: func(ctx context.Context, user model.User) error {
            return audit.BeforeUserDeletion(ctx, user.ID)
        },
        AfterDelete: func(ctx context.Context, user model.User) error {
            return audit.AfterUserDeletion(ctx, user.ID)
        },
    },
},
```

`POST /delete-user` requires an authoritative session. It accepts optional `password`, `token`, and `callbackURL`:

- a supplied password must match the credential account;
- a supplied deletion token is atomically consumed and must belong to the current user;
- when a verification sender is configured, a 32-character token is stored under `delete-account-<token>` and the response is `{success:true,message:"Verification email sent"}`;
- without password or verification, the session must still be fresh unless `FreshAge` is zero.

`GET /delete-user/callback` also requires the current authoritative session, consumes the token, and optionally redirects. The token default lifetime is 24 hours.

Actual deletion runs `BeforeDelete`, removes all authoritative and database sessions, deletes every account, deletes the user, expires browser session cookies, then runs `AfterDelete`. Errors from either callback are returned. The user record passed to `AfterDelete` is the pre-deletion snapshot.

Deletion spans several storage operations and the route does not automatically wrap them in one transaction. A trusted direct workflow can call it inside `RunInTransaction` and pass that transaction context to the direct API when all records must commit or roll back together. Use an outbox for external cleanup. `AfterDelete` running successfully does not automatically remove data from unrelated external systems.

## Direct server methods

The direct API exposes the same production handlers:

- `UpdateUser`
- `SendVerificationEmail`
- `VerifyEmail`
- `ChangeEmail`
- `DeleteUser`
- `DeleteUserCallback`

Supply session cookies in `contract.Headers` for authenticated operations and propagate returned `Set-Cookie` values. Direct calls still execute endpoint hooks and database lifecycle logic, but they bypass HTTP-only origin/CSRF and rate-limit middleware; only call them from trusted server code with equivalent authorization and abuse controls.
