# Signing in to Google Workspace with mamori (OIDC)

Google Workspace can use a third-party identity provider through a custom OIDC profile, so people sign in to Gmail, Drive and the rest with their mamori sign-in, including passkeys and two-step verification. Combined with the Google Workspace connector (`docs/v0.3.md`), disabling someone in mamori both suspends their Google account and stops them signing in.

What Google documents for a custom OIDC profile ([Setting up SSO](https://knowledge.workspace.google.com/admin/apps/setting-up-sso)):

- It must use the authorization code flow.
- The `email` claim must match the user's primary email address in Google.
- The profile is assigned to organizational units or groups, so it can be tried on a few people first.

## 1. Register Google as an app in mamori

Add a client to `mamori.config.json`. The redirect URI comes from Google in step 2, so leave a placeholder for now.

```json
{
  "client_id": "google-workspace",
  "client_secret": "a-long-random-value",
  "client_name": "Google Workspace",
  "redirect_uris": ["REPLACE-WITH-THE-REDIRECT-URI-FROM-GOOGLE"]
}
```

mamori puts `email` in the ID token for the `email` scope, which is what Google matches on.

## 2. Add the OIDC profile in Google

In the Admin console: Menu → Security → Authentication → SSO with third party IdP → Third-party SSO profiles → Add OIDC profile.

| Field | Value |
|---|---|
| Name | mamori |
| Client ID | `google-workspace` |
| Issuer URL | mamori's issuer, e.g. `https://id.example.co.jp` |
| Client secret | the `client_secret` from step 1 |

Save, then copy the Redirect URI shown on the profile's page into `redirect_uris` in step 1 and restart mamori.

## 3. Try it on a test group

Assign the profile to a group that has only a test user, and sign in to Google as that user in a private window. You should land on mamori's sign-in page, and after signing in, in Gmail.

## Not confirmed yet

These depend on Google's side and have to be checked on a real Workspace before rolling out:

- **PKCE.** mamori requires PKCE from every app by default. If Google does not send it, the sign-in stops with an `invalid_request` error that mentions PKCE. Then add `"pkce_optional": true` to the client from step 1. This is allowed only for clients with a secret; public clients always need PKCE.
- **Super admins.** Whether Google sends super administrators to the third-party IdP, or keeps them on Google passwords, is not stated on the page above. Keep at least one super admin who can sign in with a Google password and two-step verification, so a problem with mamori cannot lock everyone out of the Admin console.
- **Signing out.** Signing out of Google does not sign the person out of mamori. Signing out of mamori's account page ends the mamori session, so the next Google sign-in asks again.
