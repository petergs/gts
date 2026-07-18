# graph-token-tools PLAN-v1.md

> **Note:** this is a historical design record. The package was later renamed from
> `graph_token_tools` / `gtt` to `gts` (Graph Token Store); names below are unchanged.

This is an empty python project that I'd like to use to consolidate two tools I've previously written: `mgc-enum` and `mgc-token-tools`. 
Both repositories have been `git cloned` into this directory. Now that the Microsoft Graph CLI is deprecated and no longer under development, 
I want to reimplement some of the functionality of the original `mgc` tool and decouple some of the functionality in my wrapper tools (`mgc-enum` and `mgc-token-tools`) from `mgc`. 
The goal of this tool is to identify risky users and applications in my Azure/Entra environment.


## Features

### Entrypoints
The project should have a single cli entrpoint called `gtt` with subcommands. 

### Subcommands
- `status` Status command to identify the current signed-in user, application in-use, and scopes provided by that application
- `aliases` Alises for useful first-party Microsoft clients
- `dump` Print an access or refresh token from the OS keyring for a specific client (via the client id)
- `refresh-to` FOCI client login 
- `insert` Store a correctly-formatted access or refresh token sourced outside mgc in the mgc token cache
- `switch` Switch between applications with valid access tokens
- `enum` Use the same sub-subcommands as the `mgc-enum` project
 
### Keychain and Token Storage
The project should implement a generic token storage interface that is capable of supporting a variety of token storage backends. 
At first, I'd like to support `gnome-keyring`, the macos keychain, and 1password as token storage backends. 

The `mgc-token-tools` repository has some ability to interface with OS keychains. This is implemented in 
`mgc-token-tools/mtt/cache.py`.The current implementation used the format required by `mgc` (described in `mgc-token-tools/INFO.md`). 
Since this project is decoupled from `mgc`, we are now free to format the token storage in whatever way we want.

Overall, I think the MSAL schema used by `mgc` has a number of issues:
1. Complexity. For example, the `AccessToken` object has a subkey with the format `<user_id>.<tenant_id>-login.windows.net-accesstoken-1950a258-227b-4e31-a9cf-717495945fc2-<tenant_id>-email openid profile https://graph.microsoft.com/auditlog.read.all https://graph.microsoft.com/directory.accessasuser.all https://graph.microsoft.com/.default"` 
assuming a token for the Microsoft Azure PowerShell (client_id=1950a258-227b-4e31-a9cf-717495945fc2). 
2. No support for multiple users. The interface provides single, top-level keys for `AccessToken`, `RefreshToken`, `IdToken`, and `Account` that would get overwritten 
when signing into the CLI as a different user or with a different client id. Our format should support multiple users.
3. It doesn't support storing Service Principal tokens. Our format should support both users and service principals. 

Like with `mtt`, the token cache should be serializable as a single json blob. With the above improvements in mind, 
we could use something like:
```
{
    "users" : {
        "first.last@contoso.com" : {
            "applications" : {
                "9AB397F0-5D53-4AB4-8C1D-03BCCFF90FDD" : {
                    "access_token" : ...,
                    "refresh_token" : ...,
                    "app_display_name" : ...,
                    "scopes" : ...,
                    ...
                }
            },
            "tenant_id" : ...,
            "tenant_domain" : ...,
            ...
        }
    },
    "service_principals" : {
        "51B17D63-26DB-471B-B8E8-3C94F5320B9B" : {
            "access_token" : ...,
            "refresh_token" : ...,
            "service_principal_display_name : ...,
            "tenant_id" : ...,
        }
    }
}
```

This exact format is not a hard requirement but is provided as guidance.


### Authencation Flows
The project should support the client credentials flow, device code flow, and interactive browser login. 

## Dependencies
When implementing `mgc-enum` and `mgc-token-tools`, I tried to avoid any third party dependencies. For `gtt`, I'm happy to use the following
packages. Please confirm before adding additional dependencies. 

- https://github.com/fastapi/typer for the CLI interface
- https://github.com/jaraco/keyring for interfacing with gnome-keyring and the macos keychain
- https://github.com/1Password/onepassword-sdk-python for interfacing with 1password 
- https://github.com/jpadilla/pyjwt for parsing JWTs
- https://github.com/psf/requests for any HTTP requests 

Note, while it *might* simplify things to use `msgraph-sdk-python`, we'd then be stuck using the MSAL cache format. Since we're only implementing code 
against a subset of the Graph API, for now, it's better to use requests. If this library is absolutely required to implement any of the required 
authentication flows (eg. Interactive Browser login), we can consider adding it. 

## Implementation Plan

1. Read the `mgc-enum` and `mgc-token-tools` projects to understand their features.
2. Implement the token cache interface and a macos keyring backend.
3. Implement the `mgc-token-tools` subcommands
4. Implement the `mgc-enum` subcommands


