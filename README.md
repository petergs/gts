# gts (graph-token-store)

> `gts` is a CLI for authenticating to Microsoft Graph and managing the resulting tokens

## Overview

The cli (`gts`) provides the following features (and more!):
- Status command to identify the current signed-in user, application in-use, and scopes provided by that application (`status`)
- Alises for useful first-party Microsoft clients (`aliases`)
- Print an access or refresh token from the OS keyring for a specific client (via the client id) to pass to another tool (AAD-Internals, RoadTools etc) (`dump`)
- [FOCI client](https://github.com/secureworks/family-of-client-ids-research/tree/main) login similar to `Invoke-RefreshTo<X>` commands provided by [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) (`refresh-to`)
- Store and use an access or refresh token sourced outside `gts`(`insert`)
- Switch between applications with valid access tokens (`switch`)
- Enumerate some basic tenant information (`enum`)

## Install

```bash
uv tool install graph-token-store
```

## Quickstart 

```bash
$> gts

 Usage: gts [OPTIONS] COMMAND [ARGS]...

 A cli for managing Graph API tokens

╭─ Options ────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────╮
│ login       Authenticate and store the resulting token(s), setting the active identity.  │
│ logout      Remove the active identity (or all) from the cache and clear active state.   │
│ status      Show the active identity, client, tenant, and scopes.                        │
│ switch      Switch the active identity. With no client id, pick from an interactive menu.│
│ aliases     List first-party client aliases.                                             │
│ list        List all cached user client applications.                                    │
│ list-sps    List all cached service principals.                                          │
│ dump        Print a stored access or refresh token secret.                               │
│ refresh-to  Use the active users cached refresh token to log in as another FOCI client.  │
│ insert      Insert an externally sourced token into the cache.                           │
│ enum        Enumerate Entra directory objects.                                           │
│ config      View and edit non-secret settings (~/.config/gts/settings.json).             │
│ clients     Search and reference first-party / FOCI clients.                             │
╰──────────────────────────────────────────────────────────────────────────────────────────╯

$> gts login -c azpowershell
$> gts enum current-user

```

## Storage backends

Tokens are stored through a pluggable `StorageBackend`, selected by the `storage_backend`
setting (`gts config set storage_backend …`, or the `GTS_STORAGE_BACKEND` env var):

| Value | Backend |
| --- | --- |
| `keyring` (default) | OS keyring — macOS Keychain / gnome-keyring, via the `keyring` library. |
| `onepassword` | 1Password via the **`op` CLI**. Authorization is cached per terminal session, so you approve **once per terminal**, not per command. |


## LLM Disclosure
This repository was generated via Claude Code using Opus 4.8 with minimal human review. Initial plans are stored in the [docs/plans](./docs/plans) 
folder (v1 drafted by me, v2 iterated upon via Claude Code). In it's current state, the code is mostly write-only (by agents)...
