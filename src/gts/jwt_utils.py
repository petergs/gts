"""JWT helpers built on pyjwt. Access/ID tokens from Entra are JWTs; refresh tokens
are opaque and cannot be decoded here."""

import time
from datetime import datetime, timezone

import jwt


def decode_claims(token: str) -> dict:
    """Decode a JWT's claims without verifying the signature.

    We only ever read claims from tokens we already hold; we never trust them for
    authorization decisions, so signature verification is intentionally skipped.
    """
    return jwt.decode(
        token,
        options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
    )


def get_scopes(access_token: str) -> list[str]:
    """Return the space-delimited scopes (scp) from an access token, or []."""
    scp = decode_claims(access_token).get("scp", "")
    return scp.split(" ") if scp else []


def get_expiry(token: str) -> int | None:
    """Return the exp claim (epoch seconds) as an int, or None."""
    exp = decode_claims(token).get("exp")
    return int(exp) if exp is not None else None


def _humanize_delta(seconds: int) -> str:
    """Render a signed second delta as e.g. 'in 1h 5m' or 'expired 5m ago'."""
    past = seconds < 0
    remaining = abs(seconds)
    days, remaining = divmod(remaining, 86400)
    hours, remaining = divmod(remaining, 3600)
    minutes, secs = divmod(remaining, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{secs}s")
    text = " ".join(parts[:2])  # keep it concise (two largest units)
    return f"expired {text} ago" if past else text


def format_utc(epoch: int | None) -> str | None:
    """Render an epoch as an absolute UTC timestamp, or None if unknown."""
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def humanize_expiry(epoch: int | None) -> dict:
    """Describe an epoch expiry in human-readable form.

    Returns a dict with the absolute UTC time, a relative descriptor, and whether
    the token has expired. `epoch` of None/0 (unknown) yields a placeholder.
    """
    if not epoch:
        return {"expires_at": None, "expires_in": "unknown", "expired": None}
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    delta = int(epoch - time.time())
    return {
        "expires_at": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "expires_in": _humanize_delta(delta),
        "expired": delta <= 0,
    }
