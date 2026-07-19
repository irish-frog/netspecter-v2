import datetime as dt
import hashlib
import hmac
import json
import secrets
import time
from urllib import error, request


NETLIC_PRIVACY = (
    "NetLic records licensing and support information such as appliance name, version, "
    "last connection, public IP address and optional aggregated usage counts. It does not "
    "collect browsing history, DNS history, packet captures, usernames or detailed network activity."
)


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def iso_now():
    return utc_now().isoformat().replace("+00:00", "Z")


def canonical_json(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def signing_secret(licence_key):
    return str(licence_key or "").strip().upper()


def verify_signature(payload, secret):
    signature = str(payload.get("signature", ""))
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    expected = hmac.new(signing_secret(secret).encode("utf-8"), canonical_json(unsigned).encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def installation_id(config):
    value = str(config.get("netlic_installation_id") or "").strip()
    if value:
        return value
    return secrets.token_urlsafe(32)


def post_json(base_url, path, payload, timeout=15):
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        str(base_url).rstrip("/") + path,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def activate(config, company_name, administrator_name, administrator_email, appliance_name, licence_key, product_version):
    requested_key = str(licence_key or "").strip() or str(config.get("netlic_free_registration_key") or "FREE")
    install_id = installation_id(config)
    payload = {
        "licence_key": requested_key,
        "installation_id": install_id,
        "company_name": company_name,
        "administrator_name": administrator_name,
        "administrator_email": administrator_email,
        "appliance_name": appliance_name,
        "product_version": product_version,
        "timestamp": iso_now(),
    }
    response = post_json(config.get("netlic_url"), "/api/v1/activate", payload)
    if not verify_signature(response, requested_key) or not response.get("valid"):
        return False, "NetLic returned an unsigned or invalid activation response.", None
    issued_key = str(response.get("issued_licence_key") or requested_key).strip()
    return True, "", {
        "netlic_setup_complete": True,
        "netlic_installation_id": install_id,
        "netlic_licence_key": issued_key,
        "netlic_signing_secret": signing_secret(issued_key),
        "netlic_appliance_name": appliance_name,
        "netlic_last_success_at": iso_now(),
        "netlic_last_response": response,
        "netlic_next_check_after": int(time.time()) + int(response.get("next_check_after_hours", 24)) * 3600,
    }


def check_in(config, product_version, metrics=None):
    licence_key = str(config.get("netlic_licence_key") or "").strip()
    signing = str(config.get("netlic_signing_secret") or licence_key).strip()
    if not licence_key:
        return False, "NetLic licence key is not configured.", None
    payload = {
        "licence_key": licence_key,
        "installation_id": str(config.get("netlic_installation_id") or "").strip(),
        "appliance_name": str(config.get("netlic_appliance_name") or config.get("app_name") or "NetSpecter"),
        "product_version": product_version,
        "timestamp": iso_now(),
        "health_status": "ok",
    }
    payload.update(metrics or {})
    response = post_json(config.get("netlic_url"), "/api/v1/check-in", payload)
    if not verify_signature(response, signing):
        return False, "NetLic check-in signature could not be verified.", None
    return bool(response.get("valid")), "", {
        "netlic_last_success_at": iso_now(),
        "netlic_last_response": response,
        "netlic_next_check_after": int(time.time()) + int(response.get("next_check_after_hours", 24)) * 3600,
    }


def grace_state(config):
    last = str(config.get("netlic_last_success_at") or "").strip()
    if not last:
        return "unlicensed"
    try:
        last_dt = dt.datetime.fromisoformat(last.replace("Z", "+00:00"))
    except ValueError:
        return "unlicensed"
    grace_days = int(config.get("netlic_offline_grace_period_days") or 30)
    if utc_now() - last_dt <= dt.timedelta(days=grace_days):
        return "valid_or_grace"
    return "verification_required"
