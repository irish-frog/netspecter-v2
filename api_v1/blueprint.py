import time

from flask import Blueprint, g, jsonify, request

from .auth import audit_api_request, ensure_api_schema, require_api_key
from . import data


api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")


@api_v1.before_request
def api_before_request():
    g.api_started_at = time.perf_counter()
    ensure_api_schema()


@api_v1.after_request
def api_after_request(response):
    started = getattr(g, "api_started_at", None)
    elapsed_ms = (time.perf_counter() - started) * 1000 if started else 0
    response.headers.setdefault("X-NetSpecter-API-Version", "v1")
    audit_api_request(response.status_code, elapsed_ms)
    return response


@api_v1.route("/openapi.json")
@require_api_key()
def openapi():
    return jsonify(data.openapi_spec())


@api_v1.route("/dashboard")
@require_api_key()
def dashboard():
    return jsonify(data.dashboard_summary())


@api_v1.route("/devices")
@require_api_key()
def devices():
    return jsonify(data.devices(limit=_limit(request.args.get("limit"), 500)))


@api_v1.route("/devices/<path:device_id>")
@require_api_key()
def device(device_id):
    item = data.device(device_id)
    if not item:
        return jsonify({"error": "not_found"}), 404
    return jsonify(item)


@api_v1.route("/internet")
@require_api_key()
def internet():
    return jsonify(data.internet_health())


@api_v1.route("/dns")
@require_api_key()
def dns():
    return jsonify(data.dns_analytics())


@api_v1.route("/alerts")
@require_api_key()
def alerts():
    return jsonify(data.alerts(limit=_limit(request.args.get("limit"), 100)))


@api_v1.route("/threats")
@require_api_key()
def threats():
    return jsonify(data.threats())


@api_v1.route("/incidents")
@require_api_key()
def incidents():
    return jsonify(data.incident_timeline(limit=_limit(request.args.get("limit"), 100)))


@api_v1.route("/reports/<period_name>")
@require_api_key()
def reports(period_name):
    if period_name not in {"daily", "weekly", "monthly"}:
        return jsonify({"error": "unknown_report"}), 404
    return jsonify(data.report(period_name))


@api_v1.route("/ai/<summary_name>")
@require_api_key()
def ai(summary_name):
    if summary_name not in {"network-summary", "executive-summary", "security-summary"}:
        return jsonify({"error": "unknown_summary"}), 404
    return jsonify(data.ai_summary(summary_name))


def _limit(value, default):
    try:
        return max(1, min(500, int(value)))
    except Exception:
        return default
