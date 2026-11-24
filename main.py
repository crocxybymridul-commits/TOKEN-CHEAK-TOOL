import os
import re
import json
import time
import socket
import asyncio
import logging
import platform
from collections import deque
from datetime import datetime, timezone
from io import BytesIO

import httpx
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ChatType
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, ContextTypes, filters
)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_USER_ID = os.getenv("ADMIN_USER_ID", "").strip()
DEV_USERNAME = os.getenv("DEV_USERNAME", "@Developer").strip()
APP_NAME = os.getenv("APP_NAME", "Token Diagnostic Bot")
START_TIME = time.time()

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing. Add it in Railway Variables.")

try:
    ADMIN_ID = int(ADMIN_USER_ID) if ADMIN_USER_ID else None
except ValueError:
    raise RuntimeError("ADMIN_USER_ID must be a numeric Telegram user ID.")

# Keep only recent application log lines in memory; never log submitted bot tokens.
_recent_logs = deque(maxlen=500)

class MemoryLogHandler(logging.Handler):
    def emit(self, record):
        try:
            _recent_logs.append(self.format(record))
        except Exception:
            pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
memory_handler = MemoryLogHandler()
memory_handler.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
))
logging.getLogger().addHandler(memory_handler)
log = logging.getLogger("diagnostic-bot")

COLORS = {
    "blue": "🔵", "green": "🟢", "red": "🔴",
    "yellow": "🟡", "purple": "🟣"
}

def is_admin(user_id: int) -> bool:
    return ADMIN_ID is not None and user_id == ADMIN_ID

def main_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔑 Check Bot Token", callback_data="check_token")],
        [
            InlineKeyboardButton("🌐 Network Test (30s)", callback_data="network"),
            InlineKeyboardButton("🚄 Deployment Status", callback_data="deployment")
        ],
        [
            InlineKeyboardButton("📄 Recent Logs", callback_data="logs"),
            InlineKeyboardButton("📦 System Info", callback_data="system")
        ],
        [InlineKeyboardButton("ℹ️ Help & Security", callback_data="help")]
    ])

def safe_text(value, limit=3500):
    value = str(value)
    value = re.sub(r"\b\d{6,}:[A-Za-z0-9_-]{20,}\b", "[REDACTED_TOKEN]", value)
    return value[:limit]

def report_bytes(report):
    return BytesIO(json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8"))

def log_bytes():
    content = "\n".join(_recent_logs) or "No application logs captured yet."
    content = safe_text(content, 100000)
    return BytesIO(content.encode("utf-8"))

async def send_report(update: Update, report: dict, filename="diagnostic.json"):
    data = report_bytes(report)
    data.name = filename
    await update.effective_message.reply_document(
        document=data,
        caption="📦 Diagnostic JSON report\nSensitive token values are not included."
    )

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    name = user.first_name if user else "Developer"
    mention = f"@{user.username}" if user and user.username else name
    status = "🟢 Admin access enabled" if user and is_admin(user.id) else "🔒 Admin-only token testing"
    text = (
        f"🛡️ <b>{APP_NAME}</b>\n\n"
        f"Welcome, {mention}!\n"
        "Advanced Telegram token diagnostics and deployment checks.\n\n"
        f"{status}\n"
        f"👨‍💻 Developer: {safe_text(DEV_USERNAME, 100)}\n\n"
        "Choose a service below."
    )
    await update.effective_message.reply_text(
        text, reply_markup=main_menu(), parse_mode="HTML"
    )
    log.info("Start command used by user_id=%s", user.id if user else "unknown")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "ℹ️ <b>How to use</b>\n\n"
        "• Token Check: validates a bot token using Telegram getMe.\n"
        "• Network Test: runs DNS and HTTPS connectivity checks for 30 seconds.\n"
        "• Deployment Status: reports this service's Railway/runtime indicators.\n"
        "• Reports: downloads JSON and recent application logs.\n\n"
        "🔐 Token checks are restricted to ADMIN_USER_ID. Submitted tokens are "
        "not saved and are never written to logs or reports.\n\n"
        "⚠️ A valid Telegram token does not itself deploy a bot to Railway. "
        "Remote deployment requires a separately configured Railway project and "
        "authorized Railway API access."
    )
    await update.effective_message.reply_text(text, parse_mode="HTML", reply_markup=main_menu())

async def begin_token_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or not is_admin(user.id):
        await update.effective_message.reply_text(
            "🔒 Token testing is admin-only. Set ADMIN_USER_ID in Railway Variables."
        )
        return
    context.user_data["awaiting_token"] = True
    await update.effective_message.reply_text(
        "🔑 Send the bot token you own.\n\n"
        "It will be checked in memory only and will not be saved.\n"
        "Use /cancel to stop."
    )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("awaiting_token", None)
    await update.effective_message.reply_text("❎ Cancelled.", reply_markup=main_menu())

async def handle_token(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get("awaiting_token"):
        return
    user = update.effective_user
    if not user or not is_admin(user.id):
        context.user_data.pop("awaiting_token", None)
        return
    token = (update.effective_message.text or "").strip()
    context.user_data.pop("awaiting_token", None)

    if not re.fullmatch(r"\d{5,15}:[A-Za-z0-9_-]{20,}", token):
        await update.effective_message.reply_text(
            "🔴 Token format does not look correct. Check the copied value and try again."
        )
        return

    msg = await update.effective_message.reply_text("⏳ Contacting Telegram Bot API securely…")
    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "check": "Telegram getMe",
        "token_validation": "UNKNOWN",
        "deployment_status": "NOT_VERIFIED",
        "bot": None,
        "error": None,
        "security": "Submitted token omitted from this report."
    }
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            response = await client.get(
                f"https://api.telegram.org/bot{token}/getMe"
            )
        body = response.json()
        if response.status_code == 200 and body.get("ok") is True:
            bot = body.get("result", {})
            result["token_validation"] = "VALID"
            result["bot"] = {
                "id": bot.get("id"),
                "username": bot.get("username"),
                "first_name": bot.get("first_name"),
                "can_join_groups": bot.get("can_join_groups"),
                "can_read_all_group_messages": bot.get("can_read_all_group_messages"),
                "supports_inline_queries": bot.get("supports_inline_queries")
            }
            status = (
                "🟢 <b>TOKEN VALID</b>\n\n"
                f"🤖 Bot: @{safe_text(bot.get('username', 'unknown'), 100)}\n"
                f"🆔 ID: <code>{bot.get('id', 'unknown')}</code>\n"
                f"👤 Name: {safe_text(bot.get('first_name', 'unknown'), 100)}\n\n"
                "⚠️ Telegram accepted the token. This does NOT mean a Railway "
                "deployment has been created or started."
            )
            log.info("Token check succeeded for admin user_id=%s", user.id)
        else:
            result["token_validation"] = "INVALID"
            description = body.get("description", "Telegram rejected the token")
            result["error"] = safe_text(description, 300)
            status = (
                "🔴 <b>TOKEN INVALID</b>\n\n"
                f"Reason: {safe_text(description, 300)}\n\n"
                "Check for a revoked token, missing characters, spaces, or a "
                "token copied from the wrong bot."
            )
            log.warning("Token check rejected for admin user_id=%s; HTTP %s",
                        user.id, response.status_code)
    except httpx.TimeoutException:
        result["token_validation"] = "INCONCLUSIVE"
        result["error"] = "Telegram API request timed out."
        status = "🟡 <b>TEST TIMEOUT</b>\nTelegram did not respond before the timeout."
    except Exception as exc:
        result["token_validation"] = "INCONCLUSIVE"
        result["error"] = safe_text(type(exc).__name__, 100)
        status = "🟡 <b>TEST ERROR</b>\nCould not complete the Telegram API check."
        log.exception("Token diagnostic request failed (token redacted)")
    finally:
        token = None

    await msg.edit_text(status, parse_mode="HTML")
    await send_report(update, result)

async def network_test(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = await update.effective_message.reply_text(
        "🌐 Starting 30-second network diagnostics…\n"
        "Checking DNS and HTTPS connectivity every 5 seconds."
    )
    started = time.monotonic()
    samples = []
    hosts = ["api.telegram.org", "railway.app"]
    for i in range(6):
        sample = {"time": datetime.now(timezone.utc).isoformat(), "dns": {}, "https": {}}
        for host in hosts:
            try:
                t0 = time.monotonic()
                await asyncio.to_thread(socket.getaddrinfo, host, 443)
                sample["dns"][host] = {
                    "status": "OK",
                    "latency_ms": round((time.monotonic() - t0) * 1000, 2)
                }
            except Exception as exc:
                sample["dns"][host] = {"status": "FAILED", "error": type(exc).__name__}
        try:
            t0 = time.monotonic()
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get("https://api.telegram.org")
            sample["https"]["telegram_api"] = {
                "status": "REACHABLE",
                "http_status": response.status_code,
                "latency_ms": round((time.monotonic() - t0) * 1000, 2)
            }
        except Exception as exc:
            sample["https"]["telegram_api"] = {
                "status": "FAILED", "error": type(exc).__name__
            }
        samples.append(sample)
        elapsed = int(time.monotonic() - started)
        try:
            await message.edit_text(
                f"🌐 Network test running…\n"
                f"Progress: {min((i + 1) * 5, 30)}/30 seconds\n"
                f"Samples: {len(samples)}"
            )
        except Exception:
            pass
        if i < 5:
            await asyncio.sleep(5)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.monotonic() - started, 2),
        "network_samples": samples,
        "note": "Network diagnostics are observations from this running service."
    }
    await message.edit_text("✅ 30-second network diagnostics completed.")
    await send_report(update, report, "network_diagnostic.json")

def deployment_report():
    railway_vars = {
        "RAILWAY_PROJECT_ID": bool(os.getenv("RAILWAY_PROJECT_ID")),
        "RAILWAY_SERVICE_ID": bool(os.getenv("RAILWAY_SERVICE_ID")),
        "RAILWAY_ENVIRONMENT_ID": bool(os.getenv("RAILWAY_ENVIRONMENT_ID")),
        "RAILWAY_DEPLOYMENT_ID": bool(os.getenv("RAILWAY_DEPLOYMENT_ID"))
    }
    on_railway = bool(os.getenv("RAILWAY_PROJECT_ID") or os.getenv("RAILWAY_SERVICE_ID"))
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "runtime": "Railway" if on_railway else "Other / local",
        "railway_environment_indicators": railway_vars,
        "process_status": "RUNNING",
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "deployment_status": "RUNNING_ON_RAILWAY" if on_railway else "NOT_CONFIRMED_AS_RAILWAY",
        "remote_deployment": "NOT_PERFORMED",
        "explanation": "This check identifies the current service runtime. It does not deploy another bot."
    }

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    choice = query.data
    if choice == "check_token":
        await begin_token_check(update, context)
    elif choice == "network":
        await network_test(update, context)
    elif choice == "deployment":
        report = deployment_report()
        await query.message.reply_text(
            "🚄 <b>Deployment diagnostics</b>\n\n"
            f"Runtime: <b>{report['runtime']}</b>\n"
            f"Process: 🟢 {report['process_status']}\n"
            f"Status: <code>{report['deployment_status']}</code>\n"
            f"Uptime: {report['uptime_seconds']} seconds\n\n"
            "Remote deployment: not performed. A valid Telegram token is not a Railway deployment.",
            parse_mode="HTML"
        )
        fake_update = update
        await send_report(fake_update, report, "deployment_report.json")
    elif choice == "logs":
        data = log_bytes()
        data.name = "application_logs.log"
        await query.message.reply_document(
            document=data,
            caption="📄 Recent in-memory application logs (tokens are redacted)."
        )
    elif choice == "system":
        report = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "runtime": "Railway" if os.getenv("RAILWAY_PROJECT_ID") else "Other / local",
            "uptime_seconds": round(time.time() - START_TIME, 2)
        }
        await query.message.reply_text(
            f"📦 <b>System information</b>\n\n"
            f"Python: {report['python']}\n"
            f"Platform: {safe_text(report['platform'], 150)}\n"
            f"Machine: {safe_text(report['machine'], 100)}\n"
            f"Uptime: {report['uptime_seconds']} sec",
            parse_mode="HTML"
        )
        await send_report(update, report, "system_info.json")
    elif choice == "help":
        await query.message.reply_text(
            "🔐 <b>Security</b>\n"
            "• Only test tokens you own.\n"
            "• Submitted tokens are not persisted.\n"
            "• Reports and logs redact token-shaped strings.\n"
            "• Configure ADMIN_USER_ID before using token checks.\n\n"
            "Railway's full platform deployment logs are available in the Railway dashboard. "
            "This bot can provide its own application logs.",
            parse_mode="HTML",
            reply_markup=main_menu()
        )

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    log.exception("Unhandled application error", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(
                "⚠️ An internal error occurred. Check the application log report."
            )
        except Exception:
            pass

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_token))
    app.add_error_handler(error_handler)
    log.info("%s starting", APP_NAME)
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
