# merged_igbot.py
# Merged igbot5.py + spbot.py
# Exposes both GC renamer (/attack) and message attack (/spam) features.

import argparse
import json
import os
import time
import random
import logging
import sqlite3
import re
from playwright.sync_api import sync_playwright
import urllib.parse
import subprocess
import pty
import errno
import sys
from typing import Dict, List
import threading
import uuid
import signal
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ConversationHandler, ContextTypes
import asyncio
from dotenv import load_dotenv
from playwright_stealth import stealth_sync
from instagrapi import Client
from instagrapi.exceptions import ChallengeRequired, TwoFactorRequired, PleaseWaitFewMinutes, RateLimitError, LoginRequired

load_dotenv()

# ---------------- Logging ----------------
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('merged_instagram_bot.log'),
        logging.StreamHandler()
    ]
)

# ---------------- Globals / Config ----------------
AUTHORIZED_FILE = 'authorized_users.json'
TASKS_FILE = 'tasks.json'
OWNER_TG_ID = int(os.environ.get('OWNER_TG_ID', '0') or 0)
BOT_TOKEN = os.environ.get('BOT_TOKEN')
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

authorized_users = []  # list of {'id': int, 'username': str}
# users_data stores per-telegram-user data (accounts, default, pairs, switch_minutes, threads)
users_data: Dict[int, Dict] = {}
users_pending: Dict[int, Dict] = {}
users_tasks: Dict[int, List[Dict]] = {}  # runtime tasks per tg user
persistent_tasks = []
running_processes: Dict[int, subprocess.Popen] = {}  # pid -> Popen

# PTY / session globals
APP = None
LOOP = None
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()

# ensure sessions dir
os.makedirs('sessions', exist_ok=True)

# === PATCH: Fix instagrapi invalid timestamp bug ===
def _sanitize_timestamps(obj):
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            if isinstance(v, int) and k.endswith("_timestamp_us"):
                try:
                    secs = int(v) // 1_000_000
                except Exception:
                    secs = None
                if secs is None or secs < 0 or secs > 4102444800:
                    new_obj[k] = None
                else:
                    new_obj[k] = secs
            else:
                new_obj[k] = _sanitize_timestamps(v)
        return new_obj
    elif isinstance(obj, list):
        return [_sanitize_timestamps(i) for i in obj]
    else:
        return obj

try:
    import instagrapi.extractors as extractors
    _orig_extract_reply_message = extractors.extract_reply_message

    def patched_extract_reply_message(data):
        data = _sanitize_timestamps(data)
        return _orig_extract_reply_message(data)

    extractors.extract_reply_message = patched_extract_reply_message
    print("[Patch] Applied timestamp sanitizer to instagrapi extractors ✅")
except Exception as e:
    print(f"[Patch Warning] Could not patch instagrapi: {e}")
# === END PATCH ===

# ---------------- Utilities ----------------
def run_with_sync_playwright(fn, *args, **kwargs):
    result = {"value": None, "exc": None}
    def target():
        try:
            with sync_playwright() as p:
                result["value"] = fn(p, *args, **kwargs)
        except Exception as e:
            result["exc"] = e
    t = threading.Thread(target=target)
    t.start()
    t.join()
    if result["exc"]:
        raise result["exc"]
    return result["value"]

def load_authorized():
    global authorized_users
    if os.path.exists(AUTHORIZED_FILE):
        try:
            with open(AUTHORIZED_FILE, 'r') as f:
                authorized_users = json.load(f)
        except Exception:
            authorized_users = []
    if not any(u.get('id') == OWNER_TG_ID for u in authorized_users):
        if OWNER_TG_ID:
            authorized_users.append({'id': OWNER_TG_ID, 'username': 'owner'})

load_authorized()

def load_users_data():
    global users_data
    users_data = {}
    for file in os.listdir('.'):
        if file.startswith('user_') and file.endswith('.json'):
            uid_str = file[5:-5]
            if uid_str.isdigit():
                uid = int(uid_str)
                try:
                    with open(file, 'r') as f:
                        data = json.load(f)
                except Exception:
                    data = {}
                # normalize defaults we expect
                if 'accounts' not in data:
                    data['accounts'] = []
                if 'default' not in data:
                    data['default'] = 0 if data['accounts'] else None
                if 'pairs' not in data:
                    data['pairs'] = None
                if 'switch_minutes' not in data:
                    data['switch_minutes'] = 2
                if 'threads' not in data:
                    data['threads'] = 1
                users_data[uid] = data

load_users_data()

def save_authorized():
    with open(AUTHORIZED_FILE, 'w') as f:
        json.dump(authorized_users, f)

def save_user_data(user_id: int, data: Dict):
    with open(f'user_{user_id}.json', 'w') as f:
        json.dump(data, f)

def is_authorized(user_id: int) -> bool:
    return any(u['id'] == user_id for u in authorized_users)

def is_owner(user_id: int) -> bool:
    return user_id == OWNER_TG_ID

def future_expiry(days=365):
    return int(time.time()) + days*24*3600

def convert_for_playwright(insta_file, playwright_file):
    try:
        with open(insta_file, "r") as f:
            data = json.load(f)
    except Exception:
        return
    cookies = []
    auth = data.get("authorization_data", {})
    for name, value in auth.items():
        cookies.append({
            "name": name,
            "value": urllib.parse.unquote(value),
            "domain": ".instagram.com",
            "path": "/",
            "expires": future_expiry(),
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax"
        })
    playwright_state = {
        "cookies": cookies,
        "origins": [{"origin": "https://www.instagram.com", "localStorage": []}]
    }
    with open(playwright_file, "w") as f:
        json.dump(playwright_state, f, indent=4)

def get_storage_state_from_instagrapi(settings: Dict):
    cl = Client()
    cl.set_settings(settings)
    cookies_dict = {}
    if hasattr(cl, "session") and cl.session:
        try:
            cookies_dict = cl.session.cookies.get_dict()
        except Exception:
            cookies_dict = {}
    elif hasattr(cl, "private") and hasattr(cl.private, "cookies"):
        try:
            cookies_dict = cl.private.cookies.get_dict()
        except Exception:
            cookies_dict = {}
    elif hasattr(cl, "_http") and hasattr(cl._http, "cookies"):
        try:
            cookies_dict = cl._http.cookies.get_dict()
        except Exception:
            cookies_dict = {}
    cookies = []
    for name, value in cookies_dict.items():
        cookies.append({
            "name": name,
            "value": value,
            "domain": ".instagram.com",
            "path": "/",
            "expires": int(time.time()) + 365*24*3600,
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax"
        })
    storage_state = {
        "cookies": cookies,
        "origins": [{"origin": "https://www.instagram.com", "localStorage": []}]
    }
    return storage_state

def instagrapi_login(username, password):
    cl = Client()
    session_file = f"{username}_session.json"
    playwright_file = f"{username}_state.json"
    try:
        cl.login(username, password)
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)
    except (ChallengeRequired, TwoFactorRequired):
        raise ValueError("ERROR_004: Login challenge or 2FA required")
    except (PleaseWaitFewMinutes, RateLimitError):
        raise ValueError("ERROR_002: Rate limit exceeded")
    except Exception as e:
        raise ValueError(f"ERROR_007: Login failed - {str(e)}")
    return json.load(open(playwright_file))

# ---------------- Session / PTY login (shared) ----------------
def child_login(user_id: int, username: str, password: str):
    """child process login using instagrapi; prompts for OTP on the console when needed"""
    cl = Client()
    username_norm = username.strip().lower()
    session_file = f"sessions/{user_id}_{username_norm}_session.json"
    playwright_file = f"sessions/{user_id}_{username_norm}_state.json"
    try:
        print(f"[{username_norm}] ⚙️ Attempting login.. check for otp if required.")
        cl.login(username_norm, password)
        cl.dump_settings(session_file)
        convert_for_playwright(session_file, playwright_file)
        print(f"[{username_norm}] ✅ Logged in successfully. Session saved: {session_file}")
    except TwoFactorRequired:
        print(f" Enter code (6 digits) for {username_norm} (2FA): ", end="", flush=True)
        otp = input().strip()
        try:
            cl.login(username_norm, password, verification_code=otp)
            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)
            print(f"[{username_norm}] ✅ OTP resolved. Logged in. Session saved: {session_file}")
        except Exception as e:
            print(f"[{username_norm}] ❌ OTP failed: {e}")
    except ChallengeRequired:
        print(f" Enter code (6 digits) for {username_norm} (Challenge): ", end="", flush=True)
        otp = input().strip()
        try:
            cl.challenge_resolve(cl.last_json, security_code=otp)
            cl.dump_settings(session_file)
            convert_for_playwright(session_file, playwright_file)
            print(f"[{username_norm}] ✅ OTP resolved. Logged in. Session saved: {session_file}")
        except Exception as e:
            print(f"[{username_norm}] ❌ OTP failed: {e}")
    except Exception as e:
        print(f"[{username_norm}] ❌ Login failed: {e}")
    finally:
        time.sleep(0.5)
        sys.exit(0)

def reader_thread(user_id: int, chat_id: int, master_fd: int, username: str, password: str):
    """Reads child PTY output and forwards short messages to the telegram chat"""
    global APP, LOOP
    buf = b""
    username_norm = username.strip().lower()
    while True:
        try:
            data = os.read(master_fd, 1024)
            if not data:
                break
            buf += data
            while b"\n" in buf or len(buf) > 2048:
                if b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode(errors="ignore").strip()
                else:
                    text = buf.decode(errors="ignore")
                    buf = b""
                if not text:
                    continue
                if text.startswith("Code entered"):
                    continue
                lower = text.lower()
                # filter noise
                if (
                    len(text) > 300
                    or "cdninstagram.com" in lower
                    or "http" in lower
                    or "{" in text
                    or "}" in text
                    or "debug" in lower
                    or "info" in lower
                    or "urllib3" in lower
                    or "connection" in lower
                    or "starting new https" in lower
                    or "instagrapi" in lower
                ):
                    continue
                try:
                    if APP and LOOP:
                        asyncio.run_coroutine_threadsafe(
                            APP.bot.send_message(chat_id=chat_id, text=f"🔥{text}"), LOOP
                        )
                except Exception:
                    logging.error("[THREAD] send_message failed")
        except OSError as e:
            if e.errno == errno.EIO:
                break
            else:
                logging.error("[THREAD] PTY read error: %s", e)
                break
        except Exception as e:
            logging.error("[THREAD] Unexpected error: %s", e)
            break

    # When child exits, save session if available
    try:
        playwright_file = f"sessions/{user_id}_{username_norm}_state.json"
        if os.path.exists(playwright_file):
            with open(playwright_file, 'r') as f:
                state = json.load(f)
            if user_id in users_data:
                data = users_data[user_id]
            else:
                data = {'accounts': [], 'default': None, 'pairs': None, 'switch_minutes': 2, 'threads': 1}
            # find by normalized username
            found = False
            for i, acc in enumerate(data['accounts']):
                if acc.get('ig_username', '').strip().lower() == username_norm:
                    data['accounts'][i] = {'ig_username': username_norm, 'password': password, 'storage_state': state}
                    data['default'] = i
                    found = True
                    break
            if not found:
                data['accounts'].append({'ig_username': username_norm, 'password': password, 'storage_state': state})
                data['default'] = len(data['accounts']) - 1
            save_user_data(user_id, data)
            users_data[user_id] = data
            if APP and LOOP:
                asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text="✅ Login successful and saved securely! 🎉"), LOOP)
        else:
            if APP and LOOP:
                asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text="⚠️ Login failed. No session saved."), LOOP)
    except Exception as e:
        logging.error("Failed to save user data: %s", e)
        if APP and LOOP:
            asyncio.run_coroutine_threadsafe(APP.bot.send_message(chat_id=chat_id, text=f"⚠️ Error saving data: {str(e)}"), LOOP)
    finally:
        with SESSIONS_LOCK:
            if user_id in SESSIONS:
                try:
                    os.close(SESSIONS[user_id]["master_fd"])
                except Exception:
                    pass
                SESSIONS.pop(user_id, None)

# ---------------- Relay input ----------------
async def relay_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text
    with SESSIONS_LOCK:
        info = SESSIONS.get(user_id)
    if not info:
        return
    master_fd = info["master_fd"]
    try:
        os.write(master_fd, (text + "\n").encode())
    except OSError as e:
        await update.message.reply_text(f"Failed to write to PTY stdin: {e}")
    except Exception as e:
        logging.error("Relay input error: %s", e)

# ---------------- Kill command ----------------
async def cmd_kill(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    with SESSIONS_LOCK:
        info = SESSIONS.get(user_id)
    if not info:
        await update.message.reply_text("No active PTY session.")
        return
    pid = info["pid"]
    master_fd = info["master_fd"]
    try:
        os.kill(pid, 15)
    except Exception:
        pass
    try:
        os.close(master_fd)
    except Exception:
        pass
    with SESSIONS_LOCK:
        SESSIONS.pop(user_id, None)
    await update.message.reply_text(f"🛑 Stopped login terminal (pid={pid}) successfully.")

# ---------------- Flush command (owner) ----------------
async def flush(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ you are not an admin ⚠️")
        return
    global users_tasks, persistent_tasks, running_processes
    stopped = 0
    for uid, tasks in list(users_tasks.items()):
        for task in tasks[:]:
            try:
                proc = task.get('proc')
                if proc:
                    proc.terminate()
                    await asyncio.sleep(3)
                    if proc.poll() is None:
                        proc.kill()
                    running_processes.pop(task.get('pid'), None)
                # cleanup files if message attack
                if task.get('type') == 'message_attack' and 'names_file' in task:
                    names_file = task['names_file']
                    if os.path.exists(names_file):
                        os.remove(names_file)
                mark_task_stopped_persistent(task['id'])
                tasks.remove(task)
                stopped += 1
            except Exception as e:
                logging.error("Flush error: %s", e)
        users_tasks[uid] = tasks
    await update.message.reply_text(f"🛑 All tasks globally stopped! ({stopped}) 🛑")

# ---------------- Basic bot commands (shared) ----------------
USERNAME, PASSWORD = range(2)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Welcome — merged IG bot. Use /help to see available commands")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access! ⚠️")
        return
    help_text = """
🌟 Available commands: 🌟
 /help - Show this help
 /login - Login to Instagram account (saves session)
 /viewmyac - View your saved accounts
 /setig <number> - Set default account
 /attack - Start GC renamer (rename group chats)
 /spam - Start message attack (DM or GC spam)
 /stop <PID|all> - Stop tasks
 /task - View ongoing tasks
 /logout <username> - Logout and remove account
 /kill - Kill active PTY login session
Admin:
 /add <tg_id> - Add authorized user
 /remove <tg_id> - Remove authorized user
 /users - List authorized users
 /flush - Stop all tasks globally (owner)
"""
    await update.message.reply_text(help_text)

# ---------------- Login conversation ----------------
async def login_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access! ⚠️")
        return ConversationHandler.END
    await update.message.reply_text("📱 Enter Instagram username (no @):")
    return USERNAME

async def get_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    # Normalize username
    context.user_data['ig_username'] = update.message.text.strip()
    await update.message.reply_text("🔒 Enter password:")
    return PASSWORD

async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    username = context.user_data.get('ig_username')
    password = update.message.text.strip()
    with SESSIONS_LOCK:
        if user_id in SESSIONS:
            await update.message.reply_text("⚠️ PTY session already running. Use /kill first.")
            return ConversationHandler.END
    pid, master_fd = pty.fork()
    if pid == 0:
        try:
            child_login(user_id, username, password)
        except SystemExit:
            os._exit(0)
        except Exception as e:
            print(f"[CHILD] Unexpected error: {e}")
            os._exit(1)
    else:
        t = threading.Thread(target=reader_thread, args=(user_id, chat_id, master_fd, username, password), daemon=True)
        t.start()
        with SESSIONS_LOCK:
            SESSIONS[user_id] = {"pid": pid, "master_fd": master_fd, "thread": t, "username": username, "password": password, "chat_id": chat_id}
    return ConversationHandler.END

async def viewmyac(update: Update, context: ContextTy