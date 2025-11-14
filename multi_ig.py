#!/usr/bin/env python3
"""
multi_ig.py
Merged Instagram Group Chat Renamer (async) and DM Sender (sync) in one file.
Behavior:
 - Uses existing storage-state files created by your bot (sessions/{user_id}_{username}_state.json) when available.
 - If --storage-state is provided, that path is used. Otherwise the script searches sessions/*_{username}_state.json.
 - Two modes: "rename" (async renamer) and "spam" (sync DM sender).
Usage examples:
  python3 multi_ig.py rename --username me --thread-url https://www.instagram.com/direct/t/123/ --names "Name1,Name2" --headless false
  python3 multi_ig.py spam   --username me --thread-url https://www.instagram.com/direct/t/123/ --names "msg1 & msg2" --tabs 2
"""
import argparse
import asyncio
import json
import os
import re
import time
import random
import threading
import glob
import sys

# async playwright for renamer
from playwright.async_api import async_playwright, TimeoutError as PWTimeoutError
# sync playwright for spam sender
from playwright.sync_api import sync_playwright

INVISIBLE_CHARS = ["\u200B", "\u200C", "\u200D", "\u2060"]  # zero-width variants


def find_storage_state_for_username(username: str):
    """Search sessions/*_{username}_state.json and return first match, else None"""
    if not username:
        return None
    username_norm = username.strip().lower()
    pattern = os.path.join("sessions", f"*_{username_norm}_state.json")
    matches = glob.glob(pattern)
    if matches:
        return matches[0]
    # fallback to {username}_state.json in cwd
    alt = f"{username_norm}_state.json"
    if os.path.exists(alt):
        return alt
    return None


async def apply_anti_detection_async(page):
    await page.evaluate("""() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
        window.chrome = { app: {}, runtime: {} };
        const originalQuery = navigator.permissions.query;
        navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ? Promise.resolve({ state: 'denied' }) : originalQuery(parameters)
        );
        const getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {
            if (parameter === 37445) return 'Google Inc. (Intel)';
            if (parameter === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics)';
            return getParameter.call(this, parameter);
        };
    }""")


def apply_anti_detection_sync(page):
    page.evaluate("""() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
        window.chrome = { app: {}, runtime: {} };
        const originalQuery = navigator.permissions.query;
        navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ? Promise.resolve({ state: 'denied' }) : originalQuery(parameters)
        );
        const getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {
            if (parameter === 37445) return 'Google Inc. (Intel)';
            if (parameter === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics)';
            return getParameter.call(this, parameter);
        };
    }""")


# ----------------- Renamer (async) -----------------
async def renamer_main(args):
    headless = args.headless.lower() == "true"
    names_list = [n.strip() for n in re.split(r"[,\n]", args.names) if n.strip()]
    if not names_list:
        print("No names provided (--names).")
        return

    # determine storage state
    storage_state = args.storage_state or find_storage_state_for_username(args.username)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless,
                                         args=['--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage'])

        if storage_state and os.path.exists(storage_state):
            try:
                with open(storage_state, "r", encoding="utf-8") as f:
                    state = json.load(f)
                context = await browser.new_context(storage_state=state)
                print(f"Loaded storage state: {storage_state}")
            except Exception as e:
                print(f"Failed loading storage_state {storage_state}: {e}. Creating new context.")
                context = await browser.new_context()
        else:
            context = await browser.new_context()

        page = await context.new_page()
        await apply_anti_detection_async(page)

        try:
            await page.goto(args.thread_url, timeout=60000)
        except Exception as e:
            print(f"Navigation error: {e}")

        async def setup_details_pane():
            try:
                details = page.locator("div[role='button'][aria-label*='details'], div[role='button'][aria-label*='Open the details pane']")
                await details.wait_for(timeout=15000)
                await details.click()
            except Exception:
                pass

        async def perform_login_if_needed():
            if "login" in page.url or "accounts/login" in page.url:
                if not args.password:
                    raise RuntimeError("Login required but no --password provided.")
                print("Performing login (no valid session)...")
                await apply_anti_detection_async(page)
                try:
                    await page.fill('input[name="username"]', args.username)
                    await page.fill('input[name="password"]', args.password)
                    await page.click('button[type="submit"]')
                    await page.wait_for_url(lambda url: 'login' not in url and 'challenge' not in url, timeout=60000)

                    save_path = args.storage_state or f"{args.username}_state.json"
                    await context.storage_state(path=save_path)
                    print("Saved storage_state ->", save_path)
                except Exception as e:
                    print("Login failed:", e)
                    raise

        await perform_login_if_needed()
        await setup_details_pane()

        page_ref = [page]
        pending_ref = [None]
        last_refresh_time = time.time()

        i = 0

        while True:
            base_name = names_list[i % len(names_list)]
            invis = "".join(random.choice(INVISIBLE_CHARS) for _ in range(random.randint(1,3)))
            pos = random.choice([0, len(base_name)//2, len(base_name)])
            new_name = base_name[:pos] + invis + base_name[pos:]

            try:
                change_btn = page_ref[0].locator("div[role='button'][aria-label*='Change group name']")
                await change_btn.wait_for(timeout=8000)
                await change_btn.click()

                input_locator = page_ref[0].locator("input[aria-label='Group name']")
                await input_locator.wait_for(timeout=8000)

                current = await input_locator.input_value()
                if current == new_name:
                    await page_ref[0].keyboard.press('Escape')
                    i += 1
                    continue

                await input_locator.fill(new_name)

                save_btn = page_ref[0].locator("div[role='button']:has-text('Save')")
                await save_btn.wait_for(timeout=5000)
                await save_btn.click()

                print("Renamed:", new_name)
                i += 1

                if pending_ref[0]:
                    try:
                        print("Switching to new prepared tab")
                        old = page_ref[0]
                        page_ref[0] = pending_ref[0]
                        pending_ref[0] = None
                        await old.close()
                    except:
                        pass

                if time.time() - last_refresh_time >= 60 and pending_ref[0] is None:
                    async def prepare_new_tab():
                        try:
                            np = await context.new_page()
                            await apply_anti_detection_async(np)
                            await np.goto(args.thread_url, timeout=60000)
                            await np.wait_for_selector("div[role='button'][aria-label*='Change group name']", timeout=60000)
                            pending_ref[0] = np
                            print("Prepared new tab.")
                        except Exception as e:
                            print("Failed preparing tab:", e)

                    asyncio.create_task(prepare_new_tab())
                    last_refresh_time = time.time()

            except Exception as e:
                print("Rename error:", e)
                try:
                    await page_ref[0].keyboard.press('Escape')
                except:
                    pass
                await asyncio.sleep(1)
                i += 1


# ----------------- Spam Sender (sync) -----------------
def parse_messages(names_arg):
    if names_arg.endswith(".txt") and os.path.exists(names_arg):
        with open(names_arg, "r", encoding="utf-8") as f:
            content = f.read().strip()
    else:
        content = names_arg.strip()

    content = content.replace(" and ", "&")
    return [m.strip() for m in content.split("&") if m.strip()]


def spam_sender_tab(tab_id, args, messages, headless, storage_path):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)

        if storage_path and os.path.exists(storage_path):
            context = browser.new_context(storage_state=storage_path)
            print(f"[Tab {tab_id}] Loaded storage_state: {storage_path}")
        else:
            context = browser.new_context()

        page = context.new_page()
        apply_anti_detection_sync(page)

        try:
            page.goto(args.thread_url, timeout=60000)
            dm_sel = 'div[role="textbox"][aria-label="Message"]'
            page.wait_for_selector(dm_sel, timeout=30000)

            print(f"[Tab {tab_id}] Started message loop")

            while True:
                for msg in messages:
                    try:
                        if page.locator(dm_sel).is_visible():
                            page.click(dm_sel)
                            page.fill(dm_sel, msg)
                            page.press(dm_sel, "Enter")
                            print(f"[Tab {tab_id}] Sent:", msg)
                        time.sleep(0.4)
                    except Exception as e:
                        print(f"[Tab {tab_id}] Error: {e}")
                        time.sleep(0.4)

        except Exception as e:
            print(f"[Tab {tab_id}] Unexpected:", e)
        finally:
            try:
                browser.close()
            except:
                pass


def spam_main(args):
    headless = args.headless.lower() == "true"
    messages = parse_messages(args.names)

    if not messages:
        print("No messages provided.")
        return

    storage = args.storage_state or find_storage_state_for_username(args.username)
    tabs = min(max(args.tabs, 1), 3)

    threads = []
    for i in range(tabs):
        t = threading.Thread(target=spam_sender_tab, args=(i+1, args, messages, headless, storage), daemon=True)
        t.start()
        threads.append(t)

    print(f"Running {tabs} tabs... Ctrl+C to stop")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("Stopping...")


# ----------------- Utilities -----------------
def ensure_storage_state_or_fail(args):
    storage = args.storage_state or find_storage_state_for_username(args.username)
    if storage and os.path.exists(storage):
        return storage
    return None


# ----------------- CLI -----------------
def main():
    parser = argparse.ArgumentParser(prog="multi_ig.py", description="Merged IG renamer + spam using bot sessions")
    sub = parser.add_subparsers(dest="mode", required=True)

    # rename mode
    r = sub.add_parser("rename")
    r.add_argument("--username", required=False)
    r.add_argument("--password", required=False)
    r.add_argument("--thread-url", required=True)
    r.add_argument("--names", required=True)
    r.add_argument("--headless", default="true")
    r.add_argument("--storage-state")

    # spam mode
    s = sub.add_parser("spam")
    s.add_argument("--username", required=False)
    s.add_argument("--password", required=False)
    s.add_argument("--thread-url", required=True)
    s.add_argument("--names", required=True)
    s.add_argument("--headless", default="true")
    s.add_argument("--tabs", type=int, default=1)
    s.add_argument("--storage-state")

    args = parser.parse_args()

    if args.mode == "rename":
        storage = ensure_storage_state_or_fail(args)
        if not storage and not args.password:
            print("No session found. Provide --password or --storage-state.")
            return
        asyncio.run(renamer_main(args))

    elif args.mode == "spam":
        storage = ensure_storage_state_or_fail(args)
        if not storage and not args.password:
            print("No session found. Provide --password or --storage-state.")
            return
        spam_main(args)


if __name__ == "__main__":
    main()