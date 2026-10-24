"""Personal link health monitor with SQLite history and a local dashboard."""
import asyncio
import csv
import io
import json
import os
import secrets
import time
from urllib.parse import urlsplit
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite
import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel, Field

from url_pattern_checker import DEFAULT_ERROR_KEYWORDS, DEFAULT_VALID_KEYWORDS, STANDARD_HEADERS, check_url, generate_urls, validate_url

BASE = Path(__file__).resolve().parent
DEFAULT_DB_PATH = Path("/tmp/link_monitor.sqlite3") if os.environ.get("VERCEL") == "1" else BASE / "link_monitor.sqlite3"
DB_PATH = Path(os.environ.get("LINK_MONITOR_DB", str(DEFAULT_DB_PATH)))
SESSION_COOKIE = "admin_session"
SESSION_TTL_SECONDS = 86400
sessions: dict[str, float] = {}
login_attempts: dict[str, tuple[int, float]] = {}
jobs: dict[str, dict] = {}
db: aiosqlite.Connection | None = None
db_lock = asyncio.Lock()
http_client: httpx.AsyncClient | None = None
monitor_scheduler = None
monitor_interval_hours = 6


async def init_db():
    global db
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    await db.executescript("""
      CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY, pattern TEXT NOT NULL, status TEXT NOT NULL,
        started_at TEXT NOT NULL, completed_at TEXT, total INTEGER NOT NULL,
        checked INTEGER NOT NULL DEFAULT 0, valid INTEGER NOT NULL DEFAULT 0,
        rejected INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
        url TEXT NOT NULL, final_url TEXT, status TEXT NOT NULL, status_code INTEGER,
        category TEXT NOT NULL DEFAULT 'unconfirmed', latency_ms REAL, reason TEXT NOT NULL, checked_at TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 1, cached INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(run_id) REFERENCES runs(id)
      );
      CREATE INDEX IF NOT EXISTS checks_url_time ON checks(url, checked_at DESC);
      CREATE INDEX IF NOT EXISTS checks_run ON checks(run_id, id);
      CREATE TABLE IF NOT EXISTS monitored_links (
        url TEXT PRIMARY KEY, final_url TEXT, status TEXT NOT NULL,
        first_seen TEXT NOT NULL, last_checked TEXT NOT NULL, last_error TEXT
      );
      CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    """)
    columns = await (await db.execute("PRAGMA table_info(checks)")).fetchall()
    if "category" not in {row["name"] for row in columns}:
        await db.execute("ALTER TABLE checks ADD COLUMN category TEXT NOT NULL DEFAULT 'unconfirmed'")
    await db.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    global http_client, monitor_scheduler, monitor_interval_hours
    await init_db()
    http_client = httpx.AsyncClient(headers=STANDARD_HEADERS, follow_redirects=True,
                                    limits=httpx.Limits(max_connections=100, max_keepalive_connections=50))
    async with db_lock:
        saved_interval = await (await db.execute("SELECT value FROM app_settings WHERE key='monitor_interval_hours'")).fetchone()
    monitor_interval_hours = max(0, int(saved_interval["value"] if saved_interval else os.environ.get("MONITOR_INTERVAL_HOURS", "6")))
    if monitor_interval_hours:
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
            monitor_scheduler = AsyncIOScheduler()
            monitor_scheduler.add_job(scheduled_check, "interval", hours=monitor_interval_hours, id="health-check", coalesce=True,
                              max_instances=1, next_run_time=datetime.now(timezone.utc))
            monitor_scheduler.start()
        except ImportError:
            print("APScheduler unavailable; scheduled monitoring is disabled")
    try:
        yield
    finally:
        if monitor_scheduler:
            monitor_scheduler.shutdown(wait=False)
            monitor_scheduler = None
        active = [state["task"] for state in jobs.values() if state["task"] and not state["task"].done()]
        for task in active:
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)
        if http_client:
            await http_client.aclose()
        if db:
            await db.close()


app = FastAPI(title="مراقبة صحة الروابط", lifespan=lifespan)


def session_ok(request: Request) -> bool:
    token = request.cookies.get(SESSION_COOKIE)
    expires = sessions.get(token or "", 0)
    if expires <= time.monotonic():
        sessions.pop(token or "", None)
        return False
    return True


def require_auth(request: Request):
    if not session_ok(request):
        raise HTTPException(status_code=401, detail="سجّل الدخول أولاً")


class RunRequest(BaseModel):
    pattern: str = Field(min_length=1, max_length=2000)
    count: int = Field(default=1000, ge=1, le=20000)
    concurrency: int = Field(default=50, ge=1, le=100)
    requests_per_second: int = Field(default=25, ge=1, le=100)
    timeout: float = Field(default=7, gt=0, le=30)
    valid_keywords: list[str] = Field(default_factory=lambda: DEFAULT_VALID_KEYWORDS)
    error_keywords: list[str] = Field(default_factory=lambda: DEFAULT_ERROR_KEYWORDS)
    force_refresh: bool = False


class UploadBatch(BaseModel):
    urls: list[str]


class ScheduleRequest(BaseModel):
    interval_hours: int = Field(ge=0, le=8760)


def validate_target_url(url: str) -> None:
    validate_url(url)
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    allowed = {item.strip().lower().rstrip(".") for item in os.environ.get("ALLOWED_TARGET_HOSTS", "").split(",") if item.strip()}
    if host in {"localhost", "127.0.0.1", "::1"}:
        return
    if any(host == item or host.endswith("." + item) for item in allowed):
        return
    raise ValueError(f"النطاق غير مسموح للفحص: {host}. أضفه إلى ALLOWED_TARGET_HOSTS بعد التأكد من ملكيته.")


def result_category(result: dict) -> str:
    if result.get("status") == "valid":
        return "active"
    reason = str(result.get("reason", "")).casefold()
    code = result.get("status_code")
    if code == 410 or any(word in reason for word in ("revoked", "revoke", "ملغى", "ملغي", "إلغاء")):
        return "revoked"
    if code == 404 or any(word in reason for word in ("expired", "انتهى", "منتهي", "انتهت الصلاحية")):
        return "expired"
    if code is None or (isinstance(code, int) and code >= 500) or any(word in reason for word in ("اتصال", "مهلة", "timeout", "network")):
        return "network_error"
    return "unconfirmed"


class RateGate:
    def __init__(self, per_second: int):
        self.interval = 1 / max(1, per_second)
        self.next_at = 0.0
        self.lock = asyncio.Lock()

    async def wait(self):
        async with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_at - now)
            self.next_at = max(now, self.next_at) + self.interval
        if delay:
            await asyncio.sleep(delay)


async def start_run(urls: list[str], pattern: str, concurrency: int, timeout: float,
                    good: list[str], bad: list[str], force: bool = False,
                    requests_per_second: int = 25) -> str:
    run_id = secrets.token_urlsafe(12)
    started = datetime.now(timezone.utc).isoformat()
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    state = {"id": run_id, "urls": urls, "queue": queue, "status": "running", "checked": 0,
             "valid": 0, "rejected": 0, "total": len(urls), "pause": asyncio.Event(),
             "cancel": asyncio.Event(), "task": None, "concurrency": concurrency,
             "timeout": timeout, "good": good, "bad": bad, "force": force,
             "requests_per_second": requests_per_second, "streaming_input": False,
             "input_queue": asyncio.Queue(maxsize=max(100, concurrency * 2)),
             "started_monotonic": time.monotonic()}
    state["pause"].set()
    jobs[run_id] = state
    async with db_lock:
        await db.execute("INSERT INTO runs(id,pattern,status,started_at,total) VALUES(?,?,?,?,?)",
                         (run_id, pattern, "running", started, len(urls)))
        await db.commit()
    state["task"] = asyncio.create_task(run_workers(state))
    return run_id


async def start_stream_run(concurrency: int, timeout: float, requests_per_second: int) -> str:
    run_id = secrets.token_urlsafe(12)
    started = datetime.now(timezone.utc).isoformat()
    state = {"id": run_id, "urls": [], "queue": asyncio.Queue(maxsize=500), "status": "running",
             "checked": 0, "valid": 0, "rejected": 0, "total": 0, "pause": asyncio.Event(),
             "cancel": asyncio.Event(), "task": None, "concurrency": concurrency,
             "timeout": timeout, "good": DEFAULT_VALID_KEYWORDS, "bad": DEFAULT_ERROR_KEYWORDS,
             "force": True, "requests_per_second": requests_per_second, "streaming_input": True,
             "input_queue": asyncio.Queue(maxsize=max(100, concurrency * 2)), "input_finished": False,
             "started_monotonic": time.monotonic(), "seen_urls": set()}
    state["pause"].set()
    jobs[run_id] = state
    async with db_lock:
        await db.execute("INSERT INTO runs(id,pattern,status,started_at,total) VALUES(?,?,?,?,0)",
                         (run_id, "[stream upload]", "running", started))
        await db.commit()
    state["task"] = asyncio.create_task(run_workers(state))
    return run_id


async def run_workers(state: dict):
    semaphore = asyncio.Semaphore(state["concurrency"])
    rate_gate = RateGate(state["requests_per_second"])
    queue: asyncio.Queue = state["input_queue"]
    limits = httpx.Limits(max_connections=state["concurrency"], max_keepalive_connections=state["concurrency"])
    cache_seconds = max(0, int(os.environ.get("CHECK_CACHE_SECONDS", "120")))
    try:
        async with httpx.AsyncClient(headers=STANDARD_HEADERS, follow_redirects=True, limits=limits) as client:
            async def worker(url: str):
                await state["pause"].wait()
                if state["cancel"].is_set():
                    return
                result = None
                if cache_seconds and not state["force"]:
                    cutoff = datetime.fromtimestamp(time.time() - cache_seconds, timezone.utc).isoformat()
                    async with db_lock:
                        row = await (await db.execute("SELECT * FROM checks WHERE url=? AND checked_at>=? ORDER BY id DESC LIMIT 1", (url, cutoff))).fetchone()
                    if row:
                        result = dict(row)
                        result["cached"] = True
                if result is None:
                    result = await check_url(client, url, semaphore, state["timeout"], state["good"], state["bad"],
                                             verbose=False, max_page_bytes=1024, request_gate=rate_gate.wait)
                    result["cached"] = False
                result.setdefault("attempts", 1)
                result.setdefault("checked_at", datetime.now(timezone.utc).isoformat())
                result["run_id"] = state["id"]
                result["category"] = result_category(result)
                was_valid = False
                async with db_lock:
                    old = await (await db.execute("SELECT status FROM monitored_links WHERE url=?", (url,))).fetchone()
                    was_valid = bool(old and old["status"] == "valid")
                    await db.execute("INSERT INTO checks(run_id,url,final_url,status,status_code,category,latency_ms,reason,checked_at,attempts,cached) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                                     (state["id"], url, result.get("final_url"), result["status"], result.get("status_code"), result["category"], result.get("latency_ms"), result["reason"], result["checked_at"], result["attempts"], int(result["cached"])))
                    if result["status"] == "valid":
                        await db.execute("INSERT INTO monitored_links(url,final_url,status,first_seen,last_checked,last_error) VALUES(?,?,?,?,?,NULL) ON CONFLICT(url) DO UPDATE SET final_url=excluded.final_url,status='valid',last_checked=excluded.last_checked,last_error=NULL",
                                         (url, result.get("final_url"), "valid", result["checked_at"], result["checked_at"]))
                    elif old:
                        await db.execute("UPDATE monitored_links SET status='error',last_checked=?,last_error=? WHERE url=?",
                                         (result["checked_at"], result["reason"], url))
                    await db.commit()
                if was_valid and result["status"] != "valid":
                    await send_alert(url, result["reason"])
                state["checked"] += 1
                state["valid"] += result["status"] == "valid"
                state["rejected"] += result["status"] != "valid"
                await state["queue"].put({"type": "result", "data": result, "checked": state["checked"],
                                          "valid": state["valid"], "rejected": state["rejected"],
                                          "total": state["total"]})

            worker_count = state["concurrency"] if state["streaming_input"] else min(state["concurrency"], len(state["urls"]))
            async def producer():
                for url in state["urls"]:
                    if state["cancel"].is_set():
                        break
                    await queue.put(url)
                for _ in range(worker_count):
                    await queue.put(None)

            async def consumer():
                while not state["cancel"].is_set():
                    await state["pause"].wait()
                    url = await queue.get()
                    if url is None:
                        queue.task_done()
                        return
                    try:
                        await worker(url)
                    finally:
                        queue.task_done()
            consumers = [asyncio.create_task(consumer()) for _ in range(worker_count)]
            if not state["streaming_input"]:
                await producer()
            await queue.join()
            await asyncio.gather(*consumers)
    except asyncio.CancelledError:
        state["cancel"].set()
        raise
    finally:
        state["status"] = "cancelled" if state["cancel"].is_set() else "completed"
        completed = datetime.now(timezone.utc).isoformat()
        async with db_lock:
            await db.execute("UPDATE runs SET status=?,completed_at=?,checked=?,valid=?,rejected=? WHERE id=?",
                             (state["status"], completed, state["checked"], state["valid"], state["rejected"], state["id"]))
            await db.commit()
        await state["queue"].put({"type": "done", "status": state["status"], "total": state["total"],
                                  "checked": state["checked"], "valid": state["valid"], "rejected": state["rejected"]})
        await send_completion_alert(state)


async def send_alert(url: str, reason: str):
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        return
    try:
        await http_client.post(f"https://api.telegram.org/bot{token}/sendMessage",
                               json={"chat_id": chat, "text": f"رابط مراقب أصبح غير صالح: {url}\n{reason}"}, timeout=8)
    except httpx.HTTPError:
        pass


async def send_completion_alert(state: dict):
    discord = os.environ.get("DISCORD_WEBHOOK_URL")
    bot_token, chat_id = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not discord and not (bot_token and chat_id):
        return
    elapsed = max(0.0, time.monotonic() - state.get("started_monotonic", time.monotonic()))
    summary = (f"انتهى فحص الروابط ({state['status']}): {state['checked']} مفحوص، "
               f"{state['valid']} نشط، {state['rejected']} مستبعد، خلال {elapsed:.1f} ثانية.")
    try:
        if discord:
            await http_client.post(discord, json={"content": summary}, timeout=8)
        elif bot_token and chat_id:
            await http_client.post(f"https://api.telegram.org/bot{bot_token}/sendMessage",
                                   json={"chat_id": chat_id, "text": summary}, timeout=8)
    except httpx.HTTPError:
        pass


async def scheduled_check():
    if any(x["status"] in {"running", "paused"} for x in jobs.values()):
        return
    async with db_lock:
        rows = await (await db.execute("SELECT url FROM monitored_links")).fetchall()
    urls = []
    for row in rows:
        try:
            validate_target_url(row["url"])
            urls.append(row["url"])
        except ValueError:
            continue
    if urls:
        await start_run(urls, "[scheduled monitoring]", min(30, len(urls)), 7,
                        DEFAULT_VALID_KEYWORDS, DEFAULT_ERROR_KEYWORDS, True)


@app.get("/")
async def home():
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if session_ok(request):
        return RedirectResponse("/dashboard", status_code=303)
    return HTMLResponse((BASE / "login.html").read_text(encoding="utf-8"), headers={"Cache-Control": "no-store"})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not session_ok(request):
        return RedirectResponse("/login", status_code=303)
    return HTMLResponse((BASE / "index.html").read_text(encoding="utf-8"), headers={"Cache-Control": "no-store"})


@app.post("/api/login")
async def login(request: Request, response: Response):
    password = os.environ.get("ADMIN_PASSWORD")
    if not password:
        raise HTTPException(503, "اضبط ADMIN_PASSWORD في متغيرات البيئة أولاً")
    ip = request.client.host if request.client else "unknown"
    attempts, lock_until = login_attempts.get(ip, (0, 0.0))
    now = time.monotonic()
    if lock_until > now:
        raise HTTPException(429, "محاولات كثيرة؛ انتظر قبل إعادة المحاولة")
    payload = await request.json()
    submitted = payload.get("password", "") if isinstance(payload, dict) else ""
    if not isinstance(submitted, str) or not secrets.compare_digest(submitted, password):
        attempts += 1
        login_attempts[ip] = (attempts, now + 900 if attempts >= 5 else 0.0)
        raise HTTPException(401, "كلمة المرور غير صحيحة")
    login_attempts.pop(ip, None)
    token = secrets.token_urlsafe(32)
    sessions[token] = now + SESSION_TTL_SECONDS
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL_SECONDS, httponly=True,
                        secure=os.environ.get("COOKIE_SECURE", "0").lower() in {"1", "true", "yes"},
                        samesite="strict", path="/")
    return {"success": True}


@app.post("/api/logout")
async def logout(request: Request, response: Response):
    sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"success": True}


@app.post("/api/clear-data")
async def clear_data(request: Request):
    """Cancel live scans and permanently remove persisted scan and monitoring data."""
    require_auth(request)
    active = [state for state in jobs.values() if state["status"] in {"running", "paused"}]
    tasks = [state["task"] for state in active if state["task"] and not state["task"].done()]
    for state in active:
        state["cancel"].set()
        state["pause"].set()
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    async with db_lock:
        await db.execute("DELETE FROM checks")
        await db.execute("DELETE FROM runs")
        await db.execute("DELETE FROM monitored_links")
        await db.commit()
        await db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        await db.execute("VACUUM")
    jobs.clear()
    return {"success": True, "cancelled_runs": len(active)}


@app.post("/api/runs")
async def create_run(payload: RunRequest, request: Request):
    require_auth(request)
    try:
        urls = list(generate_urls(payload.pattern, 20000))[:payload.count]
        if not urls:
            raise ValueError("لم ينتج النمط أي روابط")
        for url in urls:
            validate_target_url(url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if not payload.valid_keywords or not payload.error_keywords:
        raise HTTPException(422, "أدخل كلمة قبول وكلمة رفض واحدة على الأقل")
    run_id = await start_run(urls, payload.pattern, payload.concurrency, payload.timeout,
                             payload.valid_keywords, payload.error_keywords, payload.force_refresh,
                             payload.requests_per_second)
    return {"run_id": run_id, "total": len(urls)}


@app.post("/api/runs/upload")
async def upload_run(request: Request, file: UploadFile = File(...), concurrency: int = Form(50),
                     timeout: float = Form(7), requests_per_second: int = Form(25)):
    require_auth(request)
    if not 1 <= concurrency <= 100 or not 0 < timeout <= 30 or not 1 <= requests_per_second <= 100:
        raise HTTPException(422, "Concurrency يجب أن تكون 1–100، ومعدل الطلبات 1–100، والمهلة حتى 30 ثانية")
    raw = await file.read(4_000_001)
    if len(raw) > 4_000_000:
        raise HTTPException(413, "حجم الملف يتجاوز 4 ميغابايت")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(422, "يجب أن يكون الملف بترميز UTF-8") from exc
    if (file.filename or "").lower().endswith(".csv"):
        candidates = []
        for row in csv.reader(io.StringIO(content)):
            match = next((cell.strip() for cell in row if cell.strip().lower().startswith(("http://", "https://"))), None)
            if match:
                candidates.append(match)
    else:
        candidates = [line.strip() for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    urls = list(dict.fromkeys(candidates))
    if not urls:
        raise HTTPException(422, "لم أجد روابط HTTP/HTTPS في الملف")
    if len(urls) > 20000:
        raise HTTPException(422, "الحد الأقصى 20,000 رابط فريد في الدفعة")
    try:
        for url in urls:
            validate_target_url(url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    run_id = await start_run(urls, f"[uploaded: {file.filename or 'links'}]", concurrency, timeout,
                             DEFAULT_VALID_KEYWORDS, DEFAULT_ERROR_KEYWORDS, True, requests_per_second)
    return {"run_id": run_id, "total": len(urls)}


@app.post("/api/uploads")
async def create_upload(request: Request, concurrency: int = 50, timeout: float = 7,
                        requests_per_second: int = 25):
    require_auth(request)
    if not 1 <= concurrency <= 100 or not 0 < timeout <= 30 or not 1 <= requests_per_second <= 100:
        raise HTTPException(422, "إعدادات التوازي أو معدل الطلبات أو المهلة خارج الحدود")
    run_id = await start_stream_run(concurrency, timeout, requests_per_second)
    return {"run_id": run_id, "total": 0}


@app.post("/api/uploads/{run_id}/batch")
async def upload_batch(run_id: str, payload: UploadBatch, request: Request):
    require_auth(request)
    state = jobs.get(run_id)
    if not state or not state["streaming_input"] or state["input_finished"] or state["status"] != "running":
        raise HTTPException(404, "جلسة رفع غير موجودة أو مغلقة")
    if not payload.urls or len(payload.urls) > 500:
        raise HTTPException(422, "ترسل الدفعة من 1 إلى 500 رابط")
    batch = list(dict.fromkeys(url.strip() for url in payload.urls if url.strip()))
    try:
        for url in batch:
            validate_target_url(url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    fresh = [url for url in batch if url not in state["seen_urls"]]
    if state["total"] + len(fresh) > 20000:
        raise HTTPException(422, "الحد الأقصى 20,000 رابط فريد في الدفعة")
    for url in fresh:
        state["seen_urls"].add(url)
    state["total"] += len(fresh)
    async with db_lock:
        await db.execute("UPDATE runs SET total=? WHERE id=?", (state["total"], run_id))
        await db.commit()
    for url in fresh:
        await state["input_queue"].put(url)
    return {"accepted": len(fresh), "total": state["total"]}


@app.post("/api/uploads/{run_id}/finish")
async def finish_upload(run_id: str, request: Request):
    require_auth(request)
    state = jobs.get(run_id)
    if not state or not state["streaming_input"] or state["input_finished"] or state["status"] != "running":
        raise HTTPException(404, "جلسة رفع غير موجودة أو مغلقة")
    state["input_finished"] = True
    for _ in range(state["concurrency"]):
        await state["input_queue"].put(None)
    return {"success": True, "total": state["total"]}


@app.get("/api/runs/{run_id}/events")
async def run_events(run_id: str, request: Request):
    require_auth(request)
    state = jobs.get(run_id)
    if not state:
        raise HTTPException(404, "الفحص غير موجود في الذاكرة الحالية")
    async def events():
        while True:
            if await request.is_disconnected():
                return
            first = await state["queue"].get()
            if first["type"] == "done":
                yield f"data: {json.dumps(first, ensure_ascii=False)}\n\n"
                return
            batch = [first]
            deadline = asyncio.get_running_loop().time() + 0.2
            finished = None
            while len(batch) < 50:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    item = await asyncio.wait_for(state["queue"].get(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                if item["type"] == "done":
                    finished = item
                    break
                batch.append(item)
            last = batch[-1]
            payload = {"type": "batch", "results": [item["data"] for item in batch],
                       "checked": last["checked"], "valid": last["valid"],
                       "rejected": last["rejected"], "total": last["total"]}
            yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            if finished:
                yield f"data: {json.dumps(finished, ensure_ascii=False)}\n\n"
                return
    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control":"no-cache", "X-Accel-Buffering":"no"})


@app.post("/api/runs/{run_id}/{action}")
async def control_run(run_id: str, action: str, request: Request):
    require_auth(request)
    state = jobs.get(run_id)
    if not state:
        raise HTTPException(404, "الفحص غير موجود")
    if action == "pause" and state["status"] == "running":
        state["pause"].clear(); state["status"] = "paused"
        async with db_lock:
            await db.execute("UPDATE runs SET status='paused' WHERE id=?", (run_id,)); await db.commit()
    elif action == "resume" and state["status"] == "paused":
        state["status"] = "running"; state["pause"].set()
        async with db_lock:
            await db.execute("UPDATE runs SET status='running' WHERE id=?", (run_id,)); await db.commit()
    elif action == "cancel" and state["status"] in {"running", "paused"}:
        state["cancel"].set(); state["pause"].set()
        if state["task"] and not state["task"].done():
            state["task"].cancel()
            await asyncio.gather(state["task"], return_exceptions=True)
    else:
        raise HTTPException(409, "تعذر تنفيذ الإجراء على هذه الحالة")
    return {"status": state["status"]}


@app.get("/api/runs")
async def run_history(request: Request):
    require_auth(request)
    async with db_lock:
        rows = await (await db.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT 50")).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/monitored")
async def monitored(request: Request):
    require_auth(request)
    async with db_lock:
        rows = await (await db.execute("SELECT * FROM monitored_links ORDER BY last_checked DESC LIMIT 500")).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/scheduler")
async def get_scheduler(request: Request):
    require_auth(request)
    return {"interval_hours": monitor_interval_hours, "enabled": monitor_interval_hours > 0}


@app.post("/api/scheduler")
async def update_scheduler(payload: ScheduleRequest, request: Request):
    global monitor_scheduler, monitor_interval_hours
    require_auth(request)
    monitor_interval_hours = payload.interval_hours
    async with db_lock:
        await db.execute("INSERT INTO app_settings(key,value) VALUES('monitor_interval_hours',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (str(monitor_interval_hours),))
        await db.commit()
    if monitor_scheduler is None:
        if monitor_interval_hours:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
            monitor_scheduler = AsyncIOScheduler()
            monitor_scheduler.start()
    if monitor_scheduler:
        if monitor_interval_hours:
            if monitor_scheduler.get_job("health-check"):
                monitor_scheduler.reschedule_job("health-check", trigger="interval", hours=monitor_interval_hours)
            else:
                monitor_scheduler.add_job(scheduled_check, "interval", hours=monitor_interval_hours,
                                          id="health-check", coalesce=True, max_instances=1)
        elif monitor_scheduler.get_job("health-check"):
            monitor_scheduler.remove_job("health-check")
    return {"interval_hours": monitor_interval_hours, "enabled": monitor_interval_hours > 0}


@app.get("/api/runs/{run_id}/export")
async def export_run(run_id: str, request: Request, format: str = "csv"):
    require_auth(request)
    if format not in {"csv", "json"}:
        raise HTTPException(422, "الصيغة المدعومة csv أو json")
    async def record_batches():
        last_id = 0
        while True:
            async with db_lock:
                rows = await (await db.execute(
                    "SELECT id,url,final_url,status,status_code,category,latency_ms,reason,checked_at,attempts,cached FROM checks WHERE run_id=? AND id>? ORDER BY id LIMIT 500",
                    (run_id, last_id),
                )).fetchall()
            if not rows:
                return
            last_id = rows[-1]["id"]
            yield [dict(row) for row in rows]

    if format == "json":
        async def json_stream():
            yield b"["
            first = True
            async for batch in record_batches():
                for row in batch:
                    row.pop("id", None)
                    if not first:
                        yield b","
                    yield json.dumps(row, ensure_ascii=False).encode("utf-8")
                    first = False
            yield b"]"
        return StreamingResponse(json_stream(), media_type="application/json",
                                 headers={"Content-Disposition": f'attachment; filename="link-health-{run_id}.json"'})

    fields = ["url", "final_url", "status", "status_code", "category", "latency_ms", "reason", "checked_at", "attempts", "cached"]
    async def csv_stream():
        header = io.StringIO(newline="")
        csv.DictWriter(header, fieldnames=fields).writeheader()
        yield ("\ufeff" + header.getvalue()).encode("utf-8")
        async for batch in record_batches():
            output = io.StringIO(newline="")
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writerows({key: row.get(key) for key in fields} for row in batch)
            yield output.getvalue().encode("utf-8")
    return StreamingResponse(csv_stream(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="link-health-{run_id}.csv"'})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000)
