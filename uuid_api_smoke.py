#!/usr/bin/env python3
"""Check a local/staging UUIDv4 API with randomly generated identifiers."""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
NOT_FOUND_VALUES = {"not_found", "not found", "invalid", "expired", "missing"}
SUCCESS_VALUES = {"success", "active", "activated"}


def build_url(base_url: str, token: str) -> str:
    parts = urlsplit(base_url)
    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key != "id"]
    query.append(("id", token))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def validate_target(base_url: str, allow_staging: bool) -> None:
    parts = urlsplit(base_url)
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in {"http", "https"} or not host:
        raise ValueError("أدخل عنوان HTTP(S) صالحاً مثل http://localhost:8000/activate")
    local = host in LOCAL_HOSTS or host.endswith(".localhost") or host.endswith(".test")
    staging = "staging" in host
    if not local and not (allow_staging and staging):
        raise ValueError("الهدف مسموح به افتراضياً على localhost فقط؛ لاختبار نطاق staging استخدم --allow-staging ويجب أن يتضمن اسم المضيف كلمة staging")
    if parts.username or parts.password:
        raise ValueError("لا تضع بيانات اعتماد داخل عنوان URL")


def classify(status_code: int, content_type: str, body: bytes, success_marker: str) -> tuple[str, str]:
    if status_code >= 500:
        return "server_error", f"HTTP {status_code}"
    if status_code in {404, 410}:
        return "not_found", f"HTTP {status_code}"

    text = body.decode("utf-8", errors="replace")
    payload = None
    if "json" in content_type.lower():
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            pass

    if isinstance(payload, dict):
        status = str(payload.get("status", "")).strip().casefold()
        if status in NOT_FOUND_VALUES:
            return "not_found", f"API status: {status}"
        if status in SUCCESS_VALUES and 200 <= status_code < 300:
            return "valid", f"API status: {status}"
        if payload.get("success") is True and 200 <= status_code < 300:
            return "valid", "API success: true"

    if 200 <= status_code < 300 and success_marker.casefold() in text.casefold():
        return "valid", f"وجدت علامة النجاح: {success_marker}"
    return "unknown", f"HTTP {status_code} دون إشارة نجاح مؤكدة"


async def run(args: argparse.Namespace) -> int:
    validate_target(args.url, args.allow_staging)
    semaphore = asyncio.Semaphore(args.concurrency)
    latencies: list[float] = []
    totals = {"valid": 0, "not_found": 0, "server_error": 0, "unknown": 0}
    output = Path(args.output)
    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    timeout = httpx.Timeout(args.timeout)

    async with httpx.AsyncClient(follow_redirects=True, limits=limits, timeout=timeout) as client:
        async def check_one() -> tuple[str, str, float]:
            token = uuid.uuid4().hex
            url = build_url(args.url, token)
            async with semaphore:
                start = time.perf_counter()
                try:
                    async with client.stream("GET", url) as response:
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk[: 256_000 - len(body)])
                            if len(body) >= 256_000:
                                break
                        state, reason = classify(response.status_code, response.headers.get("content-type", ""), bytes(body), args.success_marker)
                    latency = (time.perf_counter() - start) * 1000
                except httpx.HTTPError as exc:
                    latency = (time.perf_counter() - start) * 1000
                    state, reason = "server_error", type(exc).__name__
            print(f"[{state}] {token} — {reason}")
            return token, state, latency

        # Keep the number of scheduled coroutine objects bounded by the worker count.
        queue: asyncio.Queue[int | None] = asyncio.Queue()
        for _ in range(args.count):
            queue.put_nowait(1)
        for _ in range(args.concurrency):
            queue.put_nowait(None)

        async def worker():
            while await queue.get() is not None:
                token, state, latency = await check_one()
                totals[state] += 1
                latencies.append(latency)
                if state == "valid":
                    with output.open("a", encoding="utf-8", newline="\n") as file:
                        file.write(token + "\n")

        output.write_text("", encoding="utf-8")
        started = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(min(args.concurrency, args.count))))
        elapsed = time.perf_counter() - started

    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))] if ordered else 0
    mean = statistics.fmean(latencies) if latencies else 0
    print("\nملخص الاختبار")
    print(f"إجمالي الطلبات: {sum(totals.values())} | الصالحة: {totals['valid']} | غير الموجودة: {totals['not_found']} | أخطاء الخادم/الاتصال: {totals['server_error']} | غير محسومة: {totals['unknown']}")
    print(f"زمن الاستجابة: متوسط {mean:.1f}ms، المئين 95 {p95:.1f}ms | الزمن الكلي: {elapsed:.1f}s")
    print(f"المعرّفات المقبولة: {output.resolve()}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="اختبار API محلي أو staging بمعرّفات UUIDv4 عشوائية")
    parser.add_argument("url", help="عنوان المسار، مثل http://localhost:8000/activate")
    parser.add_argument("--count", type=int, default=100, help="عدد الطلبات (1–10000، الافتراضي 100)")
    parser.add_argument("--concurrency", type=int, default=10, help="حد الطلبات المتزامنة (1–100، الافتراضي 10)")
    parser.add_argument("--timeout", type=float, default=5, help="مهلة الطلب بالثواني")
    parser.add_argument("--success-marker", default="active", help="علامة نصية تؤكد النجاح")
    parser.add_argument("--output", default="accepted_uuids.txt", help="ملف UUIDs المقبولة")
    parser.add_argument("--allow-staging", action="store_true", help="السماح بنطاق خارجي يحتوي اسمه على staging")
    args = parser.parse_args()
    if not 1 <= args.count <= 10_000 or not 1 <= args.concurrency <= 100 or args.timeout <= 0:
        parser.error("count يجب أن يكون 1–10000، وconcurrency 1–100، والمهلة أكبر من صفر")
    try:
        return asyncio.run(run(args))
    except (ValueError, OSError) as exc:
        print(f"خطأ: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
