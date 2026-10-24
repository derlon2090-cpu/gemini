#!/usr/bin/env python3
"""Expand URL patterns and save reachable candidates to valid_links.txt."""

from __future__ import annotations

import argparse
import asyncio
import email.utils
import itertools
import random
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from bs4 import BeautifulSoup


TOKEN = re.compile(r"\[([^\[\]]+)\]")
RANGE = re.compile(r"^(-?\d+)-(-?\d+)$")
DEFAULT_VALID_KEYWORDS = ["صالح للقبول", "متاح للقبول", "claim now", "available", "accept offer"]
DEFAULT_ERROR_KEYWORDS = ["غير متاح", "انتهى العرض", "انتهت الصلاحية", "ملغي", "ملغى", "revoked", "error", "expired", "not found", "غير صالح"]
MAX_PAGE_BYTES = 1_000_000
STANDARD_HEADERS = {
    "User-Agent": "URLHealthMonitor/1.0 (personal link monitoring)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
}


def expand_token(token: str) -> list[str]:
    """Expand [1-10], [001-020], [a-z], or a literal choice such as [abc]."""
    match = RANGE.fullmatch(token)
    if match:
        left, right = match.groups()
        start, end = int(left), int(right)
        step = 1 if start <= end else -1
        width = max(len(left.lstrip("-")), len(right.lstrip("-")))
        padded = left.lstrip("-").startswith("0") or right.lstrip("-").startswith("0")
        values = range(start, end + step, step)
        return [(("-" if value < 0 else "") + str(abs(value)).zfill(width if padded else 1)) for value in values]
    if len(token) == 3 and token[1] == "-" and token[0].isalpha() and token[2].isalpha():
        start, end = ord(token[0]), ord(token[2])
        step = 1 if start <= end else -1
        return [chr(code) for code in range(start, end + step, step)]
    if token:
        return list(dict.fromkeys(token))
    raise ValueError("النمط [] فارغ")


def parse_pattern(pattern: str) -> tuple[list[str], list[list[str]]]:
    parts: list[str] = []
    choices: list[list[str]] = []
    cursor = 0
    for match in TOKEN.finditer(pattern):
        parts.append(pattern[cursor:match.start()])
        choices.append(expand_token(match.group(1)))
        cursor = match.end()
    parts.append(pattern[cursor:])
    if "[" in "".join(parts) or "]" in "".join(parts):
        raise ValueError("صيغة الأقواس غير صحيحة")
    return parts, choices


def generate_urls(pattern: str, limit: int):
    parts, choices = parse_pattern(pattern)
    total = 1
    for choice in choices:
        total *= len(choice)
        if total > limit:
            raise ValueError(f"النمط يولّد أكثر من الحد الأقصى ({limit:,})؛ قلّل النطاق أو ارفع --max-urls")
    for values in itertools.product(*choices):
        yield "".join(piece for pair in itertools.zip_longest(parts, values, fillvalue="") for piece in pair)


def validate_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"رابط غير صالح (يجب أن يبدأ بـ http:// أو https://): {url}")


async def check_url(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    timeout: float,
    valid_keywords: list[str] = DEFAULT_VALID_KEYWORDS,
    error_keywords: list[str] = DEFAULT_ERROR_KEYWORDS,
    verbose: bool = True,
    retries: int = 2,
    max_page_bytes: int = MAX_PAGE_BYTES,
    request_gate=None,
):
    async with semaphore:
        started = time.perf_counter()
        reason = "فشل الاتصال أو انتهت المهلة"
        status_code = None
        final_url = url
        attempt = 0
        result = None
        while attempt <= retries:
            if request_gate is not None:
                await request_gate()
            retry_delay = None
            try:
                async with client.stream("GET", url, timeout=timeout, headers=STANDARD_HEADERS) as response:
                    status_code = response.status_code
                    final_url = str(response.url)
                    if status_code in {429, 503} and attempt < retries:
                        retry_after = response.headers.get("Retry-After", "")
                        try:
                            retry_delay = float(retry_after)
                        except ValueError:
                            try:
                                date = email.utils.parsedate_to_datetime(retry_after)
                                retry_delay = max(0.0, (date - datetime.now(timezone.utc)).total_seconds())
                            except (TypeError, ValueError, OverflowError):
                                retry_delay = None
                        if retry_delay is None:
                            retry_delay = 0.5 * (2**attempt) + random.uniform(0.0, 0.15)
                        retry_delay = min(max(retry_delay, 0.0), 8.0)
                    elif status_code >= 400:
                        reason = f"HTTP {status_code}"
                    else:
                        chunks = bytearray()
                        async for chunk in response.aiter_bytes():
                            chunks.extend(chunk[: max_page_bytes - len(chunks)])
                            if len(chunks) >= max_page_bytes:
                                break
                        encoding = response.encoding or "utf-8"
                        html = bytes(chunks).decode(encoding, errors="replace")
                        soup = BeautifulSoup(html, "html.parser")
                        for node in soup(["script", "style", "noscript", "template"]):
                            node.decompose()
                        page_text = soup.get_text(separator=" ", strip=True).casefold()
                        bad = next((word for word in error_keywords if word.casefold() in page_text), None)
                        good = next((word for word in valid_keywords if word.casefold() in page_text), None)
                        if bad:
                            reason = f"إشارة رفض: {bad}"
                        elif good:
                            result = {
                                "url": url, "final_url": final_url, "status": "valid",
                                "status_code": status_code,
                                "reason": f"إشارة قبول: {good}",
                            }
                            break
                        else:
                            reason = "لم يتم العثور على إشارة قبول"
                        break
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt >= retries:
                    reason = f"فشل الاتصال أو انتهت المهلة ({type(exc).__name__})"
                    break
                retry_delay = 0.5 * (2**attempt) + random.uniform(0.0, 0.15)
            except httpx.HTTPError as exc:
                reason = f"فشل الاتصال ({type(exc).__name__})"
                break

            if retry_delay is not None:
                await asyncio.sleep(retry_delay)
                attempt += 1
                continue
            break
        else:
            reason = f"HTTP {status_code}" if status_code is not None else reason

        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        if result is None:
            result = {
                "url": url, "final_url": final_url, "status": "error",
                "status_code": status_code, "reason": reason,
            }
        result["latency_ms"] = elapsed_ms
        result["attempts"] = attempt + 1
        result["checked_at"] = datetime.now(timezone.utc).isoformat()
        if verbose:
            print(f"[{result['status']}] {url}: {result['reason']}")
        return result


async def run(args: argparse.Namespace) -> int:
    urls = list(generate_urls(args.pattern, args.max_urls))
    for url in urls:
        validate_url(url)
    semaphore = asyncio.Semaphore(args.concurrency)
    count = valid_count = 0
    output = Path(args.output)
    headers = STANDARD_HEADERS
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
        with output.open("w", encoding="utf-8", newline="\n") as file:
            tasks = set()
            for url in urls:
                count += 1
                tasks.add(asyncio.create_task(check_url(client, url, semaphore, args.timeout, args.valid_keywords, args.error_keywords)))
                if len(tasks) >= args.concurrency * 2:
                    done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    for task in done:
                        result = task.result()
                        if result["status"] == "valid":
                            file.write(result["url"] + "\n")
                            file.flush()
                            valid_count += 1
            for task in asyncio.as_completed(tasks):
                result = await task
                if result["status"] == "valid":
                    file.write(result["url"] + "\n")
                    file.flush()
                    valid_count += 1
    print(f"\nاكتمل الفحص: {count} رابط، {valid_count} صالح. النتائج: {output.resolve()}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="توسيع أنماط الروابط وفحص المتاح منها")
    parser.add_argument("pattern", help='مثال: "https://example.com/offer/[001-100]-[a-c]"')
    parser.add_argument("-o", "--output", default="valid_links.txt", help="ملف حفظ الروابط الصالحة")
    parser.add_argument("-c", "--concurrency", type=int, default=20, help="عدد الطلبات المتزامنة (افتراضي 20)")
    parser.add_argument("-t", "--timeout", type=float, default=5, help="مهلة كل طلب بالثواني")
    parser.add_argument("--max-urls", type=int, default=10_000, help="حد أعلى لتوليد الروابط (افتراضي 10000)")
    parser.add_argument("--valid-keywords", default=",".join(DEFAULT_VALID_KEYWORDS), help="إشارات القبول مفصولة بفواصل")
    parser.add_argument("--error-keywords", default=",".join(DEFAULT_ERROR_KEYWORDS), help="إشارات الرفض مفصولة بفواصل")
    args = parser.parse_args()
    if args.concurrency < 1 or args.timeout <= 0 or args.max_urls < 1:
        parser.error("يجب أن تكون concurrency وmax-urls موجبتين والمهلة أكبر من صفر")
    args.valid_keywords = [word.strip() for word in args.valid_keywords.split(",") if word.strip()]
    args.error_keywords = [word.strip() for word in args.error_keywords.split(",") if word.strip()]
    try:
        return asyncio.run(run(args))
    except (ValueError, httpx.HTTPError, OSError) as exc:
        print(f"خطأ: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
