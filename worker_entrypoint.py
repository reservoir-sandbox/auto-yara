#!/usr/bin/env python3
"""K8s Job entrypoint: pull a sample from S3, generate a YARA rule for it,
upload the report, and report back to the backend callback API.

Env var contract mirrors the reverse repo's elf_analyzer.py worker so all
three analysis workers (reverse/static, auto-yara/sandbox, ml-models/ml) are
launched identically by charts/job-to-run in gitops-deployment.
"""
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import aioboto3
import aiohttp

from byte_pattern_extractor import extract_byte_patterns
from feature_extractor import extract_imports, extract_metadata, extract_strings
from main import build_rule_from_features, get_rodata_entropy_label
from string_filter import filter_strings, load_whitelist
from suspicious_imports import detect_suspicious_combinations

WHITELIST_PATH = os.getenv("WHITELIST_PATH", "whitelist/clean_strings.txt")
INLINE_RESULT_THRESHOLD_BYTES = 1024 * 1024


def get_iso_time() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def generate_report(elf_path: str, task_id: str) -> dict:
    whitelist = load_whitelist(WHITELIST_PATH)
    raw_strings = extract_strings(elf_path)
    filtered = filter_strings(raw_strings, whitelist)
    imports = extract_imports(elf_path)
    byte_patterns = extract_byte_patterns(elf_path)

    builder = build_rule_from_features(elf_path, f"task_{task_id}", filtered)
    rule_text = builder.build()
    rule_valid = builder.validate()

    return {
        "yara_rule": rule_text,
        "rule_valid": rule_valid,
        "metadata": extract_metadata(elf_path),
        "rodata_entropy": get_rodata_entropy_label(elf_path),
        "imports": imports,
        "suspicious_imports": detect_suspicious_combinations(imports),
        "strings_filtered": filtered,
        "byte_patterns_count": len(byte_patterns["patterns"]),
    }


async def send_error_callback(url: str, headers: dict, error_msg: str, started_at: str):
    finished_at = get_iso_time()
    error_payload = {
        "status": "failed",
        "error": error_msg,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    timeout = aiohttp.ClientTimeout(total=30)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as http_session:
            await http_session.post(url, headers=headers, json=error_payload)
    except Exception as network_err:
        print(f"Failed to deliver error callback: {network_err}")


async def main():
    started_at = get_iso_time()

    ACCESS_KEY = os.getenv("S3_ACCESS_KEY")
    SECRET_KEY = os.getenv("S3_SECRET_KEY")
    ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL")
    BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

    BACKEND_CALLBACK_URL = os.getenv("BACKEND_CALLBACK_URL")
    WORKER_CALLBACK_SECRET = os.getenv("WORKER_CALLBACK_SECRET")
    TASK_ID = os.getenv("TASK_ID")
    S3_OBJECT_KEY = os.getenv("S3_OBJECT_KEY")

    if not all([ACCESS_KEY, SECRET_KEY, ENDPOINT_URL, BUCKET_NAME, BACKEND_CALLBACK_URL, WORKER_CALLBACK_SECRET, TASK_ID, S3_OBJECT_KEY]):
        print(json.dumps({"error": "Critical configuration missing from environment variables."}))
        sys.exit(1)

    if not BACKEND_CALLBACK_URL.endswith("/callback"):
        callback_url = f"{BACKEND_CALLBACK_URL.rstrip('/')}/api/v1/internal/tasks/{TASK_ID}/callback"
    else:
        callback_url = BACKEND_CALLBACK_URL

    http_headers = {
        "X-Worker-Token": WORKER_CALLBACK_SECRET,
        "Content-Type": "application/json",
    }

    temp_file = Path(f"/tmp/{TASK_ID}.elf")
    session = aioboto3.Session()

    try:
        async with session.client(
            "s3", endpoint_url=ENDPOINT_URL, aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY, region_name="local-cluster"
        ) as s3:
            await s3.download_file(Bucket=BUCKET_NAME, Key=S3_OBJECT_KEY, Filename=str(temp_file))

        report = await asyncio.wait_for(
            asyncio.to_thread(generate_report, str(temp_file), TASK_ID),
            timeout=300.0,
        )

        json_string = json.dumps(report)
        payload_bytes = json_string.encode("utf-8")
        finished_at = get_iso_time()

        callback_payload = {
            "status": "completed",
            "started_at": started_at,
            "finished_at": finished_at,
        }

        if len(payload_bytes) <= INLINE_RESULT_THRESHOLD_BYTES:
            callback_payload["result"] = report
        else:
            output_report_key = f"reports/{TASK_ID}_report.json"
            async with session.client(
                "s3", endpoint_url=ENDPOINT_URL, aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY, region_name="local-cluster"
            ) as s3:
                await s3.put_object(
                    Bucket=BUCKET_NAME, Key=output_report_key, Body=payload_bytes, ContentType="application/json"
                )
            callback_payload["report_object_name"] = output_report_key

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as http_session:
            async with http_session.post(callback_url, headers=http_headers, json=callback_payload) as response:
                if response.status not in [200, 201, 202, 204]:
                    print(f"Failed to post success callback. HTTP Status: {response.status}")
                    body = await response.text()
                    print(f"Backend response: {body}")

    except asyncio.TimeoutError:
        error_msg = "Analysis timed out (exceeded 5 minutes). Possible decompression bomb."
        print(error_msg)
        await send_error_callback(callback_url, http_headers, error_msg, started_at)
    except Exception as err:
        print(f"Execution Error: {err}")
        await send_error_callback(callback_url, http_headers, str(err), started_at)
        sys.exit(1)
    finally:
        if temp_file.exists():
            temp_file.unlink()


if __name__ == "__main__":
    asyncio.run(main())
