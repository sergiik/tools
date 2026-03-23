#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Harbor full config exporter (best-effort, read-only).

Что делает:
- Экспортирует system configuration
- Экспортирует все проекты
- Экспортирует связанные сущности проектов
- Пробует вычитать глобальные сущности Harbor через набор candidate endpoints
- Складывает всё в единый JSON snapshot

Почему "best-effort":
- у Harbor нет одного штатного full-export endpoint
- часть endpoint'ов зависит от версии Harbor
- некоторые сущности/поля могут требовать дополнительных прав
- часть секретов Harbor обратно не возвращает в полном виде

Требования:
    pip install requests

Примеры запуска:
    python3 harbor_export.py \
      --url https://harbor.example.com \
      --username admin \
      --password 'SuperSecret' \
      --output harbor-full-export.json

    HARBOR_URL=https://harbor.example.com \
    HARBOR_USERNAME=admin \
    HARBOR_PASSWORD=SuperSecret \
    python3 harbor_export.py

Опционально:
    --insecure            отключить TLS verify
    --page-size 100       размер страницы для list endpoints
    --timeout 30          HTTP timeout
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

DEFAULT_PAGE_SIZE = 100
DEFAULT_TIMEOUT = 30

# Endpoints, которые официально и стабильно ожидаем в Harbor v2 API.
# Остальные candidate endpoints ниже уже best-effort по версиям.
STABLE_ENDPOINTS = {
    "health": "/api/v2.0/health",
    "system_config": "/api/v2.0/configurations",
    "projects": "/api/v2.0/projects",
}

# Candidate endpoints для глобальных сущностей.
# Скрипт пробует по очереди; успешные результаты попадают в export,
# ошибки и 404 — в errors.
GLOBAL_CANDIDATE_ENDPOINTS = {
    "registries": [
        "/api/v2.0/registries",
    ],
    "replication_policies": [
        "/api/v2.0/replication/policies",
    ],
    "replication_executions": [
        "/api/v2.0/replication/executions",
    ],
    "scanners": [
        "/api/v2.0/scanners",
    ],
    "scanner_registrations": [
        "/api/v2.0/scanner/registrations",
    ],
    "system_robot_accounts": [
        "/api/v2.0/robots",
    ],
    "labels_global": [
        "/api/v2.0/labels?scope=g",
        "/api/v2.0/labels",
    ],
    "ldap_groups_search_schema_hint": [
        # Обычно этот endpoint требует параметры поиска и не нужен для экспорта,
        # поэтому оставляем пустым; просто показываем, что его можно расширить вручную.
    ],
}

# Candidate endpoints для project-scoped сущностей.
PROJECT_CANDIDATE_ENDPOINTS = {
    "detail": [
        "/api/v2.0/projects/{project_id}",
    ],
    "summary": [
        "/api/v2.0/projects/{project_id}/summary",
    ],
    "metadata": [
        "/api/v2.0/projects/{project_id}/metadatas",
        "/api/v2.0/projects/{project_id}/metadatas/",
    ],
    "members": [
        "/api/v2.0/projects/{project_id}/members",
    ],
    "labels": [
        "/api/v2.0/labels?scope=p&project_id={project_id}",
        "/api/v2.0/projects/{project_id}/labels",
    ],
    "robots": [
        "/api/v2.0/projects/{project_id}/robots",
    ],
    "immutable_tag_rules": [
        "/api/v2.0/projects/{project_id}/immutabletagrules",
        "/api/v2.0/projects/{project_id}/immutable-tag-rules",
    ],
    "webhook_policies": [
        "/api/v2.0/projects/{project_id}/webhook/policies",
        "/api/v2.0/projects/{project_id}/webhook/policies/",
    ],
    "retentions": [
        "/api/v2.0/retentions?scope=project&scope_id={project_id}",
        "/api/v2.0/retentions?scope_id={project_id}",
        "/api/v2.0/projects/{project_id}/retentions",
    ],
    "quotas": [
        "/api/v2.0/quotas?reference=project&reference_id={project_id}",
        "/api/v2.0/quotas?reference_type=project&reference_id={project_id}",
    ],
    "cves_allowlist": [
        "/api/v2.0/projects/{project_id}/scanner/CVEAllowlist",
        "/api/v2.0/projects/{project_id}/scanner/CVEAllowlist/",
    ],
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export Harbor config into one JSON snapshot")
    parser.add_argument("--url", default=os.getenv("HARBOR_URL", "").strip(), help="Harbor base URL, e.g. https://harbor.example.com")
    parser.add_argument("--username", default=os.getenv("HARBOR_USERNAME", "").strip(), help="Harbor username")
    parser.add_argument("--password", default=os.getenv("HARBOR_PASSWORD", "").strip(), help="Harbor password")
    parser.add_argument("--output", default=os.getenv("HARBOR_OUTPUT", "harbor-full-export.json"), help="Output JSON file")
    parser.add_argument("--page-size", type=int, default=int(os.getenv("HARBOR_PAGE_SIZE", str(DEFAULT_PAGE_SIZE))), help="Page size for paginated endpoints")
    parser.add_argument("--timeout", type=int, default=int(os.getenv("HARBOR_TIMEOUT", str(DEFAULT_TIMEOUT))), help="HTTP timeout in seconds")
    parser.add_argument("--insecure", action="store_true", default=os.getenv("HARBOR_INSECURE", "").lower() in {"1", "true", "yes"}, help="Disable TLS certificate verification")
    return parser.parse_args()


class HarborClient:
    def __init__(self, base_url: str, username: str, password: str, verify_tls: bool, timeout: int):
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = verify_tls
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "harbor-exporter/1.0",
        })

    def _full_url(self, path: str) -> str:
        return urljoin(self.base_url + "/", path.lstrip("/"))

    def get_raw(self, path: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        url = self._full_url(path)
        return self.session.get(url, params=params, timeout=self.timeout)

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        response = self.get_raw(path, params=params)
        response.raise_for_status()
        if not response.text:
            return None
        if response.status_code == 204:
            return None
        content_type = response.headers.get("Content-Type", "")
        if "application/json" not in content_type and response.text.strip() and not response.text.strip().startswith(("{", "[")):
            return {"_raw_text": response.text}
        return response.json()

    def get_json_optional(self, path: str, params: Optional[Dict[str, Any]] = None) -> Tuple[bool, Any, Optional[Dict[str, Any]]]:
        try:
            response = self.get_raw(path, params=params)
            if response.status_code in (404, 405):
                return False, None, {
                    "status": response.status_code,
                    "path": path,
                    "params": params,
                    "message": "endpoint not available on this Harbor version or method not allowed",
                }
            if response.status_code == 403:
                return False, None, {
                    "status": response.status_code,
                    "path": path,
                    "params": params,
                    "message": "forbidden",
                }
            if response.status_code == 401:
                return False, None, {
                    "status": response.status_code,
                    "path": path,
                    "params": params,
                    "message": "unauthorized",
                }
            response.raise_for_status()
            if not response.text:
                return True, None, None
            content_type = response.headers.get("Content-Type", "")
            if "application/json" not in content_type and response.text.strip() and not response.text.strip().startswith(("{", "[")):
                return True, {"_raw_text": response.text}, None
            return True, response.json(), None
        except RequestException as exc:
            return False, None, {
                "status": "request_error",
                "path": path,
                "params": params,
                "message": str(exc),
            }

    def list_paginated(self, path: str, page_size: int = DEFAULT_PAGE_SIZE, extra_params: Optional[Dict[str, Any]] = None) -> List[Any]:
        results: List[Any] = []
        page = 1
        while True:
            params = {"page": page, "page_size": page_size}
            if extra_params:
                params.update(extra_params)
            response = self.get_raw(path, params=params)
            response.raise_for_status()
            data = response.json() if response.text else []
            if isinstance(data, dict):
                # Некоторые endpoints могут вернуть объект, а не массив.
                results.append(data)
                break
            if not isinstance(data, list):
                break
            results.extend(data)
            if len(data) < page_size:
                break
            page += 1
        return results

    def list_paginated_optional(self, path: str, page_size: int = DEFAULT_PAGE_SIZE, extra_params: Optional[Dict[str, Any]] = None) -> Tuple[bool, Any, Optional[Dict[str, Any]]]:
        results: List[Any] = []
        page = 1
        while True:
            params = {"page": page, "page_size": page_size}
            if extra_params:
                params.update(extra_params)
            try:
                response = self.get_raw(path, params=params)
                if response.status_code in (404, 405):
                    return False, None, {
                        "status": response.status_code,
                        "path": path,
                        "params": params,
                        "message": "endpoint not available on this Harbor version or method not allowed",
                    }
                if response.status_code == 403:
                    return False, None, {
                        "status": response.status_code,
                        "path": path,
                        "params": params,
                        "message": "forbidden",
                    }
                if response.status_code == 401:
                    return False, None, {
                        "status": response.status_code,
                        "path": path,
                        "params": params,
                        "message": "unauthorized",
                    }
                response.raise_for_status()
                data = response.json() if response.text else []
                if isinstance(data, dict):
                    results.append(data)
                    return True, results, None
                if not isinstance(data, list):
                    return True, results, None
                results.extend(data)
                if len(data) < page_size:
                    return True, results, None
                page += 1
            except RequestException as exc:
                return False, None, {
                    "status": "request_error",
                    "path": path,
                    "params": params,
                    "message": str(exc),
                }


def normalize_project_id(project_obj: Dict[str, Any]) -> Optional[int]:
    for key in ("project_id", "projectId", "id"):
        if key in project_obj and project_obj[key] is not None:
            try:
                return int(project_obj[key])
            except (TypeError, ValueError):
                return None
    return None


def normalize_project_name(project_obj: Dict[str, Any]) -> Optional[str]:
    for key in ("name", "project_name", "projectName"):
        value = project_obj.get(key)
        if isinstance(value, str) and value:
            return value
    metadata = project_obj.get("metadata")
    if isinstance(metadata, dict):
        for key in ("project_name", "name"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def fetch_first_success_paginated(
    client: HarborClient,
    candidates: List[str],
    page_size: int,
    errors: List[Dict[str, Any]],
) -> Tuple[Optional[str], Any]:
    for path in candidates:
        ok, data, err = client.list_paginated_optional(path, page_size=page_size)
        if ok:
            return path, data
        if err:
            errors.append(err)
    return None, None


def fetch_first_success_json(
    client: HarborClient,
    candidates: List[str],
    errors: List[Dict[str, Any]],
) -> Tuple[Optional[str], Any]:
    for path in candidates:
        ok, data, err = client.get_json_optional(path)
        if ok:
            return path, data
        if err:
            errors.append(err)
    return None, None


def export_global_entities(client: HarborClient, page_size: int, errors: List[Dict[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for entity_name, candidates in GLOBAL_CANDIDATE_ENDPOINTS.items():
        if not candidates:
            result[entity_name] = {
                "endpoint_used": None,
                "items": None,
                "note": "no default candidate endpoints configured in exporter",
            }
            continue

        endpoint_used, items = fetch_first_success_paginated(client, candidates, page_size, errors)
        if endpoint_used is None:
            endpoint_used, items = fetch_first_success_json(client, candidates, errors)

        result[entity_name] = {
            "endpoint_used": endpoint_used,
            "items": items,
        }
    return result


def export_projects(client: HarborClient, page_size: int, errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    projects = client.list_paginated(
        STABLE_ENDPOINTS["projects"],
        page_size=page_size,
        extra_params={"with_detail": "true"},
    )

    exported_projects: List[Dict[str, Any]] = []

    for project in projects:
        if not isinstance(project, dict):
            exported_projects.append({
                "raw": project,
                "error": "project item is not a dict",
            })
            continue

        project_id = normalize_project_id(project)
        project_name = normalize_project_name(project)

        entry: Dict[str, Any] = {
            "project_id": project_id,
            "project_name": project_name,
            "project": project,
            "detail": {"endpoint_used": None, "items": None},
            "summary": {"endpoint_used": None, "items": None},
            "metadata": {"endpoint_used": None, "items": None},
            "members": {"endpoint_used": None, "items": None},
            "labels": {"endpoint_used": None, "items": None},
            "robots": {"endpoint_used": None, "items": None},
            "immutable_tag_rules": {"endpoint_used": None, "items": None},
            "webhook_policies": {"endpoint_used": None, "items": None},
            "retentions": {"endpoint_used": None, "items": None},
            "quotas": {"endpoint_used": None, "items": None},
            "cves_allowlist": {"endpoint_used": None, "items": None},
        }

        if project_id is None:
            entry["error"] = "cannot determine project_id"
            exported_projects.append(entry)
            continue

        for section_name, candidates in PROJECT_CANDIDATE_ENDPOINTS.items():
            rendered_candidates = [c.format(project_id=project_id) for c in candidates]

            # Какие секции почти наверняка paginated/list
            if section_name in {"members", "robots", "webhook_policies", "immutable_tag_rules", "labels", "retentions", "quotas"}:
                endpoint_used, items = fetch_first_success_paginated(client, rendered_candidates, page_size, errors)
                if endpoint_used is None:
                    endpoint_used, items = fetch_first_success_json(client, rendered_candidates, errors)
            else:
                endpoint_used, items = fetch_first_success_json(client, rendered_candidates, errors)
                if endpoint_used is None:
                    endpoint_used, items = fetch_first_success_paginated(client, rendered_candidates, page_size, errors)

            entry[section_name] = {
                "endpoint_used": endpoint_used,
                "items": items,
            }

        exported_projects.append(entry)

    return exported_projects


def validate_inputs(args: argparse.Namespace) -> None:
    missing = []
    if not args.url:
        missing.append("--url or HARBOR_URL")
    if not args.username:
        missing.append("--username or HARBOR_USERNAME")
    if not args.password:
        missing.append("--password or HARBOR_PASSWORD")
    if missing:
        print("Missing required parameters:", ", ".join(missing), file=sys.stderr)
        sys.exit(2)


def main() -> int:
    args = parse_args()
    validate_inputs(args)

    client = HarborClient(
        base_url=args.url,
        username=args.username,
        password=args.password,
        verify_tls=not args.insecure,
        timeout=args.timeout,
    )

    started_at = time.time()
    errors: List[Dict[str, Any]] = []

    export: Dict[str, Any] = {
        "meta": {
            "harbor_url": args.url.rstrip("/"),
            "exported_at": utc_now_iso(),
            "tool": "harbor-exporter/1.0",
            "page_size": args.page_size,
            "timeout_seconds": args.timeout,
            "tls_verify": not args.insecure,
        },
        "health": None,
        "system_configuration": None,
        "projects": [],
        "globals": {},
        "errors": errors,
    }

    # Health
    try:
        export["health"] = client.get_json(STABLE_ENDPOINTS["health"])
    except RequestException as exc:
        errors.append({
            "status": "request_error",
            "path": STABLE_ENDPOINTS["health"],
            "params": None,
            "message": f"health check failed: {exc}",
        })

    # System configuration
    try:
        export["system_configuration"] = client.get_json(STABLE_ENDPOINTS["system_config"])
    except RequestException as exc:
        errors.append({
            "status": "request_error",
            "path": STABLE_ENDPOINTS["system_config"],
            "params": None,
            "message": f"system configuration export failed: {exc}",
        })

    # Projects and project-scoped entities
    try:
        export["projects"] = export_projects(client, args.page_size, errors)
    except RequestException as exc:
        errors.append({
            "status": "request_error",
            "path": STABLE_ENDPOINTS["projects"],
            "params": {"with_detail": "true"},
            "message": f"project export failed: {exc}",
        })

    # Global entities
    export["globals"] = export_global_entities(client, args.page_size, errors)

    export["meta"]["duration_seconds"] = round(time.time() - started_at, 3)
    export["meta"]["project_count"] = len(export["projects"])
    export["meta"]["error_count"] = len(errors)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(export, f, ensure_ascii=False, indent=2, sort_keys=False)

    print(f"Export completed: {args.output}")
    print(f"Projects exported: {export['meta']['project_count']}")
    print(f"Errors recorded:   {export['meta']['error_count']}")

    if errors:
        print("\nSome endpoints were unavailable or forbidden on this Harbor instance/version.")
        print("Review the 'errors' section in the output JSON.")

    return 0


if __name__ == "__main__":
    sys.exit(main())