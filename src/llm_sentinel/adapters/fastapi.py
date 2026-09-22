"""FastAPI middleware: scan request and response bodies through a Vault.

Drop-in example:
    from fastapi import FastAPI
    from llm_sentinel import Vault, default_scanners
    from llm_sentinel.adapters.fastapi import SentinelMiddleware

    app = FastAPI()
    app.add_middleware(
        SentinelMiddleware,
        vault=Vault(default_scanners()),
        block_status_code=400,
    )

Request bodies are scanned before they reach your route; response bodies
are scanned on the way out. When a scan blocks, the middleware
short-circuits with ``block_status_code`` instead of calling your handler
(requests) or returning the body (responses).

This is intentionally thin: it reads bodies as text and scans the whole
thing. For large file uploads or streaming responses, scope the middleware
to the routes that handle prompts (``include_paths``) instead of the
whole app.
"""

from __future__ import annotations

from ..vault import Vault

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse, Response

    _HAVE_STARLETTE = True
except ImportError:  # pragma: no cover
    _HAVE_STARLETTE = False


class SentinelMiddleware(BaseHTTPMiddleware if _HAVE_STARLETTE else object):
    """Starlette/FastAPI middleware applying a Vault to request/response bodies."""

    def __init__(
        self,
        app,
        vault: Vault,
        *,
        block_status_code: int = 400,
        scan_requests: bool = True,
        scan_responses: bool = True,
        include_paths: list[str] | None = None,
        redact: bool = False,
    ) -> None:
        if not _HAVE_STARLETTE:  # pragma: no cover
            raise ImportError(
                "SentinelMiddleware needs starlette/fastapi installed: "
                "pip install llm-sentinel[fastapi]"
            )
        super().__init__(app)
        self.vault = vault
        self.block_status_code = block_status_code
        self.scan_requests = scan_requests
        self.scan_responses = scan_responses
        self.include_paths = include_paths
        self.redact = redact

    def _path_included(self, path: str) -> bool:
        return self.include_paths is None or any(path.startswith(p) for p in self.include_paths)

    def _blocked_response(self) -> JSONResponse:
        return JSONResponse(
            {"detail": "Blocked by llm-sentinel guardrails"},
            status_code=self.block_status_code,
        )

    async def dispatch(self, request, call_next):  # type: ignore[override]
        if not self._path_included(request.url.path):
            return await call_next(request)

        if self.scan_requests:
            body = await request.body()
            text = body.decode("utf-8", errors="ignore")
            if text and self.vault.scan(text).blocked:
                return self._blocked_response()

        response = await call_next(request)

        if self.scan_responses:
            chunks = [chunk async for chunk in response.body_iterator]
            body = b"".join(chunks)
            text = body.decode("utf-8", errors="ignore")
            if text:
                result = self.vault.scan(text, redact=self.redact)
                if result.blocked and not self.redact:
                    return self._blocked_response()
                if self.redact and result.redacted_text is not None:
                    body = result.redacted_text.encode("utf-8")
            return Response(
                content=body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )
        return response
