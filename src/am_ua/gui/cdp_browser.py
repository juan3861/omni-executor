"""CDP Interactive DOM-Indexed Browser Organ — browser-use & Stagehand Architecture (F7).

Assimilates `browser-use/browser-use` + `browserbase/stagehand` under AetherMind Isolation & Triple-Proof Laws:
1. Isolated Browser Context Law:
   - Always launches a dedicated, isolated Chromium instance/context (`playwright.chromium.launch`)
     with its own user-data/temp directory under `F:\\AetherMind_Temp\\cdp_browser`, never polluting
     or closing the user's personal browser session.
2. Interactive DOM Tree Indexing (`DOM_INDEXER_JS`):
   - Injects a lightweight DOM/AXTree scanner into the live page that tags every visible interactive
     element (`button`, `a`, `input`, `select`, `textarea`, `[role=button]`, etc.) with
     `data-am-idx="1..N"` and extracts compact metadata (`idx`, `tag`, `type`, `text`, `label`, `bbox`).
3. Stagehand Primitives (`observe`, `act`, `extract`) + Self-Healing Selector Recovery:
   - `observe(url)`: Navigates/refreshes, indexes interactive elements, and saves BOTH the F12 DOM
     HTML dump (`dom_f12_<ts>.html`) and Visual PNG screenshot (`browser_view_<ts>.png`).
   - `act(action, idx, selector, text)`: Interacts by numeric `[idx]` or selector; if a selector breaks,
     self-heals by fuzzy-matching element text/labels from the live DOM index.
   - `extract(selector_or_mode)`: Extracts structured text, tables, links, or inputs from the live DOM.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import difflib
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional


DOM_INDEXER_JS = """
() => {
    const INTERACTIVE_SELECTOR = [
        'a[href]', 'button', 'input:not([type="hidden"])', 'textarea', 'select',
        '[role="button"]', '[role="link"]', '[role="checkbox"]', '[role="menuitem"]',
        '[role="tab"]', '[onclick]'
    ].join(',');

    const nodes = Array.from(document.querySelectorAll(INTERACTIVE_SELECTOR));
    const results = [];
    let counter = 1;

    for (const el of nodes) {
        const rect = el.getBoundingClientRect();
        const style = window.getComputedStyle(el);
        if (rect.width < 4 || rect.height < 4) continue;
        if (style.visibility === 'hidden' || style.display === 'none' || parseFloat(style.opacity || '1') < 0.05) continue;

        const idx = counter++;
        el.setAttribute('data-am-idx', String(idx));

        const tag = el.tagName.toLowerCase();
        const type = (el.getAttribute('type') || '').toLowerCase();
        const role = el.getAttribute('role') || tag;
        const ariaLabel = el.getAttribute('aria-label') || '';
        const placeholder = el.getAttribute('placeholder') || '';
        const nameAttr = el.getAttribute('name') || el.id || '';
        const rawText = (el.innerText || el.value || ariaLabel || placeholder || nameAttr || '').trim().replace(/\\s+/g, ' ');

        results.push({
            idx: idx,
            tag: tag,
            type: type,
            role: role,
            name: nameAttr.slice(0, 80),
            text: rawText.slice(0, 140),
            placeholder: placeholder.slice(0, 80),
            href: (el.getAttribute('href') || '').slice(0, 160),
            bbox: [Math.round(rect.left), Math.round(rect.top), Math.round(rect.right), Math.round(rect.bottom)]
        });
        if (results.length >= 120) break;
    }
    return results;
}
"""


@dataclass
class IndexedDOMElement:
    """Single interactive element indexed in the live browser DOM."""

    idx: int
    tag: str
    type: str
    role: str
    name: str
    text: str
    placeholder: str
    href: str
    bbox: List[int]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CDPIndexedBrowser:
    """Isolated Playwright/CDP Browser with `browser-use` DOM indexing and Stagehand `observe`/`act`/`extract`."""

    def __init__(
        self,
        artifact_dir: Optional[Path | str] = None,
        *,
        headless: bool = True,
    ) -> None:
        self.artifact_dir = Path(
            artifact_dir or r"F:\AetherMind_Temp\cdp_browser_artifacts"
        ).resolve()
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.headless = bool(headless)
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self.last_elements: Dict[int, IndexedDOMElement] = {}
        self.last_observation: Optional[Dict[str, Any]] = None
        self.receipts: List[Dict[str, Any]] = []

    def _ensure_page(self) -> Any:
        if self._page is not None:
            return self._page
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=self.headless,
            args=["--disable-blink-features=AutomationControlled"],
        )
        self._context = self._browser.new_context(viewport={"width": 1280, "height": 800})
        self._page = self._context.new_page()
        return self._page

    def observe(self, url: Optional[str] = None, *, wait_ms: int = 200) -> Dict[str, Any]:
        """Navigate (if `url` given), index all interactive DOM elements `[1..N]`, and save F12 + Visual proof."""
        page = self._ensure_page()
        if url:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
        if wait_ms > 0:
            page.wait_for_timeout(wait_ms)

        raw_items = page.evaluate(DOM_INDEXER_JS) or []
        indexed: List[IndexedDOMElement] = [
            IndexedDOMElement(
                idx=int(item["idx"]),
                tag=str(item.get("tag", "")),
                type=str(item.get("type", "")),
                role=str(item.get("role", "")),
                name=str(item.get("name", "")),
                text=str(item.get("text", "")),
                placeholder=str(item.get("placeholder", "")),
                href=str(item.get("href", "")),
                bbox=list(item.get("bbox", [0, 0, 0, 0])),
            )
            for item in raw_items
        ]
        self.last_elements = {el.idx: el for el in indexed}

        ts = int(time.time() * 1000)
        html_path = self.artifact_dir / f"dom_f12_{ts}.html"
        png_path = self.artifact_dir / f"browser_view_{ts}.png"

        html_content = page.content()
        html_path.write_text(html_content, encoding="utf-8", errors="replace")
        page.screenshot(path=str(png_path), full_page=False)

        obs = {
            "ok": True,
            "url": page.url,
            "title": page.title(),
            "element_count": len(indexed),
            "elements": [el.to_dict() for el in indexed],
            "f12_dom_path": str(html_path),
            "f12_dom_bytes": html_path.stat().st_size,
            "visual_screenshot_path": str(png_path),
            "visual_screenshot_bytes": png_path.stat().st_size,
        }
        self.last_observation = obs
        return obs

    def _self_heal_resolve_idx(self, query_or_selector: str) -> Optional[int]:
        """Find best matching `data-am-idx` when a CSS selector or text description is given."""
        q = (query_or_selector or "").strip().lower()
        if not q:
            return None
        best_score = 0.0
        best_idx: Optional[int] = None
        for idx, el in self.last_elements.items():
            hay = f"{el.text} {el.name} {el.placeholder} {el.href}".strip().lower()
            if not hay:
                continue
            if q == el.text.lower() or q == el.name.lower():
                return idx
            if q in hay:
                score = 0.9
            else:
                score = difflib.SequenceMatcher(None, q, hay).ratio()
            if score > best_score and score >= 0.6:
                best_score = score
                best_idx = idx
        return best_idx

    def act(
        self,
        action: str,
        *,
        idx: Optional[int] = None,
        target: Optional[str] = None,
        text: Optional[str] = None,
        url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Stagehand/browser-use `act` primitive with self-healing selector recovery and Triple Proof."""
        page = self._ensure_page()
        t0 = time.perf_counter()
        act_name = action.lower().strip()

        if act_name == "goto" and (url or target):
            obs = self.observe(url=url or target)
            return {"ok": True, "action": "goto", "observation": obs}

        if not self.last_elements:
            self.observe(wait_ms=50)

        resolved_idx = int(idx) if idx is not None else None
        self_healed = False
        locator_str = f'[data-am-idx="{resolved_idx}"]' if resolved_idx is not None else (target or "")

        try:
            if resolved_idx is None and target:
                # Check if target CSS selector exists directly; otherwise self-heal via DOM index
                if page.locator(target).count() == 0:
                    healed_idx = self._self_heal_resolve_idx(target)
                    if healed_idx is not None:
                        resolved_idx = healed_idx
                        locator_str = f'[data-am-idx="{resolved_idx}"]'
                        self_healed = True

            if act_name == "click":
                page.locator(locator_str).first.click(timeout=5000)
            elif act_name in ("fill", "type"):
                page.locator(locator_str).first.fill(str(text or ""), timeout=5000)
            elif act_name == "select":
                page.locator(locator_str).first.select_option(str(text or ""), timeout=5000)
            elif act_name == "press":
                if locator_str:
                    page.locator(locator_str).first.press(str(text or "Enter"), timeout=5000)
                else:
                    page.keyboard.press(str(text or "Enter"))
            else:
                return {"ok": False, "error": f"Unsupported browser action: {action!r}"}
        except Exception as exc:
            # Final self-healing attempt if initial CSS selector failed on click/fill
            healed_idx = self._self_heal_resolve_idx(target or "")
            if healed_idx is not None and not self_healed:
                locator_str = f'[data-am-idx="{healed_idx}"]'
                self_healed = True
                if act_name == "click":
                    page.locator(locator_str).first.click(timeout=5000)
                elif act_name in ("fill", "type"):
                    page.locator(locator_str).first.fill(str(text or ""), timeout=5000)
            else:
                return {"ok": False, "action": act_name, "locator": locator_str, "error": str(exc)}

        post_obs = self.observe(wait_ms=100)
        receipt = {
            "schema": "BROWSER_PAF_RECEIPT/v1",
            "timestamp": time.time(),
            "action": act_name,
            "locator_used": locator_str,
            "self_healed": self_healed,
            "url_after": post_obs["url"],
            "f12_dom_path": post_obs["f12_dom_path"],
            "visual_screenshot_path": post_obs["visual_screenshot_path"],
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }
        receipt["receipt_digest"] = hashlib.sha256(
            json.dumps(receipt, sort_keys=True).encode("utf-8")
        ).hexdigest()
        self.receipts.append(receipt)
        return {"ok": True, "receipt": receipt, "observation": post_obs}

    def extract(self, selector: str = "body") -> Dict[str, Any]:
        """Stagehand `extract` primitive: extract text and structured attributes from the live DOM."""
        page = self._ensure_page()
        try:
            loc = page.locator(selector).first
            text = loc.inner_text(timeout=5000)
            html = loc.inner_html(timeout=5000)
            return {
                "ok": True,
                "url": page.url,
                "selector": selector,
                "text": text.strip(),
                "html_length": len(html),
            }
        except Exception as exc:
            return {"ok": False, "selector": selector, "error": str(exc)}

    def close(self) -> None:
        """Close ONLY the agent's isolated browser context and instance."""
        for obj in (self._page, self._context, self._browser):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass
        if self._pw is not None:
            try:
                self._pw.stop()
            except Exception:
                pass
        self._page = self._context = self._browser = self._pw = None

    def __enter__(self) -> "CDPIndexedBrowser":
        self._ensure_page()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
