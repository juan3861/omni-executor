"""AM-Bench task registry (eval/ is constitutionally sealed: the agent cannot edit the benchmark).

Every task has:
  * `files`        - initial workspace contents
  * `visible`      - tests the agent may run while working (exposed via the acceptance command)
  * `hidden`       - stricter tests copied into the workspace ONLY after the agent finishes (SWE-bench style)
Passing requires: hidden tests exit 0 AND visible test files are byte-identical (anti-tamper).
Desktop tasks additionally spawn a GUI fixture whose secret never touches the workspace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

PY = r"C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe"
PYTEST_VISIBLE = f'& "{PY}" -m pytest -q -p no:cacheprovider tests_visible'


@dataclass(frozen=True)
class BenchTask:
    task_id: str
    category: str  # "code" | "desktop"
    objective: str
    files: Dict[str, str] = field(default_factory=dict)
    visible: Dict[str, str] = field(default_factory=dict)
    hidden: Dict[str, str] = field(default_factory=dict)
    gui_mode: Optional[str] = None
    max_turns: int = 20


HDR = "import sys, pathlib\nsys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))\n"


def _t(body: str) -> str:
    return HDR + body.strip() + "\n"


CODE_TASKS = [
    BenchTask(
        "c01_off_by_one", "code",
        "Fix the bug in lists.py: last_n(xs, n) must return the last n items of xs (empty list when n <= 0).",
        files={"lists.py": "def last_n(xs, n):\n    return xs[-n-1:]\n"},
        visible={"tests_visible/test_v.py": _t("from lists import last_n\ndef test_basic():\n    assert last_n([1,2,3,4], 2) == [3,4]")},
        hidden={"tests_hidden/test_h.py": _t("from lists import last_n\ndef test_all():\n    assert last_n([1,2,3,4], 2) == [3,4]\n    assert last_n([1,2,3], 0) == []\n    assert last_n([1,2,3], -1) == []\n    assert last_n([1,2,3], 5) == [1,2,3]\n    assert last_n([], 3) == []")},
    ),
    BenchTask(
        "c02_mutable_default", "code",
        "Fix the shared-state bug in registry.py: each call to add_item without `bucket` must start from a fresh empty list.",
        files={"registry.py": "def add_item(item, bucket=[]):\n    bucket.append(item)\n    return bucket\n"},
        visible={"tests_visible/test_v.py": _t("from registry import add_item\ndef test_fresh():\n    assert add_item(1) == [1]\n    assert add_item(2) == [2]")},
        hidden={"tests_hidden/test_h.py": _t("from registry import add_item\ndef test_all():\n    assert add_item('a') == ['a']\n    assert add_item('b') == ['b']\n    b = ['x']\n    assert add_item('y', b) == ['x','y'] and b == ['x','y']")},
    ),
    BenchTask(
        "c03_slugify_unicode", "code",
        "Implement slugify(text) in text_utils.py: lowercase, strip accents (e.g. 'Ação' -> 'acao'), replace any run of non-alphanumeric chars with a single '-', and trim leading/trailing '-'.",
        files={"text_utils.py": "def slugify(text):\n    raise NotImplementedError\n"},
        visible={"tests_visible/test_v.py": _t("from text_utils import slugify\ndef test_basic():\n    assert slugify('Hello World') == 'hello-world'")},
        hidden={"tests_hidden/test_h.py": _t("from text_utils import slugify\ndef test_all():\n    assert slugify('Ação Rápida!') == 'acao-rapida'\n    assert slugify('  --Olá,   Mundo--  ') == 'ola-mundo'\n    assert slugify('São Paulo 2026') == 'sao-paulo-2026'\n    assert slugify('***') == ''")},
    ),
    BenchTask(
        "c04_money_rounding", "code",
        "Fix money.py: total(prices) receives price strings like '0.10' and must return the exact sum as a string with 2 decimals using banker-free HALF_UP rounding (e.g. ['0.105'] -> '0.11'). Avoid float errors.",
        files={"money.py": "def total(prices):\n    return '%.2f' % sum(float(p) for p in prices)\n"},
        visible={"tests_visible/test_v.py": _t("from money import total\ndef test_basic():\n    assert total(['0.10','0.20']) == '0.30'")},
        hidden={"tests_hidden/test_h.py": _t("from money import total\ndef test_all():\n    assert total(['0.10','0.20']) == '0.30'\n    assert total(['0.105']) == '0.11'\n    assert total(['2.675']) == '2.68'\n    assert total([]) == '0.00'\n    assert total(['1.005','1.005']) == '2.01'")},
    ),
    BenchTask(
        "c05_multi_file_rename", "code",
        "Rename the function calc_total to compute_total everywhere (shop/core.py, shop/cart.py, shop/report.py). Behavior must stay identical and the old name must no longer exist in core.py.",
        files={
            "shop/__init__.py": "",
            "shop/core.py": "def calc_total(items):\n    return sum(q * p for q, p in items)\n",
            "shop/cart.py": "from shop.core import calc_total\n\ndef cart_total(cart):\n    return calc_total(cart)\n",
            "shop/report.py": "from shop import core\n\ndef report(items):\n    return f'TOTAL={core.calc_total(items)}'\n",
        },
        visible={"tests_visible/test_v.py": _t("from shop.cart import cart_total\ndef test_cart():\n    assert cart_total([(2, 3)]) == 6")},
        hidden={"tests_hidden/test_h.py": _t("from shop import core\nfrom shop.cart import cart_total\nfrom shop.report import report\ndef test_all():\n    assert core.compute_total([(1,2),(3,4)]) == 14\n    assert not hasattr(core, 'calc_total')\n    assert cart_total([(2,3)]) == 6\n    assert report([(1,5)]) == 'TOTAL=5'")},
    ),
    BenchTask(
        "c06_cli_flag", "code",
        "Add an optional --upper flag to greet.py: `python greet.py NAME` prints 'Hello, NAME!' and with --upper prints it fully uppercased. Expose main(argv) returning the string as well as printing it.",
        files={"greet.py": "import argparse\n\ndef main(argv=None):\n    ap = argparse.ArgumentParser()\n    ap.add_argument('name')\n    a = ap.parse_args(argv)\n    msg = f'Hello, {a.name}!'\n    print(msg)\n    return msg\n\nif __name__ == '__main__':\n    main()\n"},
        visible={"tests_visible/test_v.py": _t("from greet import main\ndef test_plain():\n    assert main(['Ruan']) == 'Hello, Ruan!'")},
        hidden={"tests_hidden/test_h.py": _t("from greet import main\ndef test_all():\n    assert main(['Ruan']) == 'Hello, Ruan!'\n    assert main(['Ruan','--upper']) == 'HELLO, RUAN!'\n    assert main(['--upper','ana']) == 'HELLO, ANA!'")},
    ),
    BenchTask(
        "c07_fib_performance", "code",
        "fib.py computes Fibonacci exponentially. Make fib(n) return the exact value for n up to 300 in well under a second (fib(0)=0, fib(1)=1).",
        files={"fib.py": "def fib(n):\n    return n if n < 2 else fib(n-1) + fib(n-2)\n"},
        visible={"tests_visible/test_v.py": _t("from fib import fib\ndef test_small():\n    assert fib(10) == 55")},
        hidden={"tests_hidden/test_h.py": _t("import time\nfrom fib import fib\ndef test_all():\n    t=time.perf_counter()\n    assert fib(0)==0 and fib(1)==1 and fib(10)==55\n    assert fib(300) == 222232244629420445529739893461909967206666939096499764990979600\n    assert time.perf_counter()-t < 1.0")},
    ),
    BenchTask(
        "c08_csv_quotes", "code",
        "Fix parse_rows in csvparse.py: fields may be quoted and contain commas (e.g. '\"Silva, Ana\",30'). Return a list of lists of strings.",
        files={"csvparse.py": "def parse_rows(text):\n    return [line.split(',') for line in text.strip().splitlines()]\n"},
        visible={"tests_visible/test_v.py": _t("from csvparse import parse_rows\ndef test_simple():\n    assert parse_rows('a,b\\n1,2') == [['a','b'],['1','2']]")},
        hidden={"tests_hidden/test_h.py": _t("from csvparse import parse_rows\ndef test_all():\n    assert parse_rows('\"Silva, Ana\",30\\nBob,25') == [['Silva, Ana','30'],['Bob','25']]\n    assert parse_rows('x,\"say \"\"hi\"\"\"') == [['x','say \"hi\"']]")},
    ),
    BenchTask(
        "c09_br_date", "code",
        "Implement parse_br_date(s) in dates.py: parse Brazilian 'dd/mm/yyyy' into datetime.date; raise ValueError for invalid dates such as '31/02/2026' or wrong formats.",
        files={"dates.py": "def parse_br_date(s):\n    raise NotImplementedError\n"},
        visible={"tests_visible/test_v.py": _t("import datetime\nfrom dates import parse_br_date\ndef test_ok():\n    assert parse_br_date('04/11/2026') == datetime.date(2026,11,4)")},
        hidden={"tests_hidden/test_h.py": _t("import datetime, pytest\nfrom dates import parse_br_date\ndef test_all():\n    assert parse_br_date('04/11/2026') == datetime.date(2026,11,4)\n    assert parse_br_date('29/02/2024') == datetime.date(2024,2,29)\n    for bad in ['31/02/2026','2026-11-04','4/11','']:\n        with pytest.raises(ValueError):\n            parse_br_date(bad)")},
    ),
    BenchTask(
        "c10_stack_errors", "code",
        "Implement class Stack in stack.py with push(x), pop(), peek(), __len__ and is_empty(). pop()/peek() on an empty stack must raise IndexError('stack is empty').",
        files={"stack.py": "class Stack:\n    pass\n"},
        visible={"tests_visible/test_v.py": _t("from stack import Stack\ndef test_push_pop():\n    s=Stack(); s.push(1); s.push(2)\n    assert s.pop()==2 and len(s)==1")},
        hidden={"tests_hidden/test_h.py": _t("import pytest\nfrom stack import Stack\ndef test_all():\n    s=Stack()\n    assert s.is_empty() and len(s)==0\n    s.push('a'); assert s.peek()=='a' and len(s)==1\n    assert s.pop()=='a'\n    with pytest.raises(IndexError, match='stack is empty'): s.pop()\n    with pytest.raises(IndexError, match='stack is empty'): s.peek()")},
    ),
    BenchTask(
        "c11_deep_merge", "code",
        "Implement deep_merge(base, override) in config.py: returns a NEW dict where nested dicts are merged recursively and override values win; inputs must not be mutated.",
        files={"config.py": "def deep_merge(base, override):\n    raise NotImplementedError\n"},
        visible={"tests_visible/test_v.py": _t("from config import deep_merge\ndef test_flat():\n    assert deep_merge({'a':1},{'b':2}) == {'a':1,'b':2}")},
        hidden={"tests_hidden/test_h.py": _t("import copy\nfrom config import deep_merge\ndef test_all():\n    b={'db':{'host':'x','port':1},'k':[1]}; o={'db':{'port':2},'k':[2]}\n    b0,o0=copy.deepcopy(b),copy.deepcopy(o)\n    r=deep_merge(b,o)\n    assert r=={'db':{'host':'x','port':2},'k':[2]}\n    assert b==b0 and o==o0\n    r['db']['host']='y'; assert b['db']['host']=='x'")},
    ),
    BenchTask(
        "c12_email_regex", "code",
        "Fix is_valid_email in validate.py so it accepts normal addresses (dots, plus, hyphens, subdomains) and rejects missing '@', spaces, double dots, or a TLD shorter than 2 letters.",
        files={"validate.py": "import re\n\ndef is_valid_email(s):\n    return bool(re.match(r'.+@.+', s))\n"},
        visible={"tests_visible/test_v.py": _t("from validate import is_valid_email\ndef test_basic():\n    assert is_valid_email('a@b.com')\n    assert not is_valid_email('ab.com')")},
        hidden={"tests_hidden/test_h.py": _t("from validate import is_valid_email as v\ndef test_all():\n    for ok in ['ruan.p+tag@mail.example.com.br','a-b@x.io','A_1@b.co']: assert v(ok), ok\n    for bad in ['ab.com','a b@c.com','a@b','a@b.c','a..b@c.com','a@b..com','@b.com']: assert not v(bad), bad")},
    ),
    BenchTask(
        "c13_sort_key", "code",
        "Fix rank_people in people.py: sort by age descending, then by name ascending (case-insensitive).",
        files={"people.py": "def rank_people(people):\n    return sorted(people, key=lambda p: (p['age'], p['name']))\n"},
        visible={"tests_visible/test_v.py": _t("from people import rank_people\ndef test_age():\n    r=rank_people([{'name':'a','age':1},{'name':'b','age':2}])\n    assert [p['name'] for p in r]==['b','a']")},
        hidden={"tests_hidden/test_h.py": _t("from people import rank_people\ndef test_all():\n    ps=[{'name':'bob','age':30},{'name':'Ana','age':30},{'name':'carl','age':40},{'name':'alice','age':30}]\n    assert [p['name'] for p in rank_people(ps)]==['carl','alice','Ana','bob']")},
    ),
    BenchTask(
        "c14_lru_cache", "code",
        "Implement class LRUCache(capacity) in lru.py with get(key) -> value or -1 and put(key, value); evict the least recently used key when over capacity. get() counts as use.",
        files={"lru.py": "class LRUCache:\n    def __init__(self, capacity):\n        pass\n"},
        visible={"tests_visible/test_v.py": _t("from lru import LRUCache\ndef test_basic():\n    c=LRUCache(1); c.put(1,1)\n    assert c.get(1)==1")},
        hidden={"tests_hidden/test_h.py": _t("from lru import LRUCache\ndef test_all():\n    c=LRUCache(2); c.put(1,1); c.put(2,2)\n    assert c.get(1)==1\n    c.put(3,3)\n    assert c.get(2)==-1 and c.get(3)==3 and c.get(1)==1\n    c.put(1,10); c.put(4,4)\n    assert c.get(3)==-1 and c.get(1)==10 and c.get(4)==4")},
    ),
    BenchTask(
        "c15_safe_join", "code",
        "Fix safe_join(base, user_path) in paths.py: it must return the resolved absolute path inside base, and raise ValueError if the result escapes base (e.g. '../x', absolute paths, or 'a/../../x').",
        files={"paths.py": "import os\n\ndef safe_join(base, user_path):\n    return os.path.join(base, user_path)\n"},
        visible={"tests_visible/test_v.py": _t("import os\nfrom paths import safe_join\ndef test_ok(tmp_path):\n    assert safe_join(str(tmp_path), 'a.txt') == os.path.join(str(tmp_path.resolve()), 'a.txt')")},
        hidden={"tests_hidden/test_h.py": _t("import os, pytest\nfrom paths import safe_join\ndef test_all(tmp_path):\n    b=str(tmp_path)\n    assert safe_join(b,'sub/a.txt')==os.path.join(str(tmp_path.resolve()),'sub','a.txt')\n    for bad in ['../x','a/../../x', os.path.abspath(os.sep)+'Windows', 'C:\\\\Windows']:\n        with pytest.raises(ValueError): safe_join(b,bad)")},
    ),
]

DESKTOP_HINT = (
    " A desktop window titled '{title}' is open on screen (you did not create it). Use the pc_* tools "
    "(e.g. pc_observe with {{\"window_title\": \"{title}\", \"include_ocr\": true}} and pc_act) to perceive and operate it. Do not close it."
)

DESKTOP_TASKS = [
    BenchTask(
        "d01_read_secret", "desktop",
        "Read the 8-character access code displayed in the desktop window and write exactly that code (nothing else) to answer.txt in the workspace."
        + DESKTOP_HINT.format(title="AM-Bench Secret"),
        gui_mode="secret", max_turns=15,
    ),
    BenchTask(
        "d02_click_button", "desktop",
        "Click the button labelled 'Confirmar Pedido' in the desktop window. Then write the word DONE to done.txt in the workspace."
        + DESKTOP_HINT.format(title="AM-Bench Button"),
        gui_mode="button", max_turns=15,
    ),
    BenchTask(
        "d03_type_unicode", "desktop",
        "In the desktop window, type the exact text 'Ação Ω 2026' into the text field and click the 'Salvar' button. Then write DONE to done.txt in the workspace."
        + DESKTOP_HINT.format(title="AM-Bench Form"),
        gui_mode="form", max_turns=18,
    ),
    BenchTask(
        "d04_sum_numbers", "desktop",
        "The desktop window shows five integers. Write their sum (digits only) to answer.txt in the workspace."
        + DESKTOP_HINT.format(title="AM-Bench Numbers"),
        gui_mode="numbers", max_turns=15,
    ),
]

BROWSER_HINT = (
    " Use browser_observe, browser_act, and browser_extract (headless=true) to interact with the live page "
    "and write ONLY the exact extracted result to answer.txt in the workspace."
)

BROWSER_TASKS = [
    BenchTask(
        "b01_dynamic_form",
        "browser",
        "Open {SITE_URI}/login.html in the browser, fill #code_input with 'OMEGA-42', click #submit_btn, "
        "extract #badge, and write its exact text to answer.txt." + BROWSER_HINT,
        files={
            "site/login.html": """<!DOCTYPE html>
<html><body>
  <h2 id="badge">WAITING</h2>
  <input id="code_input" type="text" />
  <button id="submit_btn" onclick="var v=document.getElementById('code_input').value; var s=0; for(var i=0;i<v.length;i++) s+=v.charCodeAt(i); document.getElementById('badge').innerText='AUTH:'+v+':'+s;">Verify</button>
</body></html>
""",
        },
        hidden={
            "tests_hidden/test_h.py": _t("""
import pathlib
def test_answer():
    v = pathlib.Path("answer.txt").read_text(encoding="utf-8").strip()
    expected_sum = sum(ord(c) for c in "OMEGA-42")
    assert v == f"AUTH:OMEGA-42:{expected_sum}"
""")
        },
        max_turns=12,
    ),
    BenchTask(
        "b02_table_filter_sum",
        "browser",
        "Open {SITE_URI}/ledger.html in the browser, click #filter_approved_btn, extract #total_amount, "
        "and write its exact text to answer.txt." + BROWSER_HINT,
        files={
            "site/ledger.html": """<!DOCTYPE html>
<html><body>
  <button id="filter_approved_btn" onclick="document.getElementById('total_amount').innerText=String(120+340+95)">Filter Approved</button>
  <div id="total_amount">0</div>
</body></html>
""",
        },
        hidden={
            "tests_hidden/test_h.py": _t("""
import pathlib
def test_answer():
    assert pathlib.Path("answer.txt").read_text(encoding="utf-8").strip() == "555"
""")
        },
        max_turns=12,
    ),
    BenchTask(
        "b03_multi_step_nav",
        "browser",
        "Open {SITE_URI}/step1.html in the browser, click #next_step to navigate to step2.html, "
        "click #reveal_btn, extract #secret_out, and write its exact text to answer.txt." + BROWSER_HINT,
        files={
            "site/step1.html": """<!DOCTYPE html>
<html><body>
  <h1>Step 1</h1>
  <a id="next_step" href="step2.html">Continue to Step 2</a>
</body></html>
""",
            "site/step2.html": """<!DOCTYPE html>
<html><body>
  <h1>Step 2</h1>
  <button id="reveal_btn" onclick="document.getElementById('secret_out').innerText='STEP2-CONFIRMED-'+(450*2+1)">Reveal</button>
  <div id="secret_out">HIDDEN</div>
</body></html>
""",
        },
        hidden={
            "tests_hidden/test_h.py": _t("""
import pathlib
def test_answer():
    assert pathlib.Path("answer.txt").read_text(encoding="utf-8").strip() == "STEP2-CONFIRMED-901"
""")
        },
        max_turns=14,
    ),
    BenchTask(
        "b04_self_healing_button",
        "browser",
        "Open {SITE_URI}/portal.html in the browser, fill #ref_box with 'REF-88', click the 'Confirm Dispatch' button, "
        "extract #receipt_box, and write its exact text to answer.txt." + BROWSER_HINT,
        files={
            "site/portal.html": """<!DOCTYPE html>
<html><body>
  <input id="ref_box" type="text" />
  <button onclick="document.getElementById('receipt_box').innerText='DISPATCH:'+document.getElementById('ref_box').value+':OK'">Confirm Dispatch</button>
  <p id="receipt_box">PENDING</p>
</body></html>
""",
        },
        hidden={
            "tests_hidden/test_h.py": _t("""
import pathlib
def test_answer():
    assert pathlib.Path("answer.txt").read_text(encoding="utf-8").strip() == "DISPATCH:REF-88:OK"
""")
        },
        max_turns=14,
    ),
    BenchTask(
        "b05_validation_calc",
        "browser",
        "Open {SITE_URI}/calc.html in the browser, fill #a_in with '15' and #b_in with '27', click #calc_btn, "
        "extract #calc_out, and write its exact text to answer.txt." + BROWSER_HINT,
        files={
            "site/calc.html": """<!DOCTYPE html>
<html><body>
  <input id="a_in" type="text" />
  <input id="b_in" type="text" />
  <button id="calc_btn" onclick="var a=parseInt(document.getElementById('a_in').value,10); var b=parseInt(document.getElementById('b_in').value,10); document.getElementById('calc_out').innerText='RES='+((a*3)+b);">Calculate</button>
  <span id="calc_out">NONE</span>
</body></html>
""",
        },
        hidden={
            "tests_hidden/test_h.py": _t("""
import pathlib
def test_answer():
    assert pathlib.Path("answer.txt").read_text(encoding="utf-8").strip() == "RES=72"
""")
        },
        max_turns=14,
    ),
]

ALL_TASKS = CODE_TASKS + DESKTOP_TASKS + BROWSER_TASKS
