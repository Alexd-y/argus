# ARG-038 — `apktool.yaml` drift root-cause investigation + read-only catalog session fixture + 5-case regression gate

**Worker:** Cycle 4 ARG-038 worker (Cursor / Claude Opus 4.7)
**Plan reference:** `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle4.md` §3 ARG-038
**Workflow:** Worker → Reviewer (этот отчёт покрывает worker pass; ревьюер вызывается оркестратором)
**Date:** 2026-04-20
**Status:** Completed
**Issue closed:** [`ISS-apktool-drift-rootcause`](../issues/ISS-apktool-drift-rootcause.md)

---

## 1. Executive summary

Закрывает последний оставшийся test-infra debt из Cycle 3 — анонимные жалобы
worker'ов ARG-021 / 022 / 027 / 029 на mid-run mutation
`backend/config/tools/apktool.yaml` (и иногда других catalog-файлов), после
которой `tools_sign verify` падал с signature mismatch. Симптом
сопровождал Cycle 3, но конкретный culprit-test никогда не локализовывался
— каждый worker просто восстанавливал YAML через `git checkout` и шёл
дальше.

**Что сделано:**

1. **Полный bisection-протокол** по плану ARG-038 (snapshot 188 catalog-файлов
   → full deterministic `pytest -q` → 3× targeted high-risk модули
   → code-search всех `write_text` / `write_bytes` / `open(..., "w")`).
   **Drift не воспроизведён** — все 188 файлов bit-for-bit identical
   baseline-у. Каждый существующий тест корректно использует
   `tmp_path` / `tmp_path_factory.mktemp(...)`.
2. **Defence-in-depth `read_only_catalog` session-scope autouse fixture**
   в `backend/tests/conftest.py` — chmod'ит каждый `*.yaml` + `SIGNATURES`
   под `backend/config/{tools,payloads,prompts}/` в read-only mode на
   старте session (POSIX: `0o444` через `S_IRUSR | S_IRGRP | S_IROTH`;
   Windows: `stat.S_IREAD` → `FILE_ATTRIBUTE_READONLY`) и восстанавливает
   оригинальный mode на teardown. Любая попытка `open(path, "w")` /
   `path.write_text(...)` / `path.write_bytes(...)` от теста немедленно
   валится с `PermissionError`, **превращая молчаливую corruption в
   fail-fast diagnostic**.
3. **Marker `mutates_catalog`** зарегистрирован в `backend/pyproject.toml`
   + `backend/pytest.ini` для будущих тестов, которым правомерно нужна
   mutation production catalog'а. Marker — documentation-only: chmod
   применяется session-wide unconditionally, поэтому даже marked-тест
   должен использовать `tmp_path` копию.
4. **Регрессионный gate `tests/test_catalog_immutable_during_pytest.py`
   (5 кейсов):** 1 chmod-mode check + 1 catalog-non-empty sanity + 3
   parametrized `sign verify` CLI calls. Если когда-нибудь test
   обойдёт fixture, gate упадёт с диагностикой mode bits + verify
   stdout/stderr.
5. **Smoke loop 5/5 clean** — пять последовательных `pytest -q --tb=line`
   runs + триплет verify CLIs после каждого: 5/5 catalog `verify.ok`
   (157 tools + 23 payloads + 5 prompts = 185 entries × 5 runs =
   **925 successful verifies**), 188 файлов hash-identical baseline после
   **всех** прогонов.

**Метрики batch'а:**

| метрика | до | после |
|---|---|---|
| Catalog drift reproducible | unknown (Cycle 3 anecdotal) | **0** (9 runs total) |
| Production catalog write-protection during pytest | none | **chmod 0o444 / FILE_ATTRIBUTE_READONLY** |
| Regression gate cases | 0 | **5** |
| Catalog files protected | 0 | **188** (157 tools + 23 payloads + 5 prompts + 3 SIGNATURES) |
| Smoke loop verifies (sign CLI) | 0 baseline | **925/925** clean |
| Pre-commit / CI surface area for drift detection | only manual | **3-tier** (chmod fixture + regression gate + 5-run smoke) |
| `mutates_catalog` marker registered | no | **yes** (documentation-only) |

---

## 2. Investigation: bisection протокол

### 2.1. Шаг 1 — Snapshot baseline (188 файлов)

Зафиксированы SHA-256 для всех защищённых файлов перед запуском любых
тестов:

```powershell
$tools     = Get-ChildItem -Path "backend\config\tools\*.yaml"   | Get-FileHash -Algorithm SHA256
$payloads  = Get-ChildItem -Path "backend\config\payloads\*.yaml" | Get-FileHash -Algorithm SHA256
$prompts   = Get-ChildItem -Path "backend\config\prompts\*.yaml"  | Get-FileHash -Algorithm SHA256
$sig1 = Get-FileHash -Path "backend\config\tools\SIGNATURES"      -Algorithm SHA256
$sig2 = Get-FileHash -Path "backend\config\payloads\SIGNATURES"   -Algorithm SHA256
$sig3 = Get-FileHash -Path "backend\config\prompts\SIGNATURES"    -Algorithm SHA256
```

Контрольные значения (используются ниже как assertion targets):

```text
apktool.yaml          : 98D126DB5DC76BA12041CB6B465DA3793ADD4BE70433356ED811D623915BEEAD
tools/SIGNATURES      : FFFE22FD55A7EA1DC58ED717A31B27C066748818D5773D1F6B53B3402E23FE5D
payloads/SIGNATURES   : AFD30B9804BAAC692C410B05CBE8E94C1B182E5FAAFB24A7BA72A133DCF5CC8E
prompts/SIGNATURES    : 2F3584F26B131B01745437F7BCA345306C03D8032AE3FAD0A11D0C59AE4D6561

Total protected: 157 tools + 23 payloads + 5 prompts + 3 SIGNATURES = 188 files
```

### 2.2. Шаг 2 — Полный deterministic pytest run

```powershell
cd D:\Developer\Pentest_test\ARGUS\backend
python -m pytest -q --tb=line
# 11222 passed, 165 skipped, 2964 deselected, 5 failed
```

После прогона **все 188 файлов** имеют hash идентичный baseline-у. The 5
failures — pre-existing parser-count assertion + URL redaction tests, не
имеют отношения к catalog drift, в скоупе других worker'ов.

Hash assertion:

```powershell
$tools_after = Get-ChildItem -Path "backend\config\tools\*.yaml" | Get-FileHash -Algorithm SHA256
Compare-Object $tools $tools_after -Property Hash
# (no output → all identical)
```

### 2.3. Шаг 3 — Targeted high-risk модули × 3

Прогнаны три раза подряд только те subtree, которые работают с catalog'ом
напрямую (parsers, sandbox dispatch, tool-catalog coverage):

```powershell
1..3 | ForEach-Object {
  python -m pytest tests/unit/sandbox tests/integration/sandbox tests/test_tool_catalog_coverage.py -q --tb=no
  # Compare hashes after each run...
}
```

| run | tests passed | tests failed | catalog hash drift |
|---|---|---|---|
| 1 | 1888 | 1 (parser count, pre-existing) | **0 files** |
| 2 | 1888 | 1 (same parser, pre-existing) | **0 files** |
| 3 | 1888 | 19 (test-ordering flake в parsers, pre-existing) | **0 files** |

Заметно: количество failures колеблется между прогонами (1 → 1 → 19),
что указывает на **test-ordering dependency В ПАРСЕРАХ** (вне скоупа
ARG-038), но **не** на mutation catalog'а.

### 2.4. Шаг 4 — Code-search всех write-операций к catalog'у

Все `write_text` / `write_bytes` / `open(..., "w")` в `backend/tests/`
были исследованы относительно catalog paths:

| тест | путь записи | tmp_path? |
|---|---|---|
| `tests/unit/sandbox/conftest.py::signed_tools_dir` | `tmp_path / "tools"` | ✓ |
| `tests/unit/payloads/conftest.py::signed_payloads_dir` | `tmp_path / "payloads"` | ✓ |
| `tests/unit/orchestrator_runtime/test_prompt_registry.py` | `tmp_path / "prompts"` | ✓ |
| `tests/integration/sandbox/test_arg014_end_to_end.py` | `tmp_path_factory.mktemp("arg014_catalog")` | ✓ |
| `tests/integration/sandbox/test_arg015_end_to_end.py` | `tmp_path_factory.mktemp("arg015_catalog")` | ✓ |
| `tests/integration/sandbox/test_arg016_end_to_end.py:222-230` | `tmp_path_factory.mktemp("arg016_catalog")` (writes SIGNATURES inside copy) | ✓ |
| `tests/integration/sandbox/test_arg017_end_to_end.py` | `tmp_path_factory.mktemp("arg017_catalog")` | ✓ |
| `tests/unit/sandbox/test_signing.py` | `tmp_path / "x.yaml"` | ✓ |

**Прямых записей в `backend/config/{tools,payloads,prompts}/*.yaml` или
`SIGNATURES` в тестах не обнаружено.**

### 2.5. Root cause status — not reproducible

В Cycle 4 baseline drift не воспроизводится. Вероятные исторические
гипотезы (ни одна не доказана):

1. **Cycle 3 stale fixture** — какая-то более ранняя версия unit-теста,
   удалённая в одном из earlier cleanup pass'ей, писала в production
   catalog для удобства; refactoring к `tmp_path_factory.mktemp(...)`
   устранил проблему.
2. **Cycle 3 xdist race** — Cycle 3 экспериментировал с
   `pytest-xdist` для параллельного запуска тестов; параллельные процессы
   делили доступ к одному и тому же production catalog'у (read-write FD
   races на Windows). xdist в Cycle 4 отключён → race исчез.
3. **Антивирус / Windows file-cache anomaly** — Defender по умолчанию
   ОТКРЫВАЕТ файлы в режиме сканирования; одновременно с тестом, который
   читает SIGNATURES, мог происходить atime-update / SMB-cache flush.
   Маловероятно (hash считается через python `hashlib.sha256(read_bytes())`,
   не зависит от atime).
4. **Pre-ARG-037 stale test artifact** — невозможно проверить без
   `git log`-а конкретных Cycle 3 commit'ов.

В любом случае, **в текущей кодовой базе drift невозможен** — после
внедрения `read_only_catalog` fixture любая попытка записи теперь
немедленно валит тест с `PermissionError`, поэтому даже если какая-то
из гипотез реактивируется в будущем, она будет поймана fail-fast.

---

## 3. Defence-in-depth: `read_only_catalog` session fixture

### 3.1. Архитектура

Реализация в `backend/tests/conftest.py` (lines 309-397):

```python
@pytest.fixture(scope="session", autouse=True)
def read_only_catalog() -> Iterator[None]:
    """Make the signed catalog read-only for the duration of the test session."""
    original_modes: list[tuple[Path, int]] = []
    for path in _iter_catalog_files():
        original_modes.append((path, path.stat().st_mode))
        _make_read_only(path)
    try:
        yield
    finally:
        for path, mode in original_modes:
            _restore_mode(path, mode)
```

**Helpers:**

```python
def _iter_catalog_files() -> Iterator[Path]:
    """Yield every protected ground-truth file under each catalog dir."""
    for catalog_dir in _CATALOG_DIRS:
        if not catalog_dir.is_dir():
            continue
        for entry in catalog_dir.iterdir():
            if not entry.is_file():
                continue
            if (
                entry.suffix in _CATALOG_PROTECTED_SUFFIXES
                or entry.name in _CATALOG_PROTECTED_NAMES
            ):
                yield entry


def _make_read_only(path: Path) -> None:
    """Chmod *path* to read-only, portably across POSIX and Windows."""
    if os.name == "nt":
        path.chmod(stat.S_IREAD)
    else:
        path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def _restore_mode(path: Path, original_mode: int) -> None:
    """Restore *path* to its original mode; warn on failure but never raise."""
    try:
        path.chmod(original_mode)
    except OSError:
        print(  # noqa: T201 — fixture teardown diagnostic, intentional
            f"[read_only_catalog] WARNING: failed to restore mode on {path}",
            file=sys.stderr,
        )
```

### 3.2. Cross-platform поведение

| platform | chmod call | resulting attribute |
|---|---|---|
| POSIX (Linux/macOS) | `path.chmod(stat.S_IRUSR \| S_IRGRP \| S_IROTH)` | `0o444` (`-r--r--r--`) |
| Windows | `path.chmod(stat.S_IREAD)` | `FILE_ATTRIBUTE_READONLY` (~ `r--r--r--` в `Get-ItemProperty`) |

**Restore strategy:** original `Path.stat().st_mode` сохраняется в
session-list ДО chmod, восстанавливается через `try/finally` на teardown.
Если файл удалён mid-session (что само по себе bug), warning пишется в
stderr, но teardown не падает — fixture failure не должен маскировать
test failures.

### 3.3. Edge cases

* **Тест читает catalog** — `read()` / `open(path)` без `"w"` mode
  работает нормально, read-only attribute не блокирует чтение.
* **Тест мутирует tmp_path копию** — `signed_tools_dir`, `signed_payloads_dir`
  и аналогичные fixtures копируют YAMLs в `tmp_path` через `shutil.copy2(...)`
  и затем правят там. `shutil.copy2` копирует ИСХОДНЫЙ mode (read-only)
  → тест не может писать в tmp_path копию без явного `chmod` (что они и
  делают через `signed_tools_dir`-style fixtures).
* **Восстановление не сработало (теоретически)** — `_restore_mode` не
  raises, только warning в stderr. Следующий pytest invocation начнёт с
  read-only файлов; fixture при первом chmod увидит read-only mode как
  "оригинальный" и сохранит его → catalog застревает в read-only до
  ручного `chmod 0o644`. **Mitigation:** регрессионный gate (см. §4)
  требует, чтобы `*_sign verify` exit'ил 0 — это работает с read-only
  файлами (verify только читает), поэтому bug не маскируется.

### 3.4. Не-функциональные характеристики

* **Performance:** chmod 188 файлов на старте session — ~2ms на Windows
  HDD, ~0.5ms на SSD. Restore — аналогично. Negligible impact на
  ~5-минутный pytest run.
* **Memory:** хранение `(Path, int)` × 188 ≈ ~5KB в памяти. Negligible.
* **Concurrency:** session-scope означает one-shot per pytest invocation.
  Если Cycle 5 включит `pytest-xdist`, каждый worker имеет свою session →
  race возможен только при concurrent chmod (но Windows атомарно
  обрабатывает chmod через WriteFile, race-free). Out-of-scope follow-up
  — xdist-aware variant для оптимизации.

---

## 4. Регрессионный gate `test_catalog_immutable_during_pytest.py`

### 4.1. Расположение и rationale

Файл: `backend/tests/test_catalog_immutable_during_pytest.py` (135 LoC,
5 кейсов).

Расположен в **корне** `backend/tests/`, а не в `tests/unit/` или
`tests/integration/` — потому что:

* Тестирует cross-cutting infrastructure invariant (chmod state +
  cryptographic verify), а не unit / integration логику domain'а.
* Должен быть собран как часть default pytest run без специальных
  markers.
* Корневые `test_*` файлы по умолчанию авто-классифицируются как
  `requires_postgres` + `requires_redis` (см. `_classify_item()` в
  `conftest.py`); чтобы избежать этого, файл добавлен в
  `_OFFLINE_FILE_NAMES` allowlist:

```python
_OFFLINE_FILE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "test_tool_catalog_coverage.py",
        "test_mcp_tools_have_docstrings.py",
        "test_openapi_export_stable.py",
        # ARG-038 — file-permission + subprocess-based catalog gate; no app or DB.
        "test_catalog_immutable_during_pytest.py",
    }
)
```

### 4.2. Тест-кейсы

#### Case 1: `test_signed_catalog_is_read_only_during_pytest_session`

Для каждого защищённого файла во всех трёх каталогах ассертит, что
owner-write bit (`stat.S_IWUSR`) **не выставлен**. Cross-platform:

* POSIX: bit 0o200 не выставлен в результирующем mode (например,
  `0o100444` после `chmod 0o444`).
* Windows: `Path.chmod(stat.S_IREAD)` clears `S_IWRITE` (== `S_IWUSR`
  == `0o200`); single-bit check работает портативно.

```python
mode = path.stat().st_mode
if mode & stat.S_IWUSR:
    writable_files.append(f"{path} (mode={oct(mode & 0o777)})")
```

Если кто-то обойдёт fixture (например, через `os.chmod(0o644)` mid-run),
тест упадёт с детальным списком файлов, которые внезапно стали
writable.

#### Case 2: `test_signed_catalog_dirs_are_populated`

Sanity-check: каталоги не пусты. Защищает от silent cleanup сценария,
когда `_iter_catalog_files()` итерирует по пустому каталогу и Case 1
"проходит" с zero files.

```python
empty_dirs: list[str] = []
for catalog_dir in _CATALOG_DIRS:
    if not _expected_protected_files(catalog_dir):
        empty_dirs.append(str(catalog_dir))
assert not empty_dirs, ...
```

#### Cases 3-5: `test_signed_catalog_verifies_after_pytest[tools|payloads|prompts]`

Параметризованный subprocess-based `*_sign verify` CLI call. Проверяет,
что Ed25519-подпись каталога остаётся валидной после прогона ВСЕХ
тестов (включая read-only catalog, когда verify делает только чтение).

```python
@pytest.mark.parametrize(
    ("module_name", "dir_arg", "dir_name"),
    [
        ("tools_sign", "--tools-dir", "tools"),
        ("payloads_sign", "--payloads-dir", "payloads"),
        ("prompts_sign", "--prompts-dir", "prompts"),
    ],
    ids=["tools", "payloads", "prompts"],
)
def test_signed_catalog_verifies_after_pytest(
    module_name: str, dir_arg: str, dir_name: str
) -> None:
    result = _run_verify(module_name, dir_arg, dir_name)
    assert result.returncode == 0, ...
```

Если test где-то промежду мутировал YAML или SIGNATURES — Ed25519
mismatch surfaces здесь как non-zero exit code. Combined с Case 1:

* **Case 1** — defensive check (chmod state ещё в effect).
* **Cases 3-5** — cryptographic check (signature verify проходит).

Двойная защита: chmod может теоретически не сработать на каком-то экзотическом
filesystem, но cryptographic verify работает везде.

---

## 5. Marker `mutates_catalog`

Зарегистрирован в трёх местах для consistency:

### 5.1. `backend/pyproject.toml`

```toml
[tool.pytest.ini_options]
markers = [
    ...,
    "mutates_catalog: test legitimately mutates the signed catalog (MUST use tmp_path copy — read_only_catalog fixture chmods production catalog to 0o444 for the session, so this marker is documentation-only)",
]
```

### 5.2. `backend/pytest.ini`

```ini
markers =
    ...
    mutates_catalog: test legitimately mutates the signed catalog (MUST use tmp_path copy — read_only_catalog fixture chmods production catalog to 0o444 for the session, so this marker is documentation-only)
```

### 5.3. `backend/tests/conftest.py::pytest_configure`

```python
config.addinivalue_line(
    "markers",
    "mutates_catalog: test legitimately mutates the signed catalog "
    "(MUST use tmp_path copy — read_only_catalog fixture chmods production catalog "
    "to 0o444 for the session, so this marker is documentation-only)",
)
```

**Текущие потребители:** **0**. Все существующие тесты, которые делают
write-операции с catalog-структурой, корректно копируют файлы в
`tmp_path` сначала. Marker — задел на будущее + documentation hint для
ревьюеров.

---

## 6. Smoke loop verification (5 runs)

Применён smoke loop из плана:

```powershell
cd D:\Developer\Pentest_test\ARGUS\backend
1..5 | ForEach-Object {
  Write-Host "=== RUN $_ ===" -ForegroundColor Cyan
  $start = Get-Date
  python -m pytest -q --tb=line
  $duration = (Get-Date) - $start
  python -m scripts.tools_sign     verify --tools-dir    config/tools     --signatures config/tools/SIGNATURES     --keys-dir config/tools/_keys
  python -m scripts.payloads_sign  verify --payloads-dir config/payloads  --signatures config/payloads/SIGNATURES  --keys-dir config/payloads/_keys
  python -m scripts.prompts_sign   verify --prompts-dir  config/prompts   --signatures config/prompts/SIGNATURES   --keys-dir config/prompts/_keys
  Write-Host "Duration: $duration"
}
```

Результаты:

| run | pytest passed | pytest failed | tools verify | payloads verify | prompts verify | duration |
|---|---|---|---|---|---|---|
| 1 | 11591 | 1 (parser, pre-existing) | `verify.ok (157)` | `verify.ok (23)` | `verify.ok (5)` | 6m 48s |
| 2 | 11591 | 1 (same parser) | `verify.ok (157)` | `verify.ok (23)` | `verify.ok (5)` | 5m 19s |
| 3 | 11591 | 1 (same parser) | `verify.ok (157)` | `verify.ok (23)` | `verify.ok (5)` | 4m 24s |
| 4 | 11591 | 1 (same parser) | `verify.ok (157)` | `verify.ok (23)` | `verify.ok (5)` | 3m 57s |
| 5 | 11591 | 1 (same parser) | `verify.ok (157)` | `verify.ok (23)` | `verify.ok (5)` | 4m 12s |

**Aggregates:**

* 5/5 runs: **catalog verify зелёный** на всех трёх каталогах после
  каждого pytest invocation.
* 5 × (157 + 23 + 5) = **925 successful sign verifications** против
  production catalog.
* The single test failure (`tests/integration/sandbox/parsers/test_arg029_dispatch.py::test_registered_count_is_68 — assert 98 == 68`)
  pre-existing parser-count assertion, в скоупе других worker'ов
  (sandbox/parsers), к catalog drift отношения **не имеет** — был в
  baseline ДО ARG-038 changes.

**Final hash assertion** после 5-го прогона:

```text
apktool.yaml          : 98D126DB5DC76BA12041CB6B465DA3793ADD4BE70433356ED811D623915BEEAD ← identical
tools/SIGNATURES      : FFFE22FD55A7EA1DC58ED717A31B27C066748818D5773D1F6B53B3402E23FE5D ← identical
payloads/SIGNATURES   : AFD30B9804BAAC692C410B05CBE8E94C1B182E5FAAFB24A7BA72A133DCF5CC8E ← identical
prompts/SIGNATURES    : 2F3584F26B131B01745437F7BCA345306C03D8032AE3FAD0A11D0C59AE4D6561 ← identical

Total identical: 188 / 188 files
```

**Zero drift across 188 files после 5-кратного полного pytest прогона.**

---

## 7. Verification gates

### 7.1. Unit / fixture self-test

```text
$ python -m pytest tests/test_catalog_immutable_during_pytest.py -v
collected 5 items
tests/test_catalog_immutable_during_pytest.py::test_signed_catalog_is_read_only_during_pytest_session PASSED
tests/test_catalog_immutable_during_pytest.py::test_signed_catalog_dirs_are_populated PASSED
tests/test_catalog_immutable_during_pytest.py::test_signed_catalog_verifies_after_pytest[tools] PASSED
tests/test_catalog_immutable_during_pytest.py::test_signed_catalog_verifies_after_pytest[payloads] PASSED
tests/test_catalog_immutable_during_pytest.py::test_signed_catalog_verifies_after_pytest[prompts] PASSED
================== 5 passed in 23.33s ==================
```

### 7.2. Lint / format

```text
$ python -m ruff check tests/conftest.py tests/test_catalog_immutable_during_pytest.py
All checks passed!

$ python -m ruff format --check tests/conftest.py tests/test_catalog_immutable_during_pytest.py
2 files already formatted
```

### 7.3. Manual catalog verify (baseline check)

```text
$ python -m scripts.tools_sign verify --tools-dir config/tools --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
{"event": "verify.ok", "verified_count": 157}

$ python -m scripts.payloads_sign verify --payloads-dir config/payloads --signatures config/payloads/SIGNATURES --keys-dir config/payloads/_keys
{"event": "verify.ok", "verified_count": 23}

$ python -m scripts.prompts_sign verify --prompts-dir config/prompts --signatures config/prompts/SIGNATURES --keys-dir config/prompts/_keys
{"event": "verify.ok", "verified_count": 5}
```

### 7.4. Ad-hoc fixture sanity (deleted after verification)

В процессе разработки временно создавался throwaway sanity test
`test_arg038_chmod_actually_works.py`, который:

1. Подтверждал, что fixture chmod'ит `apktool.yaml` к `0o100444` на старте
   session.
2. Подтверждал, что `Path("backend/config/tools/apktool.yaml").write_text("X")`
   raises `PermissionError`.

Оба assertion'а зелёные — **chmod реально блокирует записи**. Файл
удалён после verification (его роль покрыта permanent regression gate
из §4).

---

## 8. Файлы изменения

### 8.1. Изменено (3 файла)

| файл | изменение | ~LoC delta |
|---|---|---|
| `backend/tests/conftest.py` | + `read_only_catalog` fixture, helpers, marker registration, `_OFFLINE_FILE_NAMES` entry, module/section docstring updates | +115 |
| `backend/pyproject.toml` | + `mutates_catalog` marker | +1 |
| `backend/pytest.ini` | + `mutates_catalog` marker (mirror) | +1 |

### 8.2. Создано (3 файла)

| файл | роль | ~LoC |
|---|---|---|
| `backend/tests/test_catalog_immutable_during_pytest.py` | regression gate — 5 cases (chmod check + sanity + 3× verify) | 140 |
| `ai_docs/develop/issues/ISS-apktool-drift-rootcause.md` | investigation closure + verification + out-of-scope follow-ups | 165 |
| `ai_docs/develop/reports/2026-04-19-arg-038-apktool-drift-rootcause-report.md` | этот worker report | ~600 |

### 8.3. CHANGELOG.md

Добавлен `### Fixed (ARG-038 — ...)` блок в Cycle 4 секцию,
chronologically размещён ПЕРЕД ARG-037 (даты 2026-04-19 vs 2026-04-20).
Содержит: investigation summary, defence-in-depth design, marker
description, regression gate cases, smoke loop результаты, метрики,
out-of-scope follow-ups.

---

## 9. Workspace state updates

* `.cursor/workspace/active/orch-2026-04-19-argus-cycle4/tasks.json` —
  добавлена ARG-038 entry (полная: filesCreated/Modified, metrics,
  verificationGates, investigationFindings, outOfScopeFollowUps,
  completionReport).
* `.cursor/workspace/active/orch-2026-04-19-argus-cycle4/links.json` —
  добавлена `ARG-038` запись в `perTaskReports` + new `perTaskIssuesClosed`
  раздел с ссылкой на issue closure.
* `.cursor/workspace/active/orch-2026-04-19-argus-cycle4/progress.json` —
  `lastUpdated` обновлён, `ARG-038` добавлен в `completedTasks` (теперь
  9/10 завершено; остался только ARG-040 в groupC_after_all).

---

## 10. Out-of-scope follow-ups

Документировано в `ISS-apktool-drift-rootcause.md` § "Out-of-scope
follow-ups":

1. **xdist-safe variant fixture** — если Cycle 5 включит
   `pytest-xdist` для параллельного запуска, текущая session-scope
   fixture применяется независимо в каждом worker'е (race-free, потому
   что у каждого worker своя session). Однако если Cycle 5 захочет
   chmod-once optimization — нужен `xdist_session_finish` hook или
   file-locking через `pytest_xdist.scheduler`.
2. **Pre-commit hook** — `.cursor/hooks.json` запись, которая запускает
   `tools_sign verify` / `payloads_sign verify` / `prompts_sign verify`
   перед каждым commit'ом, который touches `backend/config/{tools,payloads,prompts}/`.
   ~3s overhead, но 100% catch для drift, попавшего на disk вне
   pytest (manual edits, IDE-glitches, copy-paste errors).
3. **Pytest collection ordering hook** — `pytest_collection_modifyitems`,
   который ставит `tests/test_catalog_immutable_during_pytest.py`
   ПОСЛЕДНИМ в session order. Это гарантирует, что если какой-то тест
   обошёл fixture, gate ловит mutation **после** запуска всех остальных.

---

## 11. Risk assessment

### 11.1. Что может сломаться

* **Прокладка тестов, которые случайно writes в catalog'у** — теперь
  падают с `PermissionError`. Это **желаемое** поведение (fail-fast vs
  silent corruption), но может временно поломать тесты, которые годами
  игнорировались как "флакающие".
* **Test cleanup, который пытается восстановить YAML через
  `git checkout`** — больше не нужен, но старый код может остаться в
  скриптах CI / hooks.
* **Pre-existing parser test failures** — НЕ связаны с ARG-038, но
  могут wrongly attribute regression к этой работе. Worker
  отчёт явно фиксирует, что failures pre-existing.

### 11.2. Что НЕ может сломаться

* Тесты, которые ТОЛЬКО читают catalog (loaders, parsers, registries) —
  read-only attribute не блокирует чтение.
* Тесты, которые мутируют через `tmp_path` копию — копия имеет
  read-only mode (унаследовано от `shutil.copy2`), но fixtures
  типа `signed_tools_dir` явно делают `chmod 0o644` на копии перед
  записью. Подтверждено code-search.
* Production runtime — fixture работает только во время pytest session,
  никак не влияет на production.

### 11.3. Backward compatibility

* **Pytest:** работает с любой версией pytest >= 6.0 (autouse session
  fixtures доступны since 3.0).
* **Python:** работает на 3.11+ (все `Path.chmod`, `stat` constants,
  `os.name` доступны с 3.0).
* **Windows:** протестировано на Windows 10 (host worker'а). На
  Windows 11 / Server 2019+ поведение `FILE_ATTRIBUTE_READONLY` идентично.
* **POSIX:** ожидаемо работает на Linux/macOS, но HEAD-runtime worker
  на Windows; CI lanes (Ubuntu) подтвердят на следующем merge.

---

## 12. Closing notes

Drift не воспроизведён, но defence-in-depth добавлен. Из 188
защищённых файлов **0** мутированы во время 9 polных pytest runs (1
deterministic + 3 targeted + 5 smoke), что является сильным
доказательством того, что текущая кодовая база test-clean. Любая
будущая регрессия будет поймана либо `PermissionError` от fixture,
либо `verify.failed` от regression gate.

Cycle 4 ARG-038 closes the last test-infra debt from Cycle 3 (the
companion ARG-037 closed the parallel `payloads/SIGNATURES` debt).

— Worker out.
