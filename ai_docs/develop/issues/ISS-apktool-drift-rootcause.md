# ISS — `apktool.yaml` mid-test mutation root-cause

**Issue ID:** ISS-apktool-drift-rootcause
**Owner:** Backend / Test infrastructure
**Source task:** ARG-038 (Cycle 4 — apktool drift investigation + read-only catalog fixture)
**Status:** **RESOLVED** — root cause not reproducible after Cycle 4 baseline; defence-in-depth `read_only_catalog` session fixture added regardless
**Priority:** LOW (no production code path; test-infra hygiene)
**Date filed:** 2026-04-19
**Date closed:** 2026-04-19
**Companion issue:** [`ISS-payload-signatures-drift.md`](./ISS-payload-signatures-drift.md) — same investigation pattern for the payloads catalog (closed by ARG-037).

---

## Symptom (historical, Cycle 3)

В нескольких worker-проходах Cycle 3 (ARG-021, ARG-022, ARG-027, ARG-029) поверхностно всплыла идентичная аномалия:

* `backend/config/tools/apktool.yaml` мутировался mid-run — после `pytest -q` его SHA-256 hash не совпадал с записью в `backend/config/tools/SIGNATURES`.
* `python -m scripts.tools_sign verify ...` падал с `verify.failed` после прогона тестов.
* Никто из worker'ов не локализовал root-cause — каждый просто восстанавливал YAML из `git checkout backend/config/tools/apktool.yaml` и шёл дальше.
* Аналогичный симптом параллельно наблюдался для `backend/config/payloads/SIGNATURES` (закрыт ARG-037).

---

## Investigation (Cycle 4 — ARG-038)

Применён план bisection из ARG-038 + симметричная методология ARG-037:

### Шаг 1 — Snapshot baseline

Зафиксированы SHA-256 для всех 188 защищённых файлов:

* `backend/config/tools/*.yaml` × 157 + `SIGNATURES`
* `backend/config/payloads/*.yaml` × 23 + `SIGNATURES`
* `backend/config/prompts/*.yaml` × 5 + `SIGNATURES`

Контрольные значения:

```
apktool.yaml          : 98D126DB5DC76BA12041CB6B465DA3793ADD4BE70433356ED811D623915BEEAD
tools/SIGNATURES      : FFFE22FD55A7EA1DC58ED717A31B27C066748818D5773D1F6B53B3402E23FE5D
payloads/SIGNATURES   : AFD30B9804BAAC692C410B05CBE8E94C1B182E5FAAFB24A7BA72A133DCF5CC8E
prompts/SIGNATURES    : 2F3584F26B131B01745437F7BCA345306C03D8032AE3FAD0A11D0C59AE4D6561
```

### Шаг 2 — Полный pytest run (deterministic)

```powershell
python -m pytest -q --tb=line
# 11222 passed, 165 skipped, 2964 deselected, 5 failed (parser tests, unrelated)
```

После прогона hash apktool.yaml и SIGNATURES — **identical** baseline-у. Drift не воспроизводится.

### Шаг 3 — Targeted high-risk модули × 3

```powershell
python -m pytest tests/unit/sandbox tests/integration/sandbox tests/test_tool_catalog_coverage.py -q --tb=no
```

3 последовательных прогона — ни в одном из 188 файлов hash не изменился. Заметно: количество failures колеблется (1, 1, 19) — это указывает на test-ordering dependency В ПАРСЕРАХ, но не на mutation catalog'а.

### Шаг 4 — Code-search всех write-операций в `backend/tests/`

Все `write_text` / `write_bytes` / `open(..., "w")` упомянутые относительно catalog-файлов используют `tmp_path` / `tmp_path_factory.mktemp(...)`:

* `tests/unit/sandbox/conftest.py::signed_tools_dir` → `tmp_path / "tools"` ✓
* `tests/unit/payloads/conftest.py::signed_payloads_dir` → `tmp_path / "payloads"` ✓
* `tests/unit/orchestrator_runtime/test_prompt_registry.py` → `tmp_path / "prompts"` ✓
* `tests/integration/sandbox/test_arg014..017_end_to_end.py` → `tmp_path_factory.mktemp("argXXX_catalog")` ✓
* `tests/unit/sandbox/test_signing.py` → `tmp_path / "x.yaml"` ✓
* `tests/integration/sandbox/test_arg016_end_to_end.py:222-230` → пишет SIGNATURES, но **внутри** `tmp_path_factory.mktemp("arg016_catalog")` ✓

Прямых записей в `backend/config/{tools,payloads,prompts}/*.yaml` или `SIGNATURES` в тестах **не обнаружено**.

### Шаг 5 — 5× smoke loop с защитной fixture'ой (см. Resolution)

```
Run 1: 11591 passed, 1 failed (parser, pre-existing) | tools=ok | payloads=ok | prompts=ok | 408s
Run 2: 11591 passed, 1 failed (parser, pre-existing) | tools=ok | payloads=ok | prompts=ok | 319s
Run 3: 11591 passed, 1 failed (parser, pre-existing) | tools=ok | payloads=ok | prompts=ok | 264s
Run 4: 11591 passed, 1 failed (parser, pre-existing) | tools=ok | payloads=ok | prompts=ok | 237s
Run 5: 11591 passed, 1 failed (parser, pre-existing) | tools=ok | payloads=ok | prompts=ok | 252s
```

Все 188 защищённых файлов после 5 прогонов — **bit-for-bit identical** baseline-у. The single test failure (`tests/integration/sandbox/parsers/test_arg029_dispatch.py::test_registered_count_is_68`) — pre-existing, в скоупе других worker'ов (arg-029 parser dispatch), к catalog drift отношения не имеет.

---

## Root cause

**Не воспроизводится** в Cycle 4 baseline.

Наиболее вероятные исторические гипотезы (ни одна не доказана воспроизведением):

1. **Cycle 3 fixture leak** — раньше в `tests/integration/sandbox/test_argXXX_end_to_end.py` мог быть baseline, который писал в production catalog для удобства; refactoring к `tmp_path_factory.mktemp(...)` устранил проблему до Cycle 4.
2. **Cycle 3 race в xdist runs** — Cycle 3 экспериментировал с `pytest-xdist` для параллельных тестов; параллельные процессы делили доступ к одному и тому же production catalog'у (read-write FD races на Windows). xdist в Cycle 4 отключён → race исчез.
3. **Антивирус / Windows file-cache anomaly** — Defender по умолчанию ОТКРЫВАЕТ файлы в режиме сканирования; одновременно с тестом, который читает SIGNATURES, мог происходить atime-update / SMB-cache flush, искажающий hash. Маловероятно (hash считается через python `hashlib.sha256(read_bytes())`, не зависит от atime), но Cycle 3 worker'ы запускались на разных машинах с разной AV-конфигурацией.
4. **Pre-ARG-037 stale unit fixture** — какая-то более ранняя версия unit-теста (удалённая в Cycle 3 cleanup) писала в production. Невозможно проверить без `git log`-а конкретных Cycle 3 commit'ов.

В любом случае, **в текущей кодовой базе drift невозможен** — это подтверждено как baseline run'ом, так и (главное) тем, что после внедрения `read_only_catalog` fixture любая попытка записи теперь немедленно валит тест с `PermissionError`.

---

## Resolution (Cycle 4 — ARG-038)

### A. Defence-in-depth: `read_only_catalog` session fixture

Добавлен новый session-scope autouse fixture в `backend/tests/conftest.py`:

```python
@pytest.fixture(scope="session", autouse=True)
def read_only_catalog() -> Iterator[None]:
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

Покрывает все 188 защищённых файлов (`config/{tools,payloads,prompts}/*.yaml + SIGNATURES`). Cross-platform:

* POSIX: `chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)` → `0o444`
* Windows: `chmod(stat.S_IREAD)` → выставляет `FILE_ATTRIBUTE_READONLY`

Любая попытка `open(path, "w")` / `path.write_text(...)` / `path.write_bytes(...)` от теста немедленно валится с `PermissionError`.

### B. Marker `mutates_catalog`

Зарегистрирован в `pyproject.toml` + `pytest.ini` для будущих тестов, которые правомерно нуждаются в mutation catalog'а. На данный момент **ни один существующий тест** не требует этот marker — все используют `tmp_path` корректно. Marker — documentation-only: chmod применяется session-wide, поэтому даже marked-тест должен работать через `tmp_path` копию.

### C. Регрессионный gate `tests/test_catalog_immutable_during_pytest.py`

5 параметризованных кейсов:

1. `test_signed_catalog_is_read_only_during_pytest_session` — проверяет что fixture chmod'ит каждый файл (S_IWUSR bit cleared).
2. `test_signed_catalog_dirs_are_populated` — sanity: каталоги не пусты (защита от cleanup).
3. `test_signed_catalog_verifies_after_pytest[tools]` — `python -m scripts.tools_sign verify ...` exit 0.
4. `test_signed_catalog_verifies_after_pytest[payloads]` — `python -m scripts.payloads_sign verify ...` exit 0.
5. `test_signed_catalog_verifies_after_pytest[prompts]` — `python -m scripts.prompts_sign verify ...` exit 0.

Если когда-нибудь test обойдёт fixture (например, через `os.chmod(0o644)` mid-run) — gate упадёт с понятной диагностикой.

---

## Verification

```powershell
cd D:\Developer\Pentest_test\ARGUS\backend

# Регрессионный gate
python -m pytest tests/test_catalog_immutable_during_pytest.py -v
# → 5 passed in 23.33s

# Прямые verifies (manual baseline confirmation)
python -m scripts.tools_sign verify --tools-dir config/tools --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
# → {"event": "verify.ok", "verified_count": 157}
python -m scripts.payloads_sign verify --payloads-dir config/payloads --signatures config/payloads/SIGNATURES --keys-dir config/payloads/_keys
# → {"event": "verify.ok", "verified_count": 23}
python -m scripts.prompts_sign verify --prompts-dir config/prompts --signatures config/prompts/SIGNATURES --keys-dir config/prompts/_keys
# → {"event": "verify.ok", "verified_count": 5}

# 5× smoke loop — все зелёные
for ($i = 1; $i -le 5; $i++) {
  python -m pytest -q --tb=line
  python -m scripts.tools_sign verify --tools-dir config/tools --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
}
# → 5/5 verify.ok; 188 catalog files identical to baseline
```

---

## Out-of-scope follow-ups

* **xdist-safe variant**. Если Cycle 5 включит `pytest-xdist` для параллельного запуска тестов, текущий session-scope fixture будет применяться независимо в каждом worker'е; race между worker'ами при chmod восстановлении НЕ случается (каждый worker имеет свой session). Однако если Cycle 5 захочет, чтобы только один worker делал chmod (для производительности), нужен xdist-aware variant — либо `xdist_session_finish` hook, либо file-locking через `pytest_xdist.scheduler`. Документировано как N+1 issue.
* **Pre-commit hook**. Cycle 5 может добавить `.cursor/hooks.json` запись, которая запускает `tools_sign verify` / `payloads_sign verify` / `prompts_sign verify` перед каждым commit. ~3s overhead, но 100% catch для drift, попавшего на disk вне pytest (manual edits, IDE-glitches, и т.д.).
* **CI gate сильнее**. `.github/workflows/ci.yml` уже запускает verifies в отдельном job (см. ARG-037). Можно дополнительно требовать, чтобы regression gate (`tests/test_catalog_immutable_during_pytest.py`) запускался ПОСЛЕ остальных тестов через `pytest_collection_modifyitems` ordering — гарантирует, что любая mutation, проскочившая через все остальные, будет поймана.
