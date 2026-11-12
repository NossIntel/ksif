# KSIF M1 (Core + TUI + Network Discovery) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar o núcleo do KSIF, a interface de terminal e o módulo Network Discovery funcionando de ponta a ponta: escanear dentro do escopo → armazenar em SQLite → gerar relatório JSON/Markdown.

**Architecture:** `core/` (sem UI) concentra validação, escopo, execução de processos, auditoria e banco. `integrations/` tem um arquivo por ferramenta com construtores de comando tipados e parsers. `modules/` orquestra integrações e registra ações no `engine`. `ui/` (Rich) só conversa com o `engine`.

**Tech Stack:** Python ≥ 3.12, asyncio, sqlite3 (stdlib), Rich, PyYAML, pytest + pytest-asyncio, Bash.

**Spec:** `docs/superpowers/specs/2026-11-12-ksif-design.md`

## Global Constraints

- Raiz do repositório: `ksif/`. Pacotes de topo `core`, `integrations`, `modules`, `ui`; execução por `python main.py` a partir da raiz. `pyproject.toml` define `[tool.pytest.ini_options] pythonpath = ["."]`, `asyncio_mode = "auto"`, `markers = ["integration: needs real tools"]`, `addopts = "-m 'not integration'"`.
- `requires-python = ">=3.12"`. Dependências de runtime: `rich`, `pyyaml`. Nenhuma outra sem necessidade.
- Código, identificadores e textos da interface em inglês. Type hints e docstrings em toda função pública.
- Processos externos só via `core.subprocess_manager.SubprocessManager`. Proibido `shell=True`, `os.system`, `subprocess` direto fora desse arquivo (um teste faz grep disso).
- Binários permitidos no M1: `nmap`, `arp-scan`, `masscan`, `tshark`. `aireplay-ng`, `hydra`, `medusa` nunca entram na lista.
- Escopo vazio é o padrão; sem escopo nenhuma ação `ACTIVE`/`INTRUSIVE` roda.
- Tetos fixos no código: Nmap `--max-rate` ≤ 1000 e timing ≤ T4; Masscan `--rate` ≤ 1000.
- Nenhuma credencial no código. Licença GPL-3.0.
- Menu principal com exatamente os 10 itens da spec; itens de marcos futuros mostram `not yet available`.
- Cada tarefa termina com `python -m pytest` verde e um commit.

## Review Focus

1. **Domínio no escopo que resolve para IP fora do escopo** → operação ativa bloqueada e auditada (Task 2).
2. **Alvo com injeção de opção** (`-oN /tmp/x`, `10.0.0.1 --script=x`, `a;b`, quebra de linha) → `ValidationError`, nada executado (Task 1, Task 5).
3. **CIDR mais amplo que o escopo** (`10.0.0.0/8` com escopo `10.0.0.0/24`) e **sufixo enganoso** (`evilexample.com` com escopo `example.com`) → bloqueados (Task 2).
4. **XML do Nmap truncado ou vazio** (scan morto por timeout) → operação `failed` com saída bruta preservada, nenhum host parcial gravado (Task 7, Task 9).
5. **`scope.yaml` ausente, vazio ou malformado** → aplicação inicia, mostra o problema na tela Configuration, ações ativas ficam bloqueadas (Task 2, Task 11).

---

### Task 1: Scaffold, modelos e validador

**Files:**
- Create: `pyproject.toml`, `requirements.txt`, `.gitignore`, `LICENSE`, `config/settings.yaml`, `config/scope.yaml`, `core/__init__.py`, `core/models.py`, `core/validator.py`, `tests/__init__.py`, `tests/test_validator.py`, `.gitkeep` em `database/ reports/ logs/`

**Interfaces — Produces:**
```python
# core/models.py
class TargetKind(StrEnum): IPV4, IPV6, CIDR, DOMAIN, URL, INTERFACE
class Intrusiveness(IntEnum): PASSIVE = 0; ACTIVE = 1; INTRUSIVE = 2
class Mode(StrEnum): PASSIVE, ACTIVE
@dataclass(frozen=True) class Target: kind: TargetKind; value: str   # value normalizado
@dataclass class Port: number: int; protocol: str; state: str; service: str | None = None; product: str | None = None; version: str | None = None
@dataclass class Host: address: str; family: str  # "ipv4"|"ipv6"
    mac: str | None = None; vendor: str | None = None; hostname: str | None = None
    os_guess: str | None = None; os_accuracy: int | None = None; device_type: str | None = None
    state: str = "up"; ports: list[Port] = field(default_factory=list); hops: list[str] = field(default_factory=list)
# core/validator.py
class ValidationError(ValueError)
def parse_target(raw: str) -> Target
def validate_port_spec(raw: str) -> str      # "22,80,1000-2000"; cada porta 1..65535
def validate_interface(raw: str) -> str      # ^[A-Za-z0-9_.:-]{1,15}$
```

- [ ] **Step 1:** `git init` em `ksif/`; criar scaffold. `.gitignore` cobre `.venv/`, `__pycache__/`, `database/*.db`, `logs/*`, `reports/*` (mantendo `.gitkeep`). `scope.yaml` inicial com todas as listas vazias; `settings.yaml`: `operator: ""`, `mode: passive`, `rate_limit_seconds: 2.0`, `default_timeout_seconds: 600`, `paths: {database: database/ksif.db, logs: logs, reports: reports}`.
- [ ] **Step 2: Testes que falham** em `tests/test_validator.py`:
```python
@pytest.mark.parametrize("raw,kind,value", [
    ("192.168.1.10", TargetKind.IPV4, "192.168.1.10"),
    (" 192.168.1.0/24 ", TargetKind.CIDR, "192.168.1.0/24"),
    ("192.168.1.7/24", TargetKind.CIDR, "192.168.1.0/24"),
    ("fe80::1", TargetKind.IPV6, "fe80::1"),
    ("Example.COM", TargetKind.DOMAIN, "example.com"),
    ("https://example.com:8443/a", TargetKind.URL, "https://example.com:8443/a"),
])
def test_parse_valid(raw, kind, value): assert parse_target(raw) == Target(kind, value)

@pytest.mark.parametrize("raw", ["", "-oN /tmp/x", "--script=x", "10.0.0.1 -p-", "a;b", "a.com\n-sV",
    "$(id)", "`id`", "a|b", "10.0.0.1,10.0.0.2", "999.1.1.1", "ftp://x.com", "exa_mple..com", "a" * 300])
def test_parse_rejects(raw):
    with pytest.raises(ValidationError): parse_target(raw)

def test_port_spec(): assert validate_port_spec("22, 80,1000-2000") == "22,80,1000-2000"
@pytest.mark.parametrize("raw", ["0", "70000", "80-22", "22;id", "-p22", ""])
def test_port_spec_rejects(raw): ...
@pytest.mark.parametrize("raw", ["eth0", "wlan0mon"]) def test_interface_ok(raw): ...
@pytest.mark.parametrize("raw", ["-i", "eth0;id", "a b", ""]) def test_interface_rejects(raw): ...
```
- [ ] **Step 3:** Rodar `python -m pytest tests/test_validator.py` → FAIL (import).
- [ ] **Step 4:** Implementar `core/models.py` e `core/validator.py`. Usar `ipaddress` (CIDR com `strict=False`); domínio por regex RFC 1123, ≤ 253 chars; URL só `http`/`https` via `urllib.parse`, host validado como domínio ou IP.
- [ ] **Step 5:** Rodar → PASS. Commit `feat: project scaffold, models and input validator`.

### Task 2: Configuração e ScopeGuard

**Files:** Create `core/config.py`, `core/permissions.py`, `tests/test_config.py`, `tests/test_permissions.py`

**Interfaces — Consumes:** `Target`, `TargetKind`, `Intrusiveness`, `Mode`, `parse_target`.
**Produces:**
```python
# core/config.py
@dataclass class Settings: operator: str; mode: Mode; rate_limit_seconds: float; default_timeout_seconds: int; database_path: Path; logs_dir: Path; reports_dir: Path
@dataclass class Scope: ips: list[str]; subnets: list[str]; domains: list[str]; interfaces: list[str]; engagement: str = ""; errors: list[str] = field(default_factory=list)
    @property
    def is_empty(self) -> bool
def load_settings(path: Path) -> Settings      # operator vazio → env KSIF_OPERATOR → getpass.getuser()
def load_scope(path: Path) -> Scope            # nunca levanta: ausente/malformado → Scope vazio com errors preenchido
def save_settings(settings: Settings, path: Path) -> None
# core/permissions.py
class ScopeViolation(PermissionError); class ModeViolation(PermissionError)
@dataclass(frozen=True) class Authorization: target: Target; intrusiveness: Intrusiveness; operator: str; issued_at: datetime; resolved_ips: tuple[str, ...] = ()
class ScopeGuard:
    def __init__(self, scope: Scope, mode: Mode, operator: str, resolver: Callable[[str], list[str]] = default_resolver)
    def authorize(self, target: Target, intrusiveness: Intrusiveness) -> Authorization
def is_root() -> bool     # os.geteuid() == 0; False onde geteuid não existe
```
Regras de `authorize`: modo `PASSIVE` + intrusividade > `PASSIVE` → `ModeViolation`. IP: precisa estar em `ips` ou dentro de alguma `subnets`. CIDR: `subnet_of` alguma `subnets` (mesma família). Domínio/URL(host): igual a uma entrada ou, se a entrada for `*.example.com`, terminar em `.example.com`; para intrusividade ≥ `ACTIVE`, **todos** os IPs resolvidos precisam estar no escopo de IP, senão `ScopeViolation` citando o IP. Interface: precisa estar em `interfaces`. Entradas inválidas no YAML vão para `Scope.errors` e são descartadas.

- [ ] **Step 1: Testes que falham.** `test_permissions.py` (fixture: `ips=["10.0.0.5"]`, `subnets=["192.168.1.0/24"]`, `domains=["example.com","*.lab.test"]`, `interfaces=["eth0"]`, resolver fake por dict):
  - `test_ip_in_subnet_allowed`, `test_ip_listed_allowed`, `test_ip_outside_blocked` (`8.8.8.8`).
  - `test_cidr_subset_allowed` (`192.168.1.0/28`), `test_cidr_wider_blocked` (`192.168.0.0/16`), `test_cidr_other_blocked`.
  - `test_domain_exact`, `test_wildcard_subdomain` (`a.lab.test`), `test_suffix_trick_blocked` (`evilexample.com`), `test_subdomain_without_wildcard_blocked` (`a.example.com`).
  - `test_domain_resolving_outside_scope_blocked_when_active` (example.com → `["192.168.1.9","1.2.3.4"]` → `ScopeViolation`, mensagem contém `1.2.3.4`).
  - `test_domain_passive_skips_resolution` (resolver que levanta não é chamado).
  - `test_passive_mode_blocks_active` (`ModeViolation`), `test_empty_scope_blocks_everything_active`.
  - `test_interface_allowlist`, `test_authorization_carries_operator_and_resolved_ips`.

  `test_config.py`: `test_scope_missing_file`, `test_scope_malformed_yaml`, `test_scope_invalid_entry_reported` (errors não vazio, entrada descartada, demais mantidas), `test_settings_operator_from_env`, `test_settings_roundtrip`.
- [ ] **Step 2:** Rodar → FAIL.
- [ ] **Step 3:** Implementar. `default_resolver` usa `socket.getaddrinfo`; falha de resolução em operação ativa → `ScopeViolation("cannot resolve ...")`.
- [ ] **Step 4:** Rodar → PASS. Commit `feat: settings, scope loading and ScopeGuard`.

### Task 3: Banco de dados

**Files:** Create `core/database.py`, `core/migrations/001_initial.sql`, `tests/test_database.py`

**Produces:**
```python
class Database:
    def __init__(self, path: Path | str)          # ":memory:" aceito; PRAGMA foreign_keys=ON
    def migrate(self) -> int                      # aplica core/migrations/*.sql em ordem; retorna versão
    def create_operation(self, module: str, action: str, target: str, operator: str, intrusiveness: str, command: str = "") -> int
    def finish_operation(self, op_id: int, status: str, error: str | None = None, raw_output_path: str | None = None) -> None  # status: "completed"|"failed"|"blocked"
    def save_hosts(self, op_id: int, hosts: list[Host]) -> None   # transação única; upsert por address
    def list_hosts(self, op_id: int | None = None) -> list[Host]
    def list_operations(self, limit: int = 50) -> list[dict[str, Any]]
    def get_operation(self, op_id: int) -> dict[str, Any] | None
    def add_audit(self, event: dict[str, Any]) -> None
    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]
    def add_report(self, op_id: int | None, fmt: str, path: str) -> int
    def close(self) -> None
```
Tabelas da migração 001: `schema_version`, `operations(id, module, action, target, operator, intrusiveness, command, status, error, raw_output_path, started_at, finished_at)`, `audit_log(id, ts, operator, event, detail_json)`, `hosts(id, address UNIQUE, family, mac, vendor, hostname, os_guess, os_accuracy, device_type, state, hops_json, first_seen_op, last_seen_op, updated_at)`, `ports(id, host_id FK, number, protocol, state, service, product, version, op_id, UNIQUE(host_id, number, protocol))`, `reports(id, op_id, format, path, created_at)`. Timestamps em UTC ISO-8601.

- [ ] **Step 1: Testes que falham:** `test_migrate_idempotent` (duas chamadas, mesma versão 1), `test_operation_lifecycle`, `test_save_hosts_roundtrip` (host com 2 portas e hops volta igual), `test_upsert_updates_existing_host` (segunda op muda `os_guess`, mantém `first_seen_op`, não duplica porta), `test_save_hosts_atomic` (host inválido no meio → nada gravado), `test_audit_roundtrip`, `test_list_hosts_by_operation`.
- [ ] **Step 2:** FAIL → implementar → PASS. Commit `feat: sqlite database with versioned migrations`.

### Task 4: Logger estruturado e auditoria

**Files:** Create `core/logger.py`, `tests/test_logger.py`

**Produces:**
```python
def setup_logging(logs_dir: Path) -> logging.Logger       # logger "ksif", handler JSON Lines em logs/ksif.log
class AuditLogger:
    def __init__(self, logs_dir: Path, db: Database | None = None)
    def record(self, event: str, *, operator: str, **detail: Any) -> dict[str, Any]   # grava logs/audit.jsonl (+ db.add_audit); retorna o registro
def add_line_listener(cb: Callable[[str], None]) -> Callable[[], None]   # para o painel de logs ao vivo; retorna função de remoção
```
Eventos usados: `scope_allowed`, `scope_blocked`, `mode_blocked`, `confirmation_declined`, `command_started`, `command_finished`, `operation_failed`, `settings_changed`. Cada registro tem `ts` (UTC ISO), `operator`, `event` e o detalhe.

- [ ] **Step 1: Testes:** `test_audit_record_written_as_json_line`, `test_audit_goes_to_db`, `test_log_lines_are_valid_json`, `test_listener_receives_and_unsubscribes`.
- [ ] **Step 2:** FAIL → implementar → PASS. Commit `feat: structured logging and audit trail`.

### Task 5: SubprocessManager

**Files:** Create `core/subprocess_manager.py`, `tests/test_subprocess_manager.py`, `tests/test_no_raw_subprocess.py`

**Consumes:** `Authorization`, `AuditLogger`.
**Produces:**
```python
ALLOWED_BINARIES: frozenset[str] = frozenset({"nmap", "arp-scan", "masscan", "tshark"})
PROBE_ARGS: frozenset[str] = frozenset({"--version", "-V", "-v", "--help"})
class BinaryNotAllowed(PermissionError); class ToolNotFound(FileNotFoundError)
class UnauthorizedExecution(PermissionError); class ProcessTimeout(TimeoutError)
@dataclass class ProcessResult: command: list[str]; returncode: int; stdout: str; stderr: str; duration: float
class SubprocessManager:
    def __init__(self, audit: AuditLogger, *, allowed: frozenset[str] = ALLOWED_BINARIES, resolve: Callable[[str], str | None] = shutil.which)
    def is_available(self, binary: str) -> bool
    async def probe(self, binary: str, arg: str, timeout: float = 15) -> ProcessResult           # arg ∈ PROBE_ARGS; sem autorização
    async def run(self, binary: str, args: Sequence[str], *, authorization: Authorization, timeout: float, on_line: Callable[[str], None] | None = None) -> ProcessResult
```
Regras de `run`: binário fora de `allowed` → `BinaryNotAllowed`; não resolvido → `ToolNotFound`; `authorization.target.value` precisa aparecer como elemento exato de `args`, senão `UnauthorizedExecution`; qualquer arg não-`str`, vazio ou com `\x00`/`\n` → `ValueError`. Usa `asyncio.create_subprocess_exec` com `stdin=DEVNULL`; lê stdout linha a linha chamando `on_line`; no timeout mata o processo e levanta `ProcessTimeout` (com stdout parcial em `.partial_output`). Audita `command_started`/`command_finished` com argv completo.

- [ ] **Step 1: Testes** (usar `allowed=frozenset({"py"})`, `resolve=lambda _: sys.executable`, args `["-c", "<script>", alvo]`):
  `test_runs_and_captures_output`, `test_streams_lines`, `test_disallowed_binary` (`"bash"` com lista padrão), `test_default_allowlist_excludes_attack_tools` (`aireplay-ng`, `hydra`, `medusa`, `sh`, `bash` ∉ `ALLOWED_BINARIES`), `test_missing_tool`, `test_requires_target_in_args`, `test_rejects_newline_arg`, `test_timeout_kills_process` (script `time.sleep(30)`, timeout 0.5), `test_probe_rejects_other_args`, `test_shell_metachar_is_literal` (arg `"; echo pwned"` é ecoado literalmente), `test_audit_events_recorded`.
  `test_no_raw_subprocess.py`: varre `core/ integrations/ modules/ ui/ main.py` e falha se achar `shell=True`, `os.system`, `os.popen` ou `import subprocess`/`create_subprocess` fora de `core/subprocess_manager.py`.
- [ ] **Step 2:** FAIL → implementar → PASS. Commit `feat: guarded subprocess manager`.

### Task 6: Engine e limitador de taxa

**Files:** Create `core/engine.py`, `tests/test_engine.py`

**Consumes:** tudo das Tasks 1–5.
**Produces:**
```python
class RateLimiter:
    def __init__(self, min_interval: float, clock=time.monotonic, sleep=asyncio.sleep)
    async def wait(self) -> None
@dataclass class ActionContext: authorization: Authorization; runner: SubprocessManager; db: Database; settings: Settings; op_id: int; on_line: Callable[[str], None]; raw_dir: Path
@dataclass class ActionOutput: hosts: list[Host] = field(default_factory=list); summary: str = ""; data: dict[str, Any] = field(default_factory=dict)
@dataclass(frozen=True) class Action: id: str; module: str; title: str; intrusiveness: Intrusiveness; target_kinds: frozenset[TargetKind]; required_tools: tuple[str, ...]; requires_root: bool; handler: Callable[[ActionContext, dict[str, Any]], Awaitable[ActionOutput]]; params: tuple[str, ...] = ()
@dataclass class OperationResult: op_id: int; status: str; output: ActionOutput | None; error: str | None
class Engine:
    def __init__(self, settings: Settings, scope: Scope, db: Database, audit: AuditLogger, runner: SubprocessManager, root_check: Callable[[], bool] = is_root)
    def register(self, action: Action) -> None            # id duplicado → ValueError
    def actions(self, module: str | None = None) -> list[Action]
    def availability(self, action: Action) -> tuple[bool, str]     # (False, "missing tool: nmap") etc.
    def set_mode(self, mode: Mode) -> None                # audita settings_changed
    async def execute(self, action_id: str, raw_target: str, params: dict[str, Any], *, confirm: Callable[[str], bool], on_line: Callable[[str], None] = lambda _: None) -> OperationResult
```
Fluxo de `execute`: `parse_target` → conferir `target_kinds` → `ScopeGuard.authorize` → ferramentas/root → `confirm(prompt)` se intrusividade ≥ `ACTIVE` (prompt mostra ação, alvo, intrusividade) → `RateLimiter.wait` → `create_operation` → handler → `save_hosts` → `finish_operation("completed")`. Bloqueios de validação/escopo/modo/confirmação criam operação `blocked` e evento de auditoria; exceção no handler → `failed` com erro, sem `save_hosts`. `execute` nunca propaga exceção esperada: devolve `OperationResult`.

- [ ] **Step 1: Testes** (handler fake, db `:memory:`): `test_happy_path_persists_hosts`, `test_out_of_scope_blocked_and_audited` (handler não chamado), `test_passive_mode_blocks_active_action`, `test_invalid_target_blocked`, `test_wrong_target_kind_blocked`, `test_confirmation_declined`, `test_passive_action_skips_confirmation`, `test_missing_tool_blocked`, `test_requires_root_blocked`, `test_handler_exception_marks_failed_and_saves_nothing`, `test_rate_limiter_spaces_calls` (clock/sleep fakes), `test_duplicate_action_id`.
- [ ] **Step 2:** FAIL → implementar → PASS. Commit `feat: operation engine with confirmation and rate limiting`.

### Task 7: Integração Nmap

**Files:** Create `integrations/__init__.py`, `integrations/base.py`, `integrations/nmap.py`, `tests/fixtures/nmap_full.xml`, `tests/fixtures/nmap_ping_sweep.xml`, `tests/fixtures/nmap_truncated.xml`, `tests/test_nmap.py`

**Produces:**
```python
# integrations/base.py
class ParseError(ValueError)
class ToolIntegration(ABC):
    binary: ClassVar[str]; install_hint: ClassVar[str]
    def __init__(self, runner: SubprocessManager)
    def is_available(self) -> bool
    async def version(self) -> str | None          # via runner.probe + parse_version
    async def self_test(self) -> tuple[bool, str]  # execução real do probe; (ok, mensagem)
    @abstractmethod
    def parse_version(self, output: str) -> str | None
# integrations/nmap.py
MAX_RATE = 1000; MAX_TIMING = 4
class NmapIntegration(ToolIntegration):   # binary "nmap", install_hint "sudo apt install nmap"
    def host_discovery_args(self, target: Target) -> list[str]     # -sn -oX - [-6] <t>
    def port_scan_args(self, target: Target, *, ports: str | None = None, top_ports: int | None = 1000, service_detection: bool = False, os_detection: bool = False, traceroute: bool = False, timing: int = 3, max_rate: int = 300) -> list[str]
    def parse_xml(self, xml: str) -> list[Host]
```
`port_scan_args`: sempre `-oX - -Pn? não` (sem `-Pn`), `-T{min(timing, MAX_TIMING)}`, `--max-rate {min(max_rate, MAX_RATE)}`, `-6` para IPv6, `ports` passa por `validate_port_spec`, `top_ports` limitado a 1..65535, alvo sempre **último** elemento. Nunca aceita flags livres nem `--script`. `parse_xml`: hosts `up` apenas; endereço IPv4/IPv6, MAC + vendor, primeiro hostname, portas com `state/service/product/version`, melhor `osmatch` (nome + accuracy), hops do `<trace>`; XML sem `</nmaprun>` ou malformado → `ParseError`. Fixtures em formato real do `nmap -oX` (full: 2 hosts, um IPv4 com MAC/vendor/4 portas/osmatch/trace, um IPv6; um host `down` que deve ser ignorado).

- [ ] **Step 1: Testes:** `test_host_discovery_args` (`["-sn","-oX","-","192.168.1.0/24"]`), `test_ipv6_adds_flag`, `test_port_scan_caps_rate_and_timing` (pedir 99999/T5 → `--max-rate 1000`, `-T4`), `test_port_scan_validates_ports` (`"22;id"` → `ValidationError`), `test_target_is_last_arg`, `test_service_os_traceroute_flags` (`-sV`, `-O`, `--traceroute`), `test_parse_full` (asserts exatos sobre endereço, MAC, vendor, portas, produto/versão, OS, hops, host down ignorado), `test_parse_ping_sweep`, `test_parse_truncated_raises`, `test_parse_empty_raises`, `test_parse_version` (`"Nmap version 7.95 ( https://nmap.org )"` → `"7.95"`).
- [ ] **Step 2:** FAIL → implementar (`xml.etree.ElementTree`) → PASS. Commit `feat: nmap integration with typed commands and XML parser`.

### Task 8: Integrações arp-scan, Masscan e tshark

**Files:** Create `integrations/arp_scan.py`, `integrations/masscan.py`, `integrations/tshark.py`, fixtures `arp_scan.txt`, `masscan.json`, `tshark_fields.tsv`, `tests/test_arp_scan.py`, `tests/test_masscan.py`, `tests/test_tshark.py`

**Produces:**
```python
class ArpScanIntegration(ToolIntegration):   # binary "arp-scan"
    def scan_args(self, interface: str, target: Target) -> list[str]      # --interface=<if> --retry=2 <cidr>; só IPV4/CIDR
    def parse(self, output: str) -> list[Host]                           # linhas "IP\tMAC\tVendor"; ignora cabeçalho/rodapé e duplicatas "(DUP: n)"
class MasscanIntegration(ToolIntegration):   # binary "masscan"; MAX_RATE = 1000
    def scan_args(self, target: Target, ports: str, rate: int = 100) -> list[str]   # -p<ports> --rate <cap> -oJ - <t>; só IPV4/CIDR
    def parse(self, output: str) -> list[Host]                           # JSON do -oJ, tolerando vírgula final/array vazio
class TsharkIntegration(ToolIntegration):    # binary "tshark"; MAX_DURATION = 300
    def capture_args(self, interface: str, duration: int) -> list[str]   # -i <if> -a duration:<cap> -n -T fields -E separator=/t -e eth.src -e ip.src -e ipv6.src -e _ws.col.Protocol ; interface é o último valor de -i
    def parse(self, output: str) -> tuple[list[Host], dict[str, int]]    # hosts observados (por IP de origem) + contagem por protocolo
```
A interface passa por `validate_interface`. Para tshark/arp-scan o `Authorization` é emitido para o alvo `INTERFACE` (tshark) ou CIDR (arp-scan).

- [ ] **Step 1: Testes** por ferramenta: args exatos, teto de `rate`/`duration`, rejeição de IPv6 onde não suportado (`ValidationError`), parsing das fixtures com asserts exatos, saída vazia → lista vazia, saída malformada do Masscan → `ParseError`, `parse_version` de cada uma.
- [ ] **Step 2:** FAIL → implementar → PASS. Commit `feat: arp-scan, masscan and tshark integrations`.

### Task 9: Módulo Network Discovery

**Files:** Create `modules/__init__.py`, `modules/network_discovery/{__init__,actions,oui,device_classifier,topology}.py`, `tests/fixtures/oui_sample.txt`, `tests/test_network_discovery.py`, `tests/test_oui.py`, `tests/test_device_classifier.py`, `tests/test_topology.py`

**Produces:**
```python
# oui.py
OUI_PATHS = ("/usr/share/nmap/nmap-mac-prefixes", "/usr/share/arp-scan/ieee-oui.txt")
class OuiDatabase:
    def __init__(self, paths: Sequence[str | Path] = OUI_PATHS)   # carrega o primeiro existente; nenhum → lookup sempre None
    def lookup(self, mac: str) -> str | None
# device_classifier.py
def classify_device(host: Host) -> str   # "router" | "printer" | "windows-host" | "linux-host" | "network-camera" | "nas" | "mobile" | "iot" | "server" | "unknown"
# topology.py
def subnet_map(hosts: list[Host]) -> dict[str, list[str]]         # IPv4 por /24, IPv6 por /64
def topology_edges(hosts: list[Host], origin: str = "scanner") -> list[tuple[str, str]]   # arestas únicas a partir de Host.hops
# actions.py
def register(engine: Engine) -> None
```
Ações registradas (module `network_discovery`):

| id | intrusividade | ferramentas | root | params |
|---|---|---|---|---|
| `net.host_discovery` | ACTIVE | nmap | não | — |
| `net.arp_scan` | ACTIVE | arp-scan | sim | `interface` |
| `net.port_scan` | ACTIVE | nmap | não | `ports` |
| `net.service_os` | ACTIVE | nmap | sim | `ports` |
| `net.topology` | ACTIVE | nmap | sim | — |
| `net.fast_sweep` | INTRUSIVE | masscan | sim | `ports`, `rate` |
| `net.passive_capture` | PASSIVE | tshark | sim | `duration` (alvo = interface) |

Todo handler: monta args pela integração → `ctx.runner.run(...)` com `ctx.authorization` → grava saída bruta em `ctx.raw_dir/op_<id>.<ext>` → parse → enriquece cada host com `OuiDatabase.lookup` (se `vendor` vazio) e `classify_device` → `ActionOutput` com `data` contendo `subnets` e, em `net.topology`, `edges`. `ParseError`/`ProcessTimeout` propagam (engine marca `failed`; a saída bruta já está em disco e o caminho vai em `raw_output_path`). Regras do classificador: decidir por portas abertas (9100/515/631 → printer; 554/8554 → network-camera; 445+3389 → windows-host; 53+80/443 com vendor de rede → router; 2049/5000/5001 → nas; 22 sem 445 → linux-host), depois `os_guess`, depois vendor; sem sinal → `unknown`.

- [ ] **Step 1: Testes.** OUI: `test_lookup_formats` (`AA:BB:CC:…`, `aa-bb-cc-…` iguais), `test_unknown_prefix`, `test_no_database_file`. Classificador: um teste por regra + `test_unknown`. Topologia: `test_subnet_map_groups_v4_and_v6`, `test_edges_deduplicated`. Ações (engine real, `SubprocessManager` com `resolve` apontando para um script Python fake que imprime a fixture): `test_host_discovery_end_to_end` (hosts no banco com vendor e device_type), `test_port_scan_persists_ports`, `test_truncated_output_fails_and_keeps_raw_file` (operação `failed`, nenhum host gravado, arquivo bruto existe), `test_passive_capture_runs_in_passive_mode`, `test_fast_sweep_blocked_in_passive_mode`, `test_all_actions_registered`.
- [ ] **Step 2:** FAIL → implementar → PASS. Commit `feat: network discovery module`.

### Task 10: Relatórios básicos (JSON e Markdown)

**Files:** Create `modules/reporting/__init__.py`, `modules/reporting/basic.py`, `tests/test_reporting_basic.py`

**Produces:**
```python
def build_report(db: Database, scope: Scope, settings: Settings, op_ids: list[int] | None = None) -> dict[str, Any]
def render_json(report: dict[str, Any]) -> str
def render_markdown(report: dict[str, Any]) -> str
def save_report(db: Database, settings: Settings, report: dict[str, Any], fmt: str) -> Path   # fmt "json"|"markdown"; reports/ksif_<UTC yyyymmdd_HHMMSS>.<ext>
```
Chaves de `build_report`: `generated_at`, `operator`, `engagement`, `scope` (listas autorizadas), `tools` (derivadas das operações), `operations`, `hosts` (com portas/serviços/versões), `summary` (`hosts_total`, `open_ports_total`, `by_device_type`, `by_subnet`). Markdown com seções: Executive Summary, Authorized Scope, Operations, Hosts (tabela), Services (tabela por host). Vulnerabilidades e recomendações ficam para o M4 — a seção não aparece, em vez de aparecer vazia. Caracteres `|` e quebras de linha vindos de banners de serviço são escapados nas tabelas.

- [ ] **Step 1: Testes:** `test_report_contains_scope_and_operator`, `test_summary_counts`, `test_json_roundtrip`, `test_markdown_has_sections_and_rows`, `test_markdown_escapes_pipes`, `test_save_report_registers_in_db`, `test_empty_database_report`.
- [ ] **Step 2:** FAIL → implementar → PASS. Commit `feat: basic JSON and Markdown reports`.

### Task 11: Interface de terminal e `main.py`

**Files:** Create `ui/__init__.py`, `ui/theme.py`, `ui/banner.py`, `ui/app.py`, `ui/menus.py`, `ui/views.py`, `main.py`, `tests/test_ui.py`, `tests/test_main.py`

**Consumes:** `Engine`, `Action`, `OperationResult`, `build_report`/`save_report`, `ToolIntegration.self_test`.
**Produces:**
```python
# main.py
def build_engine(root: Path) -> tuple[Engine, Database, Settings, Scope]   # carrega config, migra banco, registra módulos
def main(argv: Sequence[str] | None = None) -> int     # flags: --check (lista ferramentas + escopo e sai), --version
# ui/app.py
class App:
    def __init__(self, engine: Engine, db: Database, settings: Settings, scope: Scope, console: Console, ask: Callable[[str], str])
    def run(self) -> int
```
Menu principal (texto exato): `[01] Network Discovery`, `[02] OSINT Intelligence`, `[03] Web Security Assessment`, `[04] Wi-Fi Security Audit`, `[05] Password Security Lab`, `[06] Vulnerability Intelligence`, `[07] Asset Inventory`, `[08] Report Generator`, `[09] Configuration`, `[10] Exit`. No M1: 01, 07 (tabela de hosts do banco + histórico de operações), 08 (JSON/Markdown), 09 e 10 funcionam; 02–06 mostram `not yet available (planned: M2/M3/M4)`. Submenu 01 lista as ações da Task 9 com a disponibilidade de `engine.availability` (motivo exibido quando indisponível). Execução: `rich.live` com spinner/progresso e painel com as últimas linhas de saída; ao final, tabela de hosts/portas. Confirmação: ACTIVE pede `y/N`; INTRUSIVE exige digitar o alvo. Configuration: operador, modo passivo/ativo (alternar), escopo carregado + `scope.errors`, tabela de ferramentas com versão do `self_test`, caminho dos arquivos. Cabeçalho permanente mostra operador, modo e engajamento. `views.py` só formata (funções puras `hosts_table(hosts) -> Table` etc.); `App` não contém lógica de segurança. Tema escuro em `theme.py`; banner ASCII "KSIF".

- [ ] **Step 1: Testes** (Console com `record=True`, `ask` alimentado por lista): `test_main_menu_lists_ten_items`, `test_exit_returns_zero`, `test_unavailable_module_message`, `test_configuration_shows_scope_errors` (scope.yaml malformado), `test_toggle_mode_updates_engine_and_audit`, `test_network_action_out_of_scope_shows_block` (alvo `8.8.8.8`), `test_intrusive_confirmation_requires_typing_target`, `test_asset_inventory_lists_saved_hosts`, `test_report_menu_writes_file`, `test_eof_on_input_exits_cleanly`; `test_main.py`: `test_check_flag_exits_zero_and_lists_tools` (num diretório temporário sem config: cria defaults, não levanta), `test_version_flag`.
- [ ] **Step 2:** FAIL → implementar → PASS.
- [ ] **Step 3:** Smoke real: `python main.py --check` → código 0, lista as 4 ferramentas como `missing` nesta máquina. Commit `feat: rich terminal interface and entry point`.

### Task 12: Scripts, CI Kali, testes de integração e documentação

**Files:** Create `scripts/install.sh`, `scripts/check_dependencies.sh`, `scripts/update.sh`, `tests/integration/__init__.py`, `tests/integration/test_real_tools.py`, `.github/workflows/ci.yml`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/architecture.md`, `docs/installation.md`, `docs/usage.md`, `docs/modules/network_discovery.md`, `docs/STATUS.md`

- [ ] **Step 1:** `install.sh` (`set -euo pipefail`), na ordem da spec do usuário: detectar distro por `/etc/os-release` (Kali/Debian; Termux por `$PREFIX`; outra → aviso e continuar só com Python); checar Python ≥ 3.12; `apt-get install -y` de `python3-venv nmap arp-scan masscan tshark` (com `sudo` se não root; Termux usa `pkg` e pula o que não existe); criar `.venv`; `pip install -r requirements.txt`; rodar `check_dependencies.sh`; criar `database/ logs/ reports/`; inicializar banco (`python -c` chamando `Database.migrate`); `python -m pytest -q`; imprimir instruções. **Não executa nenhuma varredura.** `check_dependencies.sh`: tabela ferramenta/versão/status, sai 0 mesmo com ausentes. `update.sh`: `git pull --ff-only`, reinstala requirements, migra banco.
- [ ] **Step 2:** `bash -n scripts/*.sh` → sem erros (e `shellcheck` se disponível).
- [ ] **Step 3:** `tests/integration/test_real_tools.py` (`pytestmark = pytest.mark.integration`; cada teste `skip` com motivo se o binário faltar): `test_nmap_self_test_reports_version`, `test_nmap_host_discovery_localhost` (escopo `127.0.0.1`, engine real, espera 1 host `up`), `test_nmap_port_scan_localhost_parses`, `test_out_of_scope_never_spawns_process` (alvo `8.8.8.8`; auditoria sem `command_started`), `test_masscan_and_tshark_self_test`.
- [ ] **Step 4:** `ci.yml`: job `unit` (ubuntu-latest, Python 3.12 e 3.13, `pytest`) e job `kali` (`container: kalilinux/kali-rolling`, roda `scripts/install.sh` como root e depois `.venv/bin/python -m pytest -m integration -v` e `.venv/bin/python main.py --check`).
- [ ] **Step 5:** Documentação. README: o que é, aviso legal/uso autorizado, estado atual (M1) com tabela módulo × status, instalação em Kali, configuração de `scope.yaml` com exemplo, exemplos de execução, dependências, roadmap M2–M5, seção em português. `docs/STATUS.md`: o que foi implementado e **como foi verificado** (unitário local / CI Kali / não verificado) — preencher com os resultados reais, sem marcar como verificado o que só o CI ou o hardware provam.
- [ ] **Step 6:** `python -m pytest` completo → PASS. Commit `feat: installer, Kali CI, integration tests and documentation`.

---

## Fora do M1

Netdiscover (coberto por arp-scan; reavaliar no M4 junto com o inventário), OSINT, Web, Wi-Fi, senhas, vulnerabilidades, relatórios HTML/CSV/PDF, publicação no GitHub (requer confirmação explícita).
