"""Interface translation (English source, Portuguese catalogue).

The code and the tool names stay in English; this layer only translates the
chrome the operator reads — menus, buttons, prompts, column headers and generic
messages. Per-action titles and descriptions carry their own translations on
the Action object. ``translate`` matches a finished string exactly (optionally
inside one Rich markup tag), then replaces known phrases inside longer strings.
"""

from __future__ import annotations

_language = "en"

EXACT: dict[str, str] = {
    "Network Discovery": "Descoberta de Rede", "OSINT Intelligence": "Inteligência OSINT",
    "Web Security Assessment": "Avaliação de Segurança Web", "Web Security": "Segurança Web",
    "Wi-Fi Security Audit": "Auditoria de Segurança Wi-Fi", "Wi-Fi Audit": "Auditoria Wi-Fi",
    "Password Security Lab": "Laboratório de Senhas", "Password Lab": "Laboratório de Senhas",
    "Vulnerability Intelligence": "Inteligência de Vulnerabilidades",
    "Vulnerability Intel": "Inteligência de Vulnerabilidades",
    "Asset Inventory": "Inventário de Ativos", "Report Generator": "Gerador de Relatórios",
    "Configuration": "Configuração", "Exit": "Sair", "Main menu": "Menu principal", "Back": "Voltar",
    "Action": "Ação", "Actions": "Ações", "Level": "Nível", "Description": "Descrição", "Status": "Status",
    "How to use": "Como usar", "Command that will run": "Comando que será executado",
    "Confirmation required": "Confirmação necessária", "Live log": "Log ao vivo", "Results": "Resultados",
    "Hosts": "Hosts", "Ports and services": "Portas e serviços", "Subnet map": "Mapa de sub-redes",
    "Findings": "Achados", "Vulnerabilities": "Vulnerabilidades", "OSINT records": "Registros OSINT",
    "Wi-Fi networks": "Redes Wi-Fi", "Operation history": "Histórico de operações", "Details": "Detalhes",
    "Report on everything stored": "Relatório de tudo que está armazenado",
    "Report on one operation": "Relatório de uma operação",
    "Switch passive / active mode": "Alternar modo passivo / ativo", "Change operator": "Alterar operador",
    "Reload scope.yaml": "Recarregar scope.yaml",
    "Check external tools (runs each tool)": "Verificar ferramentas externas (executa cada uma)",
    "Show audit log": "Mostrar log de auditoria", "Change language (pt/en)": "Mudar idioma (pt/en)",
    "Current configuration": "Configuração atual", "External tools": "Ferramentas externas",
    "Switch to ACTIVE mode": "Mudar para o modo ATIVO",
    "Operator": "Operador", "Mode": "Modo", "Rate limit": "Limite de taxa", "Timeout": "Tempo limite",
    "Database": "Banco de dados", "Logs": "Logs", "Reports": "Relatórios", "Engagement": "Engajamento",
    "Language": "Idioma", "Scope IPs": "IPs no escopo", "Scope subnets": "Sub-redes no escopo",
    "Scope domains": "Domínios no escopo", "Scope interfaces": "Interfaces no escopo",
    "Own BSSIDs": "BSSIDs próprios",
    "Address": "Endereço", "Hostname": "Hostname", "MAC": "MAC", "Vendor": "Fabricante", "Type": "Tipo",
    "OS guess": "SO provável", "Open ports": "Portas abertas", "Host": "Host", "Port": "Porta",
    "State": "Estado", "Service": "Serviço", "Product": "Produto", "Version": "Versão",
    "Severity": "Severidade", "Title": "Título", "Target": "Alvo", "Recommendation": "Recomendação",
    "Started (UTC)": "Início (UTC)", "Result": "Resultado", "Module": "Módulo", "Tool": "Ferramenta",
    "Version / reason": "Versão / motivo", "passive": "passivo", "active": "ativo", "intrusive": "intrusivo",
    "ready": "pronta", "ok": "ok", "missing": "ausente",
    "Toggle mode": "Alternar modo", "Tools": "Ferramentas", "Reload scope": "Recarregar escopo",
    "Report": "Relatório", "Inventory": "Inventário", "Modules": "Módulos",
    "Select an action": "Selecione uma ação", "Browse": "Procurar", "Interface": "Interface",
    "File": "Arquivo", "How to use & exact command": "Como usar e comando exato",
    "Preview command": "Pré-visualizar comando", "Run": "Executar", "Ready": "Pronto",
    "Report format": "Formato do relatório", "Select a file": "Selecione um arquivo",
    "Inventory shown": "Inventário exibido", "Error": "Erro",
}

PHRASES: dict[str, str] = {
    "authorized use only": "uso somente autorizado",
    "not yet available in this version.": "ainda não disponível nesta versão.",
    "not yet available": "ainda não disponível",
    "Unknown option.": "Opção desconhecida.", "Session closed.": "Sessão encerrada.",
    "press Enter to continue": "pressione Enter para continuar",
    "example command:": "exemplo de comando:", "command that will run:": "comando que será executado:",
    "consent required": "exige consentimento",
    "needs root (run with sudo)": "precisa de root (execute com sudo)",
    "requires root (run with sudo)": "requer root (execute com sudo)",
    "No target given; nothing was run.": "Nenhum alvo informado; nada foi executado.",
    "waiting for output…": "aguardando saída…",
    "Raw tool output kept at:": "Saída bruta da ferramenta salva em:",
    "Nothing stored yet.": "Nada armazenado ainda.",
    "No such operation.": "Operação inexistente.", "Unknown format.": "Formato desconhecido.",
    "Report written": "Relatório gerado",
    "Could not write the report:": "Não foi possível gravar o relatório:",
    "Scope is empty: no active operation can run. Edit config/scope.yaml and reload.":
        "O escopo está vazio: nenhuma operação ativa pode rodar. Edite config/scope.yaml e recarregue.",
    "scope problem:": "problema no escopo:", "Mode unchanged.": "Modo inalterado.",
    "Mode is now": "O modo agora é", "Operator unchanged.": "Operador inalterado.",
    "Scope reloaded.": "Escopo recarregado.", "No configuration directory.": "Sem diretório de configuração.",
    "Language is now": "O idioma agora é", "Checking tools": "Verificando ferramentas",
    "Active mode lets KSIF send traffic to the targets in your scope.":
        "O modo ativo permite que o KSIF envie tráfego aos alvos do seu escopo.",
    "Only continue if you own these systems or hold written authorization.":
        "Continue apenas se os sistemas forem seus ou se você tiver autorização por escrito.",
    "I am authorized to assess every target in scope": "Tenho autorização para avaliar todos os alvos do escopo",
    "Intrusive action. Type the target again to confirm:": "Ação intrusiva. Digite o alvo novamente para confirmar:",
    "Proceed?": "Prosseguir?", "\\[y/N]": "\\[s/N]",
    "Interface (must be listed in scope.yaml)": "Interface (precisa estar no scope.yaml)",
    "File path": "Caminho do arquivo", "Operation #:": "Operação nº:",
    "Operator name:": "Nome do operador:", "Language (pt/en):": "Idioma (pt/en):",
    "(unavailable)": "(indisponível)", "between operations": "entre operações",
    "scope entries": "itens no escopo", "Could not save settings:": "Não foi possível salvar as configurações:",
    "Audit log (latest first)": "Log de auditoria (mais recentes primeiro)",
    "Vulnerabilities (by priority)": "Vulnerabilidades (por prioridade)",
    "tools:[/]": "ferramentas:[/]", "note:[/]": "nota:[/]", "target:[/]": "alvo:[/]",
    "(no target: uses stored data)": "(sem alvo: usa dados armazenados)",
    "network interface (e.g. wlan0)": "interface de rede (ex.: wlan0)",
    "path to a local file": "caminho de um arquivo local",
    "not installed": "não instalada", "as operator": "como operador",
    # scope / engine messages
    "is not fully inside the authorized scope": "não está totalmente dentro do escopo autorizado",
    "is not in the authorized scope": "não está no escopo autorizado",
    "outside the authorized IP scope": "fora do escopo de IPs autorizado", "resolves to": "resolve para",
    "passive mode blocks": "o modo passivo bloqueia",
    "switch to active mode in Configuration": "mude para o modo ativo em Configuração",
    "invalid target:": "alvo inválido:", "missing tools:": "ferramentas ausentes:",
    "missing tool:": "ferramenta ausente:", "accepts only:": "aceita apenas:",
    "operator declined confirmation": "o operador recusou a confirmação",
    "operator declined the consent statement": "o operador recusou a declaração de consentimento",
    # parameter prompts
    "Ports, e.g. 22,80,443 or 1-1024 (empty = default)": "Portas, ex.: 22,80,443 ou 1-1024 (vazio = padrão)",
    "Network interface (must be in scope), e.g. eth0": "Interface de rede (precisa estar no escopo), ex.: eth0",
    "Packets per second (empty = 100, hard cap 1000)": "Pacotes por segundo (vazio = 100, teto fixo 1000)",
    "Capture duration in seconds (empty = 30, max 300)": "Duração da captura em segundos (vazio = 30, máx. 300)",
    "Wordlist path (empty = tool default)": "Caminho da wordlist (vazio = padrão da ferramenta)",
    "Hash format (empty = auto-detect)": "Formato do hash (vazio = detectar automaticamente)",
    "Password to evaluate (input is not stored)": "Senha a avaliar (não é armazenada)",
    "Minimum length required by your policy (empty = 12)": "Tamanho mínimo exigido pela sua política (vazio = 12)",
    "Product and version, e.g. nginx 1.18.0": "Produto e versão, ex.: nginx 1.18.0",
    "theHarvester sources (empty = crtsh,bing,duckduckgo)": "Fontes do theHarvester (vazio = crtsh,bing,duckduckgo)",
    "Port (empty = 443)": "Porta (vazio = 443)",
    "Force a fresh scan? yes/no (empty = no)": "Forçar nova varredura? yes/no (vazio = não)",
    "nuclei severities (empty = low,medium,high,critical)": "Severidades do nuclei (vazio = low,medium,high,critical)",
    # GUI fragments
    "Cannot run:": "Não é possível executar:", "Switch to ACTIVE mode?": "Mudar para o modo ATIVO?",
    "confirmation required": "confirmação necessária", "Problems:": "Problemas:",
    "Active mode sends traffic to targets in your scope. Continue only if you are authorized.":
        "O modo ativo envia tráfego aos alvos do seu escopo. Continue apenas se tiver autorização.",
    "Inventory shown": "Inventário exibido", "Scope reloaded.": "Escopo recarregado.",
    "Report written:": "Relatório gerado:", "Running ": "Executando ", "Operation #": "Operação nº ",
    "intrusiveness:": "intrusividade:",
    "BLOCKED": "BLOQUEADO", "FAILED": "FALHOU", "COMPLETED": "CONCLUÍDO",
}


def set_language(language: str) -> str:
    """Set the active language ('pt' or 'en'); returns the one in effect."""
    global _language  # noqa: PLW0603 - single process-wide UI language
    _language = "pt" if str(language).lower().startswith("pt") else "en"
    return _language


def language() -> str:
    return _language


def action_title(action: object) -> str:
    """Localized action title."""
    pt = getattr(action, "title_pt", "")
    return pt if (_language == "pt" and pt) else getattr(action, "title", "")


def action_description(action: object) -> str:
    """Localized action description."""
    pt = getattr(action, "description_pt", "")
    return pt if (_language == "pt" and pt) else getattr(action, "description", "")


def action_usage(action: object) -> str:
    """Localized 'how to use' text."""
    pt = getattr(action, "usage_pt", "")
    return pt if (_language == "pt" and pt) else getattr(action, "usage", "")


def t(text: str) -> str:
    """Translate one finished UI string for the active language."""
    if _language == "en" or not text:
        return text
    if text in EXACT:
        return EXACT[text]
    # one string wrapped in a single Rich tag, e.g. "[ksif.key]Run[/]"
    if text.startswith("[") and text.endswith("[/]") and "]" in text[1:]:
        open_tag, inner = text[: text.index("]") + 1], text[text.index("]") + 1 : -3]
        if inner in EXACT:
            return f"{open_tag}{EXACT[inner]}[/]"
    out = text
    for src, dst in PHRASES.items():
        if src in out:
            out = out.replace(src, dst)
    return out
