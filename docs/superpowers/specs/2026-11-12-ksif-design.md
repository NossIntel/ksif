# KSIF — Kali Security Intelligence Framework: Design

Data: 2026-11-12 · Status: aguardando revisão

## 1. Entendimento

**O que você pediu.** Um framework modular de terminal para Kali Linux que centraliza
ferramentas de segurança consolidadas (Nmap, Amass, Nuclei, etc.), automatiza
reconhecimento, OSINT, avaliação web, auditoria Wi-Fi, análise de senhas e
inteligência de vulnerabilidades, grava tudo em SQLite e gera relatórios técnicos.
Toda operação fica restrita a um escopo autorizado explícito. O projeto vai para o
GitHub com instalador, testes e documentação.

**Critério de sucesso (seu item 11).** Instala em Kali limpo, inicia pelo terminal,
módulos executam operações reais, ferramentas externas são detectadas, resultados
são interpretados e armazenados, relatórios são gerados, testes passam, e a
documentação basta para outra pessoa instalar e usar.

**Suposições minhas (corrija se estiverem erradas).**

- Uso em redes e sistemas próprios ou com autorização formal (pentest, laboratório).
- Código, nomes e mensagens da interface em inglês; README em inglês com seção em
  português.
- Licença GPL-3.0 (padrão do ecossistema Kali).
- Repositório GitHub criado como **privado** primeiro; a publicação só acontece com
  sua confirmação explícita.

## 2. Limitação deste ambiente

Esta máquina é Windows 11, sem WSL, sem Docker e sem Nmap. Python 3.15 e Git estão
disponíveis. Consequências:

- **Verificável aqui:** validação de escopo, construção segura de comandos, parsers
  (contra saídas reais gravadas como fixtures), banco, relatórios, lógica de senhas,
  correlação de CVE, interface (smoke test).
- **Não verificável aqui:** `install.sh` em Kali limpo e a execução real de Nmap,
  airodump-ng, hashcat etc.

**Proposta:** um workflow de GitHub Actions que roda dentro do contêiner oficial
`kalilinux/kali-rolling`, executa `install.sh` e os testes de integração contra
`127.0.0.1`. Isso dá prova real do critério de aceitação para tudo que não exige
hardware. Wi-Fi (precisa de adaptador em modo monitor) e hashcat com GPU só podem
ser validados por você em uma máquina Kali. Nada será declarado concluído sem a
evidência correspondente.

## 3. Decomposição

O projeto é grande demais para um único plano. Divido em marcos, cada um com plano,
implementação e testes próprios, seguindo suas 10 fases:

| Marco | Fases | Entrega |
|---|---|---|
| M1 | 1–3 | Núcleo, segurança/escopo, TUI, configuração, Nmap + descoberta de rede, banco, relatório básico (JSON/Markdown) |
| M2 | 4–5 | OSINT e avaliação web |
| M3 | 6–7 | Auditoria Wi-Fi e laboratório de senhas |
| M4 | 8–9 | Inteligência de vulnerabilidades, motor de relatórios completo, inventário de ativos |
| M5 | 10 | CI em Kali, documentação final, publicação |

M1 já é um produto utilizável de ponta a ponta (escanear → armazenar → relatar).
Esta spec define a arquitetura de todos os marcos e detalha M1.

## 4. Arquitetura

Estrutura de diretórios exatamente como no seu item 6. Camadas, de baixo para cima:

1. **`core/`** — sem dependência de interface.
   - `validator.py`: analisa e normaliza alvos (IPv4/IPv6, CIDR, domínio, URL,
     interface, caminho de arquivo). Rejeita qualquer entrada que comece com `-` ou
     contenha metacaracteres.
   - `permissions.py`: `ScopeGuard` carrega `config/scope.yaml` (allowlist de IPs,
     sub-redes, domínios, BSSIDs próprios) e responde `authorize(alvo, intrusividade)`.
     Também verifica root/capabilities e o modo passivo/ativo.
   - `subprocess_manager.py`: **único** ponto que executa processos. Usa
     `asyncio.create_subprocess_exec` com lista de argumentos (nunca shell), só
     aceita binários de uma lista fixa, aplica timeout, e exige um token de
     autorização emitido pelo `ScopeGuard` para cada alvo. Emite linhas de saída em
     streaming para os logs em tempo real.
   - `logger.py`: log estruturado em JSON Lines + trilha de auditoria (operador,
     data/hora UTC, módulo, comando exato, alvo, decisão de escopo, código de saída).
   - `database.py`: SQLite com migrações versionadas.
   - `engine.py`: registro de módulos, ciclo de vida de uma operação (autorizar →
     confirmar → executar → interpretar → persistir), limitador de taxa.
2. **`integrations/`** — um arquivo por ferramenta. Contrato comum (`ToolIntegration`):
   `is_available()`, `version()`, `self_test()` (execução real e inofensiva, ex.
   `nmap --version`), construtores de comando tipados (sem flags livres do usuário)
   e `parse(saída) -> modelos`. Preferência por saídas estruturadas (XML do Nmap,
   JSON do Nuclei/Subfinder/WhatWeb).
3. **`modules/`** — lógica de cada domínio; orquestra integrações e devolve modelos
   tipados. Não imprime nada.
4. **`ui/`** (dentro de `modules/` não cabe; fica em `ksif/ui/`, única adição à sua
   árvore) — interface Rich: banner, menus, progresso, painel de logs, histórico.
   Só chama o `engine`.

Um módulo novo = uma pasta em `modules/` que registra suas ações no `engine`. A
futura interface web consumiria o mesmo `engine`, sem tocar em módulos.

## 5. Modelo de segurança

- Sem `scope.yaml` preenchido, nenhuma operação ativa roda. Escopo vazio é o padrão.
- Cada ação declara intrusividade: `passive`, `active`, `intrusive`. Modo passivo
  bloqueia as duas últimas; `intrusive` sempre pede confirmação digitada.
- Alvo fora da allowlist → bloqueado e registrado na auditoria. Domínios resolvem
  para IPs antes da execução, e os IPs resolvidos também precisam estar no escopo
  para operações ativas.
- Limites de taxa configuráveis com teto fixo no código (ex.: Masscan e Nmap).
- **Wi-Fi:** o código não contém nenhuma função de desautenticação, injeção ou
  captura de handshake de terceiros (`aireplay-ng` fica fora da lista de binários).
  Somente coleta passiva (airodump-ng/Kismet) e análise de configuração; auditoria
  detalhada só para BSSIDs listados como próprios no escopo.
- **Senhas:** somente offline, sobre arquivos de hash fornecidos pelo operador, com
  declaração de propriedade registrada na auditoria. Sem Hydra/Medusa nem qualquer
  ataque online a serviços ou contas.
- **WPScan:** exige alvo no escopo marcado como `wordpress_owned: true`.
- Nenhuma credencial no código; chaves de API (NVD, WPScan) vêm de variáveis de
  ambiente.

## 6. Dados

Tabelas: `operations`, `audit_log`, `hosts`, `ports`, `services`, `domains`,
`dns_records`, `certificates`, `web_findings`, `wifi_networks`, `password_audits`,
`vulnerabilities`, `assets`, `reports`. Toda linha referencia a `operation` que a
gerou, o que dá histórico e rastreabilidade para os relatórios.

## 7. Integrações — o que é real e o que é limitado

Você pediu que nada seja simulado. Estes pontos da lista não têm automação honesta
possível e ficam assim:

- **Maltego:** é uma aplicação gráfica. Entrega: exportação de entidades em CSV/
  GraphML importável no Maltego. Sem "integração" de execução.
- **Wireshark:** uso do `tshark` (mesmo motor) para captura e análise; o KSIF apenas
  oferece abrir o `.pcap` no Wireshark.
- **Wappalyzer:** não tem mais CLI oficial mantida. Fingerprinting por WhatWeb e
  templates de tecnologia do Nuclei.
- **OWASP ZAP:** modo baseline (passivo) via `zap-baseline.py`/`zap.sh -cmd`; active
  scan só com intrusividade `intrusive`.
- **SpiderFoot, Recon-ng:** execução por CLI com módulos passivos; cobertura menor
  que a das demais ferramentas.
- **PDF:** via WeasyPrint a partir do HTML; se a biblioteca não estiver instalada,
  a opção aparece como indisponível, não falha silenciosamente.
- **Termux:** apenas o que funciona sem root (OSINT, senhas, relatórios); o resto é
  marcado como indisponível na detecção de dependências.

## 8. Erros

Ferramenta ausente → ação desabilitada no menu com instrução de instalação. Timeout,
saída não interpretável ou código de saída inesperado → operação marcada `failed`
com a saída bruta preservada em `logs/`; nunca um resultado parcial apresentado como
completo. Falta de root → mensagem clara antes de executar.

## 9. Testes

- **Unitários (rodam em qualquer SO):** validador, `ScopeGuard`, construção de
  comandos (incluindo tentativas de injeção), parsers com fixtures, banco,
  relatórios, entropia/políticas de senha, priorização de CVE.
- **Integração (`pytest -m integration`):** executam as ferramentas reais contra
  `127.0.0.1`; pulam com motivo explícito se a ferramenta não existir. Rodam no CI
  Kali.
- Testes negativos de segurança: alvo fora do escopo, modo passivo, binário não
  permitido — todos devem ser bloqueados e auditados.

## 10. Detalhe do M1

- Fase 1: `core/` completo, modelos, banco com migrações, testes.
- Fase 2: `main.py`, TUI Rich (banner, menu de 10 itens, submenus, progresso, logs
  ao vivo, histórico), `settings.yaml`/`scope.yaml`, tela de Configuration com
  detecção de ferramentas.
- Fase 3: integrações Nmap, arp-scan, Masscan (com teto de taxa) e tshark; módulo
  Network Discovery (hosts ativos, IPv4/IPv6, MAC + fabricante por OUI, portas,
  serviços/versões, fingerprint de SO, tipo provável de dispositivo, mapa de
  sub-redes, topologia por traceroute); persistência; relatório JSON/Markdown;
  `install.sh`, `check_dependencies.sh`.

Itens 4–10 do menu aparecem desde o M1, mas marcados "not yet available" até o
marco correspondente — sem telas simuladas.
