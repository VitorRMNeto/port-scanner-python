# Port Scanner com Análise de Segurança 
```bash
Ferramenta de port scanning desenvolvida em Python com identificação de serviços, extração de versões e correlação com vulnerabilidades (CVE), voltada para análise de segurança e reconhecimento de superfície de ataque.
```
## 🚀 Funcionalidades

- 🔎 Scan de portas com multithreading (alta performance)
- 🌐 Identificação de serviços via banner + porta
- 🧠 Detecção inteligente de protocolos:
  - HTTP / HTTPS
  - SSH
  - FTP
  - SMTP
  - POP3 / IMAP
  - DNS / RPC
- 📦 Extração de versão de serviços
- 🛡️ Correlação com CVE (vulnerabilidades conhecidas)
- 📊 Classificação de severidade:
  - CRITICAL
  - HIGH
  - MEDIUM
  - LOW
- 💾 Exportação dos resultados em JSON


## ▶️ Como utilizar

### 1. Clonar o repositório

```bash
git clone https://github.com/VitorRMNeto/port-scanner-python.git
cd port-scanner-python
```

### 2. Executar o script

```bash
py scanner.py
```

### 3. Informar o alvo

Digite o IP ou domínio (exemplo):
```bash
scanme.nmap.org
```

## 📊 Exemplo de Saída

```bash
[PORTA 80] HTTP detectado
Versão detectada: apache/2.4.7

Possíveis CVEs:
 - CVE-2012-2379 (CRITICAL - 10.0)
 - CVE-2013-2249 (HIGH - 7.5)

Risco: Possíveis vulnerabilidades web
```

## 📁 Estrutura de saída (JSON)
### Resultados salvos em:
```bash
results/scan.json
```
### Exemplo:
```bash
{
  "target": "scanme.nmap.org",
  "scan_time": "2026-04-03T16:02:24",
  "open_ports": [
    {
      "port": 80,
      "service": "http",
      "version": "apache/2.4.7",
      "cves": [
        {
          "id": "CVE-2012-2379",
          "severity": "CRITICAL",
          "score": 10.0
        }
      ]
    }
  ]
}
```
## ⚠️ Observações importantes

A identificação de serviços é baseada em:
- análise de banner
- Fallback por porta
- Nem todos os serviços expõem versão
- A ausência de CVEs não significa que o serviço é seguro
- A busca por vulnerabilidades é uma correlação básica, não substitui ferramentas como scanners profissionais
### Limitações:
- Dependência de banners (nem todos os serviços expõem versão)
- Correlação básica de CVE (não substitui scanners profissionais)
- Não realiza exploração, apenas identificação

## 🛠️ Tecnologias utilizadas
Python 3
Socket
Threading
JSON

