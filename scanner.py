import socket
import threading
import json
import datetime
import re
import requests
import time

open_ports = []
lock = threading.Lock()

def search_cves(service, version):
    try:
        query = f"{service} {version}"
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        params = {
            "keywordSearch": query,
            "resultsPerPage": 10
        }

        response = requests.get(url, params=params, timeout=5)
        data = response.json()

        cves = []

        for item in data.get("vulnerabilities", []):
            cve_data = item["cve"]
            cve_id = cve_data["id"]

            score = 0
            severity = "UNKNOWN"

            metrics = cve_data.get("metrics", {})

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score = cvss.get("baseScore", 0)
                severity = cvss.get("baseSeverity", "UNKNOWN")

            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                score = cvss.get("baseScore", 0)
                severity = cvss.get("baseSeverity", "UNKNOWN")

            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score = cvss.get("baseScore", 0)
                severity = "LEGACY"

            if score >=9:
                severity = "CRITICAL"

            elif score >=7:
                severity = "HIGH"

            elif score >=4:
                severity = "MEDIUM"

            else:
                severity = "LOW"

            cves.append({
                "id": cve_id,
                "score": score,
                "severity": severity
            })

        cves = sorted(cves, key=lambda x: x["score"], reverse=True)

        return cves[:3]  # top 3

    except:
        return []

def scan_port(target, port):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)

        result = s.connect_ex((target, port))

        if result == 0:
            banner = ""

            try:
                s.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore")
            except:
                try:
                    banner = s.recv(1024).decode(errors="ignore")
                except:
                    banner = "Não identificado"

            with lock:
                print(f"[+] Porta {port} aberta")
                print(f"    Banner: {banner[:100]}")
                open_ports.append({
                    "port": port,
                    "banner": banner[:100]
                })

    except:
        pass

    finally:
        if s:
            s.close()

def extract_version(banner):
    patterns = [
        r"OpenSSH[_\s]?([\d\.p]+)",
        r"Apache/([\d\.]+)",
        r"Python/([\d\.]+)",
        r"SimpleHTTP/([\d\.]+)",
        r"VMware.*?([\d\.]+)"
    ]

    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(0)  

    return None

def identify_service(port, banner):
    banner = banner.lower()

    if "ssh" in banner:
        return "ssh"

    if "ftp" in banner or "pure-ftpd" in banner:
        return "ftp"

    if "smtp" in banner or "exim" in banner:
        return "smtp"

    if "dovecot" in banner or "+ok" in banner:
        return "pop3"

    if "imap" in banner:
        return "imap"

    if "nginx" in banner or "apache" in banner or "http" in banner:
        return "http"

    if "vmware" in banner:
        return "vmware"

    if port == 21:
        return "ftp"
    elif port in [25, 26, 465, 587]:
        return "smtp"
    elif port == 110:
        return "pop3"
    elif port == 143:
        return "imap"
    elif port == 53:
        return "dns"
    elif port == 443:
        return "https"
    elif port == 111:
        return "rpc"
    elif port == 993:
        return "imaps"
    elif port == 995:
        return "pop3s"

    return "unknown"

def generate_report(open_ports):
    print("\n--- Relatório de Segurança ---\n")

    scan_results = []

    for item in open_ports:
        port = item["port"]
        banner = item["banner"].lower()
        version_info = extract_version(banner)
        service = "unknown"
        version= version_info if version_info else "unknown"
        cves = []
        service = identify_service(port, banner)

        if service == "ssh":
            print(f"[PORTA {port}] SSH detectado via banner")

            if version_info:
                print(f"Versão detectada: {version_info}")

                parts = version_info.split("/")
                if len(parts) == 2:
                    service_name = parts[0].replace("_", " ").lower()
                    version = parts[1].lower()
                    version_short = ".".join(version.split(".")[:2])

                    cves = search_cves(service, version_short)

                    print("Possíveis CVEs:")

                    if cves:
                        for cve in cves:
                            print(f" - {cve['id']} ({cve['severity']} - {cve['score']})")
                    else:
                        print(" - Nenhuma CVE encontrada")

            print("Risco: Possível ataque de força bruta\n")

        elif service == "http":
            print(f"[PORTA {port}] HTTP detectado via banner")

            version_info = "http"

            if version_info:
                print(f"Versão detectada: {version_info}")

                parts = version_info.split("/")
                if len(parts) == 2:
                    service_name = parts[0].replace("_", " ").lower()
                    version = parts[1]
                    version_short = ".".join(version.split(".")[:2])

                    cves = search_cves(service, version_short)

                    print("Possíveis CVEs:")

                    if cves:
                        for cve in cves:
                            print(f" - {cve['id']} ({cve['severity']} - {cve['score']})")
                    else:
                        print(" - Nenhuma CVE encontrada")

            print("Risco: Possíveis vulnerabilidades web\n")

        elif service == "ftp":
            print(f"[PORTA {port}] FTP detectado")
            print("Risco: Credenciais podem trafegar em texto plano\n")

        elif service == "smtp":
            print(f"[PORTA {port}] SMTP detectado")
            print("Risco: Possível uso para spam ou relay\n")

        elif service == "pop3":
            print(f"[PORTA {port}] POP3 detectado")
            print("Risco: Credenciais podem trafegar em texto plano\n")

        elif service == "imap":
            print(f"[PORTA {port}] IMAP detectado")
            print("Risco: Serviço de email exposto\n")

        elif service == "dns":
            print(f"[PORTA {port}] DNS detectado")
            print("Risco: Possível exposição de infraestrutura\n")

        elif service == "rpc":
            print(f"[PORTA {port}] RPC detectado")
            print("Risco: Comunicação interna exposta\n")

        elif service == "https":
            print(f"[PORTA {port}] HTTPS detectado")
            print("Risco: Verificar certificados e configurações TLS\n")

        elif service == "vmware":
            print(f"[PORTA {port}] VMware Service detectado")

            if version_info:
                print(f"Versão detectada: {version_info}")

                parts = version_info.split("/")
                if len(parts) == 2:
                    service_name = parts[0].replace("_", " ").lower()
                    version = parts[1]
                    version_short = ".".join(version.split(".")[:2])

                    cves = search_cves(service_name, version_short)

                    print("Possíveis CVEs:")

                    if cves:
                        for cve in cves:
                            print(f" - {cve['id']} ({cve['severity']} - {cve['score']})")
                    else:
                        print(" - Nenhuma CVE encontrada")

            print("Risco: Possível serviço de virtualização exposto\n")

        elif port == 445:
            print(f"[PORTA {port}] SMB detectado")
            print("Risco: Possível exploração SMB\n")

        elif port == 135:
            print(f"[PORTA {port}] RPC detectado")
            print("Risco: Comunicação interna do Windows\n")

        else:
            print(f"[PORTA {port}] Serviço desconhecido")
            print("Risco: Necessário investigar manualmente\n")

        scan_results.append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "cves": cves
                })
    
    return scan_results

def main():
    open_ports.clear()

    target = input("Digite o IP ou domínio: ")

    print(f"\nEscaneando alvo: {target}\n")

    threads = []

    for port in range(1, 1000):
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()
        time.sleep(0.01)

    for t in threads:
        t.join()

    result_data = {
        "target": target,
        "scan_time": datetime.datetime.now().isoformat(),
        "open_ports": open_ports
    }

    with open("results/scan.json", "w") as f:
        json.dump(result_data, f, indent=4)

    print("\nResumo:")

    if not open_ports:
        print("Nenhuma porta aberta encontrada")
    else:
        for item in sorted(open_ports, key=lambda x: x["port"]):
            print(f"Porta {item['port']} aberta")

    scan_results = generate_report(open_ports)

    result_data = {
    "target": target,
    "scan_time": str(datetime.datetime.now()),
    "results": scan_results
}
    with open("results/scan.json", "w") as f:
        json.dump(result_data, f, indent=4)

    print("\nResultados salvos em results/scan.json")

if __name__ == "__main__":
    main()