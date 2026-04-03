import socket
import threading
import json
import datetime
import re

open_ports = []
lock = threading.Lock()


def scan_port(target, port):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

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

import re

def extract_version(banner):
    patterns = [
        r"OpenSSH[_\s]?([\d\.]+)",
        r"Apache/([\d\.]+)",
        r"Python/([\d\.]+)",
        r"SimpleHTTP/([\d\.]+)",
        r"VMware.*?([\d\.]+)"
    ]

    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(0).strip().title()  

    return None

def generate_report(open_ports):
    print("\n--- Relatório de Segurança ---\n")

    for item in open_ports:
        port = item["port"]
        banner = item["banner"].lower()

        version_info = extract_version(banner)

        if "ssh" in banner:
            print(f"[PORTA {port}] SSH detectado via banner")

            if version_info:
                print(f"Versão detectada: {version_info}")

            print("Risco: Possível ataque de força bruta\n")

        elif "apache" in banner or "http" in banner:
            print(f"[PORTA {port}] HTTP detectado via banner")

            if version_info:
                print(f"Versão detectada: {version_info}")

            print("Risco: Possíveis vulnerabilidades web\n")

        elif "vmware" in banner:
            print(f"[PORTA {port}] VMware Service detectado")

            if version_info:
                print(f"Versão detectada: {version_info}")

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

def main():
    open_ports.clear()

    target = input("Digite o IP ou domínio: ")

    print(f"\nEscaneando alvo: {target}\n")

    threads = []

    for port in range(1, 1000):
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()

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

    generate_report(open_ports)

    print("\nResultados salvos em results/scan.json")


if __name__ == "__main__":
    main()