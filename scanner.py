import socket
import threading
import json
import datetime

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

def generate_report(open_ports):
    print("\n--- Relatório de Segurança ---\n")

    for item in open_ports:
        port = item["port"]
        banner = item["banner"].lower()

        if port == 22:
            print(f"[PORTA {port}] SSH detectado")
            print("Risco: Possível ataque de força bruta (brute force)\n")

        elif port == 80:
            print(f"[PORTA {port}] HTTP detectado")
            print("Risco: Possíveis vulnerabilidades web (XSS, SQL Injection)\n")

        elif port == 443:
            print(f"[PORTA {port}] HTTPS detectado")
            print("Risco: Verificar certificados e configuração SSL/TLS\n")

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