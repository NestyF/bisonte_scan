import requests
import time
import json
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from art import text2art
from pyfiglet import figlet_format  # Agregando pyfiglet para el banner

console = Console()
CONFIG_FILE = "config.json"

def center_text(text, width):
    """Centra el texto en el ancho especificado."""
    lines = text.split("\n")
    return "\n".join(line.center(width) for line in lines)

def print_banner():
    # Cambiando el banner por figlet "bisonte Scan" y ajustando el color
    banner_text = figlet_format("bisonte Scan", font="slant")
    width = console.width
    centered_banner = center_text(banner_text, width)
    console.print(centered_banner, style="bold red")
    console.print("Desarrollado por [bold blue]Nestor Monsalve[/bold blue]")
    console.print("Versión: [bold yellow]1.0.0[/bold yellow]\n")

def load_api_keys():
    """Cargar las API Keys desde el archivo de configuración si existe."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            config = json.load(file)
        return config.get("shodan_api_key"), config.get("vulners_api_key")
    return None, None

def save_api_keys(shodan_api_key, vulners_api_key):
    """Guardar las API Keys en un archivo de configuración."""
    with open(CONFIG_FILE, "w") as file:
        json.dump({"shodan_api_key": shodan_api_key, "vulners_api_key": vulners_api_key}, file)

def prompt_for_api_keys():
    """Pedir al usuario que introduzca las API Keys."""
    shodan_api_key = input("Introduce tu API Key de Shodan: ").strip()
    vulners_api_key = input("Introduce tu API Key de Vulners: ").strip()
    return shodan_api_key, vulners_api_key

def fetch_dns_records(domain, api_key):
    try:
        response = requests.get(f"https://api.shodan.io/dns/domain/{domain}?key={api_key}")
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return {}

def get_ports_and_services_from_shodan(ip, api_key):
    """Obtener los puertos y servicios desde Shodan."""
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}")
        response.raise_for_status()
        data = response.json()
        services = {}
        for service in data.get("data", []):
            port = service.get("port", "N/A")
            service_name = service.get("product", "Desconocido")
            services[port] = service_name
        return services
    except requests.HTTPError:
        return {}

def get_vulnerabilities_and_services_from_shodan(ip, api_key):
    """Obtener vulnerabilidades y servicios desde Shodan."""
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}")
        response.raise_for_status()
        data = response.json()

        vulnerabilities = []
        services = {}
        for service in data.get("data", []):
            port = service.get("port", "N/A")
            product = service.get("product", "Desconocido")
            services[port] = product
            if "vulns" in service:
                for vuln in service["vulns"]:
                    vulnerabilities.append({"cve": vuln, "cvss": "N/A", "port": port, "service": product})

        return vulnerabilities, services
    except requests.HTTPError:
        return [], {}

def get_cvss_from_vulners(cve_id, vulners_api_key):
    """Obtener el CVSS desde Vulners usando el CVE."""
    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {vulners_api_key}'
        }
        response = requests.get(f"https://vulners.com/api/v3/search/id/?id={cve_id}", headers=headers)
        response.raise_for_status()
        data = response.json()

        if 'data' in data and 'documents' in data['data'] and cve_id in data['data']['documents']:
            document = data['data']['documents'][cve_id]
            cvss = document['cvss']['score'] if 'cvss' in document and 'score' in document['cvss'] else "N/A"
            return str(cvss)
        else:
            return "N/A"
    except requests.RequestException:
        return "N/A"

def main():
    print_banner()  # Mostrar el banner al inicio

    # Cargar las API Keys desde el archivo de configuración
    shodan_api_key, vulners_api_key = load_api_keys()

    # Si no se encuentran las API Keys, pedirlas
    if not shodan_api_key or not vulners_api_key:
        shodan_api_key, vulners_api_key = prompt_for_api_keys()
        save_api_keys(shodan_api_key, vulners_api_key)

    domain = input("\nIntroduce el dominio principal (por ejemplo, sudominio.com.co): ").strip()

    # Crear la primera tabla (Subdominios, IPs, puertos)
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Subdominio", style="dim")
    table.add_column("Tipo DNS", style="dim")
    table.add_column("IP", style="dim")
    table.add_column("Puertos", style="dim")

    data = fetch_dns_records(domain, shodan_api_key)
    if not data:
        return

    ips_detectadas = set()

    # Procesar todos los registros y llenar la tabla de subdominios y puertos
    for record in data.get('data', []):
        subdomain = record['subdomain'] if record['subdomain'] else domain
        record_type = record['type']
        value = record['value']

        if record_type == "A":
            ip = value
            services = get_ports_and_services_from_shodan(ip, shodan_api_key)
            ports_str = ', '.join(f"{port} ({service})" for port, service in services.items())
            table.add_row(subdomain, record_type, ip, ports_str)
            ips_detectadas.add(ip)
        else:
            table.add_row(subdomain, record_type, "", value)

    # Mostrar la tabla con subdominios e IPs
    console.print(table)

    revisar_vulns = input("\n¿Deseas revisar las vulnerabilidades de las IPs detectadas? (s/n): ").strip().lower()
    if revisar_vulns == 's':
        vuln_table = Table(show_header=True, header_style="bold red")
        vuln_table.add_column("IP", style="dim")
        vuln_table.add_column("CVE", style="dim")
        vuln_table.add_column("CVSS", style="dim")

        vulnerabilities_by_ip = {}

        with Progress() as progress:
            task = progress.add_task("[cyan]Revisando vulnerabilidades...", total=len(ips_detectadas))
            for ip in ips_detectadas:
                vulnerabilities, services = get_vulnerabilities_and_services_from_shodan(ip, shodan_api_key)
                for vuln in vulnerabilities:
                    cve = vuln["cve"]
                    cvss = get_cvss_from_vulners(cve, vulners_api_key)
                    if ip not in vulnerabilities_by_ip:
                        vulnerabilities_by_ip[ip] = []
                    vulnerabilities_by_ip[ip].append((cve, cvss))

                time.sleep(1.5)  # Delay para evitar restricciones de la API
                progress.update(task, advance=1)

        console.clear()

        for ip, vulns in vulnerabilities_by_ip.items():
            first_entry = True
            for cve, cvss in vulns:
                if first_entry:
                    vuln_table.add_row(ip, cve, cvss)
                    first_entry = False
                else:
                    vuln_table.add_row("", cve, cvss)

        console.print(vuln_table)

if __name__ == "__main__":
    main()

