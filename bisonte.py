import requests
import time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from art import text2art

API_KEY = "tu_api" # Reemplaza con tu API Key de shodan
VULNERS_API_KEY = "tu_api"  # Reemplaza con tu API Key de Vulners
SHODAN_API_URL = "https://api.shodan.io/dns/domain/{domain}?key={key}"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"
VULNERS_API_URL = "https://vulners.com/api/v3/search/id/?id={cveId}"

console = Console()

def center_text(text, width):
    """Centra el texto en el ancho especificado."""
    lines = text.split("\n")
    return "\n".join(line.center(width) for line in lines)

def print_banner():
    # Generar el arte ASCII para el nombre de la herramienta
    banner_text = text2art("Bisonte", font="block")
    scan_text = text2art("Scan", font="starwars")  # Puedes cambiar el font para hacer el texto más pequeño o ajustado
    
    # Obtener el ancho de la consola
    width = console.width

    # Centrando el texto en el ancho de la consola
    centered_banner = center_text(banner_text, width)
    centered_scan = center_text(scan_text, width)
    
    # Imprimir el banner en la consola
    console.print(centered_banner, style="bold red")
    console.print(centered_scan, style="bold red")
    console.print("[bold green]Una herramienta avanzada para escanear y evaluar vulnerabilidades.[/bold green]")
    console.print("[bold blue]Desarrollado por Nestor Monsalve[/bold blue]")
    console.print("[bold yellow]Versión: 1.0.0[/bold yellow]\n")

def fetch_dns_records(domain):
    try:
        response = requests.get(SHODAN_API_URL.format(domain=domain, key=API_KEY))
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        console.print(f"Error en la solicitud a Shodan: {e}", style="bold red")
        return {}

def get_ports_from_shodan(ip):
    try:
        response = requests.get(SHODAN_HOST_URL.format(ip=ip, key=API_KEY))
        response.raise_for_status()
        data = response.json()
        ports = data.get("ports", [])
        return ports
    except requests.RequestException as e:
        console.print(f"Error al obtener puertos de Shodan para IP {ip}: {e}", style="bold red")
        return []

def get_vulnerabilities_from_shodan(ip):
    try:
        response = requests.get(SHODAN_HOST_URL.format(ip=ip, key=API_KEY))
        response.raise_for_status()
        data = response.json()

        vulnerabilities = []
        if "vulns" in data:
            for vuln in data["vulns"]:
                vuln_data = {}
                if isinstance(data["vulns"], dict):
                    vuln_data = data["vulns"].get(vuln, {})
                else:
                    vuln_data["cvss"] = data.get("cvss", "N/A")
                    vuln_data["summary"] = data.get("description", "No description available")

                cvss = vuln_data.get("cvss", "N/A")
                description = vuln_data.get("summary", "No description available")
                vulnerabilities.append((vuln, cvss, description))
                
        return vulnerabilities

    except requests.RequestException as e:
        if e.response and e.response.status_code == 404:
            console.print(f"IP {ip} no encontrada en Shodan.", style="yellow")
        else:
            console.print(f"Error al obtener vulnerabilidades de Shodan para IP {ip}: {e}", style="bold red")
        return []

def get_cvss_from_vulners(cve_id):
    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {VULNERS_API_KEY}'
        }
        response = requests.get(VULNERS_API_URL.format(cveId=cve_id), headers=headers)
        response.raise_for_status()
        data = response.json()

        # Imprimir el JSON completo para depuración
        console.print(f"Respuesta de Vulners para {cve_id}: {data}", style="bold yellow")

        # Verificar si 'cvss' está presente y extraer 'score'
        if 'data' in data and 'documents' in data['data'] and cve_id in data['data']['documents']:
            document = data['data']['documents'][cve_id]
            if 'cvss' in document and 'score' in document['cvss']:
                score = document['cvss']['score']
                return str(score)
            else:
                console.print(f"No se encontró información de CVSS para el CVE {cve_id}.", style="yellow")
                return "N/A"
        else:
            console.print(f"No se encontró información de CVSS para el CVE {cve_id}.", style="yellow")
            return "N/A"

    except requests.RequestException as e:
        console.print(f"Error al obtener CVSS para CVE {cve_id}: {e}", style="bold red")
        return "N/A"
    except ValueError:
        console.print(f"Error al obtener CVSS para CVE {cve_id}: Respuesta vacía o inválida.", style="bold red")
        return "N/A"

def main():
    print_banner()  # Mostrar el banner al inicio
    
    domain = input("Introduce el dominio principal (por ejemplo, sudominio.com.co): ").strip()

    data = fetch_dns_records(domain)
    if not data:
        console.print("No se encontraron registros DNS.", style="bold red")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Subdominio", style="dim")
    table.add_column("Tipo DNS", style="dim")
    table.add_column("IP", style="dim")
    table.add_column("Puertos", style="dim")

    ips_detectadas = set()

    with Progress() as progress:
        task = progress.add_task("[cyan]Procesando registros DNS...", total=len(data.get('data', [])))
        for record in data.get('data', []):
            subdomain = record['subdomain'] if record['subdomain'] else domain
            record_type = record['type']
            value = record['value']

            if record_type == "A":
                ip = value
                ports = get_ports_from_shodan(ip)
                ports_str = ', '.join(map(str, ports))
                table.add_row(subdomain, record_type, ip, ports_str)
                ips_detectadas.add(ip)
            else:
                table.add_row(subdomain, record_type, "", value)

            console.clear()
            console.print(table)
            progress.update(task, advance=1)

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
                vulnerabilities = get_vulnerabilities_from_shodan(ip)
                for cve, _, _ in vulnerabilities:
                    cvss = get_cvss_from_vulners(cve)
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
