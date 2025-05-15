import nmap
import socket
import requests

# Manually specify the path to nmap.exe (adjust if necessary)
nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"  # Update this path if necessary

def scan_ports(target):
    print(f"[+] Scanning ports on {target}...\n")
    nm = nmap.PortScanner()

    # Specify nmap executable path during initialization
    nm._nmap_exec = nmap_path  # Set the nmap executable path

    # Scan ports 1-1024 to cover common ports
    nm.scan(target, arguments='-T4 -p 1-1024')  # Fast scan over common ports
    for host in nm.all_hosts():
        print(f"Host: {host}")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                state = nm[host][proto][port]['state']
                name = nm[host][proto][port]['name']
                print(f"  Port {port}/{proto} is {state} ({name})")
                grab_banner(target, port)

def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore")
        print(f"    Banner: {banner.strip()}")
        search_cve(banner.strip())
        check_http_error_code(banner.strip())  # Check for specific HTTP error codes
        sock.close()
    except:
        pass

def search_cve(banner):
    if not banner:
        return
    print("    [+] Checking for known CVEs...")
    try:
        # Query based on a broad search for software or device banners
        query = banner.split('\n')[0][:80]  # Trim banner to first line for better results
        url = f"https://cve.circl.lu/api/search/{query}"
        r = requests.get(url, timeout=5)
        data = r.json()
        if 'results' in data and data['results']:
            for vuln in data['results'][:3]:  # Show top 3 vulnerabilities found
                print(f"      [!] CVE Found: {vuln['id']} - {vuln['summary']}")
        else:
            print("      [-] No CVEs found for this banner.")
    except Exception as e:
        print(f"      [!] CVE check failed (network or API error): {e}")

def check_http_error_code(banner):
    # Handle common HTTP error codes to suggest vulnerabilities
    if '400 Bad Request' in banner:
        print(f"      [!] Possible vulnerability due to bad request error (400). Check input validation.")
    elif '403 Forbidden' in banner:
        print(f"      [!] Potential misconfiguration. This could be due to directory permissions.")
    elif '404 Not Found' in banner:
        print(f"      [!] This might indicate outdated or exposed services.")
    elif '500 Internal Server Error' in banner:
        print(f"      [!] Check server for possible misconfigurations or outdated software.")
    elif '502 Bad Gateway' in banner:
        print(f"      [!] Potential misconfiguration in reverse proxy or gateway.")
    elif '503 Service Unavailable' in banner:
        print(f"      [!] Check if the service is overwhelmed or misconfigured.")
    elif '504 Gateway Timeout' in banner:
        print(f"      [!] Network issue or service timeout detected.")

if __name__ == "__main__":
    target_ip = input("Enter IP address to scan: ").strip()
    scan_ports(target_ip)
