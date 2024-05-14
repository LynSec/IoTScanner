import sys
import nmap
from concurrent.futures import ThreadPoolExecutor

def scan_port(target_ip, port):
    scanner = nmap.PortScanner()
    scan_arguments = f'-sV -Pn -sT --script=vuln -p {port} --min-rate 100 --max-retries 1 -T4'
    scan_results = scanner.scan(target_ip, arguments=scan_arguments)
    
    results = []
    for host in scan_results['scan']:
        for proto in scan_results['scan'][host].all_protocols():
            lport = scan_results['scan'][host][proto].keys()
            for port in sorted(lport):
                port_data = scan_results['scan'][host][proto][port]
                if port_data['state'] == 'open':  # Filter for open ports only
                    results.append({
                        'port': port,
                        'status': port_data['state'],
                        'service': port_data.get('name', 'n/a'),
                        'product': port_data.get('product', 'n/a'),
                        'version': port_data.get('version', 'n/a'),
                        'extra_info': port_data.get('extrainfo', 'n/a')
                    })
    return results

def scan_vulnerabilities(target_ip, start_port, end_port):
    ports = range(int(start_port), int(end_port) + 1)
    with ThreadPoolExecutor(max_workers=20) as executor:  # Increased number of threads
        future_to_port = {executor.submit(scan_port, target_ip, port): port for port in ports}
        results = []
        for future in future_to_port:
            results.extend(future.result())
    return results

if __name__ == "__main__":
    if len(sys.argv) == 4:
        ip = sys.argv[1]
        start_port = sys.argv[2]
        end_port = sys.argv[3]
        scan_results = scan_vulnerabilities(ip, start_port, end_port)
        for result in scan_results:
            print(result)
    else:
        print("Usage: scan.py <target_ip> <start_port> <end_port>")

