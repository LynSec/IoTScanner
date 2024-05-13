import sysimport nmapdef scan_host(target_ip):    scanner = nmap.PortScanner()    scan_arguments = '-v -sV -Pn -sT --script=banner --script=vuln'    scan_results = scanner.scan(target_ip, arguments=scan_arguments)        results = []    for host in scan_results['scan']:        host_data = scan_results['scan'][host]        result = {            'host': host,            'status': host_data['status']['state'],            'hostname': host_data['hostnames'][0]['name'] if 'hostnames' in host_data else 'n/a',            'os': host_data['osmatch'][0]['osclass'][0]['osfamily'] if 'osmatch' in host_data else 'n/a',            'open_ports': []        }        for proto in host_data.all_protocols():            lport = host_data[proto].keys()            for port in sorted(lport):                port_data = host_data[proto][port]                if port_data['state'] == 'open':                    port_info = {                        'port': port,                        'status': port_data['state'],                        'service': port_data.get('name', 'n/a'),                        'product': port_data.get('product', 'n/a'),                        'version': port_data.get('version', 'n/a'),                        'extra_info': port_data.get('extrainfo', 'n/a')                    }                    vulnerabilities = port_data.get('script', {}).get('vulners', [])                    if vulnerabilities:                        port_info['vulnerabilities'] = vulnerabilities                    result['open_ports'].append(port_info)        results.append(result)    return resultsif __name__ == "__main__":    if len(sys.argv) == 2:        ip = sys.argv[1]        scan_results = scan_host(ip)        for result in scan_results:            print(result)