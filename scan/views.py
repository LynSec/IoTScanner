from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader
import subprocess
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.db.models import Count
from scan.models import PortScanResult 
import shlex
from ipaddress import ip_network
import itertools
from nvds import NVDSearch
import nmap
import ast, requests

import urllib3
import logging

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scan_results(request):
    template = loader.get_template('scan_results.html')
    return HttpResponse(template.render())

def Scan(request):

    template = loader.get_template('scan-system.html')
    return HttpResponse(template.render())
   
def Homepage(request):
    template = loader.get_template('dashboard.html')
    return HttpResponse(template.render())

@csrf_exempt
def run_script(request):
    # Execute the Python script
    result = subprocess.check_output(['python3', './port_scan.py'])
    # Decode the result
    result_text = result.decode('utf-8')
    # Parse the result into a list of dictionaries
    result_list = []
    seen_ports = set()  # Keep track of seen ports
    for line in result_text.split('\n'):
        if line.startswith('Port'):
            parts = line.split(':')
            port = int(parts[0].split()[1])
            status = parts[1].strip()
            if port not in seen_ports:
                result_list.append({'port': port, 'status': status})
                seen_ports.add(port)
    return JsonResponse({'result': result_list})


@csrf_exempt
def script_args(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        port_range_start = request.POST.get('port_range_start')
        port_range_end = request.POST.get('port_range_end')

        # Validate input presence
        if not (ip_address and port_range_start and port_range_end):
            return JsonResponse({'error': 'IP address and port range must be provided'}, status=400)

        # Validate port range
        try:
            port_range_start = int(port_range_start)
            port_range_end = int(port_range_end)
            if not (1 <= port_range_start <= 65535 and 1 <= port_range_end <= 65535):
                raise ValueError("Port numbers must be in range 1-65535")
            if port_range_start > port_range_end:
                raise ValueError("Start port cannot be greater than end port")
        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)


        # Execute scan and process results
        try:
            command = ['python3', './scan.py', ip_address, str(port_range_start), str(port_range_end)]
            print ("Command is: ",command)
            result = subprocess.check_output(command, universal_newlines=True)
            print("Raw result from scan.py:", result)
        
            # Parse results
            results = []
            for line in result.strip().split('\n'):

                if line:
                    port_dict = ast.literal_eval(line)
                    if port_dict.get('status') == 'open': 
                        results.append({
                            'ip': ip_address,
                            'port': port_dict.get('port', 'n/a'),
                            'status': port_dict.get('status', 'n/a'),
                            'service': port_dict.get('service', 'n/a'),
                            'product': port_dict.get('product', 'n/a'),
                            'version': port_dict.get('version', 'n/a'),
                            'extra_info': port_dict.get('extra_info', 'n/a')
                        })
            print ("Final results \n\n",results)
            return JsonResponse({'results': results})
        except subprocess.CalledProcessError as e:
            return JsonResponse({'error': f'Error executing scan.py script: {str(e)}'}, status=500)
    
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def vulnerability_scan_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)  # Parse the JSON data sent with the request
            ip_address = data.get('ip_address')
            port = data.get('port')
            print(f'IP of {ip_address}, PORT: {port}')

            if not (ip_address and port):
                return JsonResponse({'error': 'IP address and port must be provided'}, status=400)

            port = int(port)  # Convert port to integer
            if port < 1 or port > 65535:
                raise ValueError("Port number must be between 1 and 65535")

            # Initiate the scan using nmap
            scanner = nmap.PortScanner()
            scan_arguments = f'-sV -Pn --script=vuln -p {port}'
            scan_results = scanner.scan(ip_address, arguments=scan_arguments)

            vulnerabilities = []
            host_data = scan_results.get('scan', {}).get(ip_address, {})
            port_data = host_data.get('tcp', {}).get(port, {})
            script_data = port_data.get('script', {})

            # Extract vulnerabilities from the nmap script output
            vulners_output = script_data.get('vulners', '')
            print(f"Vulnerability script output: {vulners_output}")

            if vulners_output:
                for line in vulners_output.strip().split('\n'):
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            cve_id, cvss_score, url = parts[1], parts[2], parts[3]
                            vulnerabilities.append({
                                'cve_id': cve_id.strip(),
                                'cvss_score': cvss_score.strip(),
                                'url': url.strip()
                            })
            print("Extracted Vulnerabilities:", vulnerabilities)
            return JsonResponse({'vulnerabilities': vulnerabilities})

        except ValueError as e:
            print(f"Value error: {e}")
            return JsonResponse({'error': str(e)}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            print(f"Unexpected error: {e}")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
# Disable SSL warnings (Not recommended for production)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


@csrf_exempt
def start_nessus_scan(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        print ("Scanning IP: ", ip_address)
        if not ip_address:
            return JsonResponse({'error': 'IP address is required'}, status=400)

        try:
            nessus_url = settings.NESSUS_URL
            access_key = settings.NESSUS_ACCESS_KEY
            secret_key = settings.NESSUS_SECRET_KEY
            scan_policy_id = settings.NESSUS_POLICY_ID

            headers = {
                'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}'
            }

            scan_data = {
                'uuid': scan_policy_id,
                'settings': {
                    'name': 'Django Initiated Scan',
                    'text_targets': ip_address,
                }
            }

            response = requests.post(f'{nessus_url}/scans', json=scan_data, headers=headers, verify=False)
            print ("Response is :", response)
            if response.status_code == 200:
                scan_id = response.json()['scan']['id']
                return JsonResponse({'message': 'Scan started successfully', 'scan_id': scan_id})
            else:
                return JsonResponse({'error': 'Failed to start scan', 'status_code': response.status_code}, status=500)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)



@csrf_exempt
def get_nessus_scan_details(request, scan_id):
    if request.method == 'GET':
        try:
            headers = {
                'X-ApiKeys': f'accessKey={settings.NESSUS_ACCESS_KEY};secretKey={settings.NESSUS_SECRET_KEY}'
            }
            url = f'{settings.NESSUS_URL}/scans/{scan_id}'
            print(f'Requesting URL: {url} with headers: {headers}')
            response = requests.get(url, headers=headers, verify=False)

            logger.debug(f'Response Status: {response.status_code}')
            if response.status_code == 200:
                data = response.json()
                return JsonResponse(data, safe=False)
            else:
                return JsonResponse({'error': 'Failed to fetch scan results', 'status_code': response.status_code}, status=500)
        except Exception as e:
            logger.exception("Failed due to an exception.")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
@csrf_exempt
def get_nessus_scan_detail(request, scan_id):
    if request.method == 'GET':
        try:
            headers = {
                'X-ApiKeys': f'accessKey={settings.NESSUS_ACCESS_KEY};secretKey={settings.NESSUS_SECRET_KEY}'
            }
            response = requests.get(f'{settings.NESSUS_URL}/scans/{scan_id}', headers=headers, verify=False)
            print (f'accessKey={settings.NESSUS_ACCESS_KEY};secretKey={settings.NESSUS_SECRET_KEY}')
            print ("Response : ", response)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])

                parsed_vulnerabilities = [{
                    'plugin_name': v.get('plugin_name'),
                    'severity': v.get('severity'),
                    'cpe': v.get('cpe'),
                    'vpr_score': v.get('vpr_score'),
                    'plugin_id': v.get('plugin_id'),
                    'description': v.get('description')
                } for v in vulnerabilities]

                return JsonResponse({'vulnerabilities': parsed_vulnerabilities}, safe=False)
            else:
                return JsonResponse({'error': 'Failed to fetch scan results'}, status=500)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
        
        
def check_scan_status(nessus_url, headers, scan_id):
    import time
    while True:
        status_response = requests.get(f'{nessus_url}/scans/{scan_id}', headers=headers, verify=False)
        if status_response.status_code != 200:
            return JsonResponse({'error': 'Failed to get scan status'}, status=500)
        
        status = status_response.json()['info']['status']
        if status in ['completed', 'canceled']:
            return fetch_scan_results(nessus_url, headers, scan_id)
        time.sleep(10)  # Sleep before checking again

def fetch_scan_results(nessus_url, headers, scan_id):
    results_response = requests.get(f'{nessus_url}/scans/{scan_id}', headers=headers, verify=False)
    if results_response.status_code == 200:
        results = results_response.json()
        return JsonResponse({'results': results})
    else:
        return JsonResponse({'error': 'Failed to fetch scan results'}, status=500)





def extract_data(request):
    # Assuming the CVE ID is provided as a query parameter named 'cve_id'
    cve_id = 'CVE-2019-10999'

    #cve_id = request.GET.get('cve_id')

    if cve_id:
        nvd_search = NVDSearch()
        result = nvd_search.find_cve(cve_id)
        if result:
            return JsonResponse(result)
        else:
            return JsonResponse({'error': 'No information found for the provided CVE ID.'}, status=404)
    else:
        return JsonResponse({'error': 'Please provide a CVE ID as a query parameter.'}, status=400)
