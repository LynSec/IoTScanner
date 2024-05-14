import nvdlib

class NVDSearch:
    def __init__(self):
        pass

    def find_cve(self, cve_id):
        result = {}
        try:
            # Search for the CVE
            cve_info = nvdlib.searchCVE(cveId=cve_id)[0]

            # Extract relevant information
            result['ID'] = cve_info.id
            result['Published'] = cve_info.published
            result['Last Modified'] = cve_info.lastModified
            result['Vulnerability Status'] = cve_info.vulnStatus
            result['Description'] = cve_info.descriptions[0].value
            result['CVSS v3 Score'] = cve_info.metrics.cvssMetricV31[0].cvssData.baseScore
            result['CVSS v3 Severity'] = cve_info.metrics.cvssMetricV31[0].cvssData.baseSeverity
            result['CWE'] = cve_info.weaknesses[0].description[0].value

             # Print the results
            # for key, value in result.items():
            #     print(f"{key}: {value}")
        except Exception as e:
            print(f"Error: {e}")
        # print (type(result))
        return result


# cve_id = 'CVE-2021-26855'
# searcher = NVDSearch()
# searcher.find_cve(cve_id)

