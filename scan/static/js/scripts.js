$(document).ready(function() {
    $('#portScanForm').submit(function(event) {
        event.preventDefault();  // Prevent default form submission

        // Show loading animation when the scan button is clicked
        $('#loadingIndicator').show();

        $.ajax({
            type: 'POST',
            url: $(this).attr('action'),
            data: $(this).serialize(),
            dataType: 'json',  // Expect JSON response from the server
            success: function(data) {
                // Hide loading animation when the scan is completed
                $('#loadingIndicator').hide();

                // Process scan results
                if (data.error) {
                    $('#resultArea').html('<p style="color: red;">' + data.error + '</p>');
                } else if (data.results) {
                    console.log("Results ",data.results);
                    displayResults(data.results);
                } else {
                    $('#resultArea').html('<p style="color: red;">No results found.</p>');
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                // Hide loading animation if there's an error
                $('#loadingIndicator').hide();

                console.error('AJAX error:', textStatus, 'Error:', errorThrown);
                $('#resultArea').html('<p style="color: red;">Request failed: ' + errorThrown + '</p>');
            }
        });
    });
});


function displayResults(results) {
    var html = '<table border="1"><thead><tr><th>Port</th><th>Status</th><th>Service</th><th>Product</th><th>Version</th><th>Extra Info</th><th>Actions</th></tr></thead><tbody>';
    results.forEach(function(result) {
        html += `<tr>
                    <td>${result.port}</td>
                    <td>${result.status}</td>
                    <td>${result.service || 'n/a'}</td>
                    <td>${result.product || 'n/a'}</td>
                    <td>${result.version || 'n/a'}</td>
                    <td>${result.extra_info || 'n/a'}</td>
                    <td>`;
        if (result.status === 'open') {
            html += 'Scanning for vulnerabilities..';
            scanVulnerabilities(result.ip, result.port)
            console.log(result.ip);
        } else {
            html += 'N/A';
        }
        html += '</td></tr>';
    });
    html += '</tbody></table>';
    $('#resultArea').html(html);
}




function scanVulnerabilities(ipAddress, port) {
    console.log("Initiating vulnerability scan on IP:", ipAddress, "Port:", port);

    // Make an AJAX POST request to the server
    $.ajax({
        type: 'POST',
        url: '/vulnerability_scan/',  
        data: JSON.stringify({
            'ip_address': ipAddress,
            'port': port
        }),
        contentType: "application/json; charset=utf-8", // Set the content type to JSON
        dataType: 'json',  // Expect JSON response from the server
        success: function(data) {
            console.log("Vulnerability scan completed:", data);
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                displayVulnerabilityResults(data.vulnerabilities);  
            } else if (data.error) {
                console.error('Scan error:', data.error);
                updatePortScanStatus(port, 'No vulnerabilities found or error occurred.');
            } else {
                updatePortScanStatus(port, 'No vulnerabilities found.');
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {
            console.error('AJAX error:', textStatus, 'Error:', errorThrown);
            updatePortScanStatus(port, 'Failed to perform vulnerability scan.');
        }
    });
}

function displayVulnerabilityResult(vulnerabilities) {
    let html = '<div class="vulnerabilities">';
    vulnerabilities.forEach(vuln => {
        html += `
            <div class="card">
            	<h3> vulnerabilities found </h3>
                <h3>${vuln.cve_id} (CVSS: ${vuln.cvss_score})</h3>
                <p><a href="${vuln.url}" target="_blank">More Details</a></p>
                <p>${vuln.details.description}</p>
            </div>
        `;
    });
    html += '</div>';
    document.getElementById('vulnerabilityResults').innerHTML = html;
}



$(document).ready(function() {
    $('#nessusScanForm').submit(function(event) {
        event.preventDefault();
        var ipAddress = $('#ipAddress').val();
        $('#scanResults').html('<div>Loading...</div>'); // Display loading text

        $.ajax({
            type: 'POST',
            url: '/start_nessus_scan/', 
            data: {
                ip_address: ipAddress
            },
            success: function(response) {
                // Display results or status
                $('#scanResults').html('<pre>' + JSON.stringify(response, null, 2) + '</pre>');
            }
        });
    });
});


function displayVulnerabilityResults(vulnerabilities) {
    let html = '<h3>Vulnerability Scan Results</h3><table border="1"><thead><tr><th>CVE ID</th><th>CVSS Score</th><th>Details</th></tr></thead><tbody>';
    vulnerabilities.forEach(vuln => {
        html += `<tr><td>${vuln.cve_id}</td><td>${vuln.cvss_score}</td><td><a href="${vuln.url}" target="_blank">Details</a></td></tr>`;
    });
    html += '</tbody></table>';
    document.getElementById('vulnerabilityResults').innerHTML = html;
}

function updatePortScanStatus(port, message) {
    // Update the status for a specific port directly in the table displayed in the 'resultArea'
    $(`#port-${port}`).html(message); // This assumes you have an element with id like `port-22` where you display the status of the scan.
}




$(document).ready(function() {
    $('#fetchResultsButton').click(function() {
        var scanId = 5; 
        $.ajax({
            type: 'GET',
            url: `/get_scan_results/${scanId}/`,  
            success: function(response) {
                $('#scanResults').empty(); // Clear previous results

                // Check if there are vulnerabilities and loop through them
                if (response.vulnerabilities) {
                    response.vulnerabilities.forEach(function(vuln) {
                        var severity = '';
                        switch(vuln.severity) {
                            case 0:
                                severity = 'Info';
                                break;
                            case 2:
                                severity = 'Medium';
                                break;
                            case 3:
                            case 4:
                                severity = 'High';
                                break;
                            default:
                                severity = 'Mixed';
                        }

                        var cardHtml = `
                            <div class="card ${severity.toLowerCase()}">
                                <div class="card-header">
                                    ${vuln.plugin_name} (Severity: ${severity})
                                </div>
                                <div class="card-body">
                                    <p class="card-text">Plugin ID: ${vuln.plugin_id}</p>
                                    <p class="card-text">Description: ${vuln.description || 'N/A'}</p>
                                    <p class="card-text">VPR Score: ${vuln.vpr_score || 'N/A'}</p>
                                    <p class="card-text">CPE: ${vuln.cpe || 'N/A'}</p>
                                </div>
                            </div>`;
                        $('#scanResults').append(cardHtml); // Append the new card to the scanResults div
                    });
                }
            },
            error: function(xhr, status, error) {
                $('#scanResults').html(`<p>An error occurred: ${error}</p>`);
            }
        });
    });
});



