
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

                if (data.error) {
                    $('#resultArea').html('<p style="color: red;">' + data.error + '</p>');
                } else if (data.results) {


                    displayResults(data.results);

                } else {
                    $('#resultArea').html('<p style="color: red;">Scan completed but no scan ID returned.</p>');
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
            var scanId = 5; 
            handlePortScanCompletion(scanId);
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


function handlePortScanCompletion(scanId) {
    var startTime = Date.now(); // Capture the start time before the AJAX request

    $.ajax({
        type: 'GET',
        url: `/get_scan_results/${scanId}/`,
        success: function(response) {
            var endTime = Date.now(); // Capture the end time when response is received
            var latency = endTime - startTime; // Calculate the latency

            $('#resultArea').empty(); // Clear previous results

            // Display the latency time in milliseconds
            $('#resultArea').append(`<p>Latency: ${latency} ms</p>`);

            // Check if there are vulnerabilities and loop through them
            if (response.vulnerabilities) {
                response.vulnerabilities.forEach(function(vuln) {
                    var severityClass = getSeverityClass(vuln.severity);
                    var severityText = getSeverityText(vuln.severity);
                    var cardHtml = `
                        <div class="card ${severityClass}">
                            <div class="card-header">
                                ${vuln.plugin_name} (Severity: ${severityText})
                            </div>
                            <div class="card-body">
                                <p class="card-text">Plugin ID: ${vuln.plugin_id}</p>
                                <p class="card-text">Description: ${vuln.description || 'N/A'}</p>
                                <p class="card-text">VPR Score: ${vuln.vpr_score || 'N/A'}</p>
                                <p class="card-text">CPE: ${vuln.cpe || 'N/A'}</p>
                                <p class="card-text">Remediation: ${vuln.remediation || 'No specific remediation available'}</p>
                            </div>
                        </div>`;
                    $('#resultArea').append(cardHtml); // Append the new card to the resultArea
                });
            } else {
                $('#resultArea').append('<p>No vulnerabilities found.</p>');
            }
        },
        error: function(xhr, status, error) {
            $('#resultArea').html(`<p>An error occurred: ${error}</p>`);
        }
    });
}

function getSeverityClass(severity) {
    switch(severity) {
        case 0: return 'info';
        case 2: return 'medium';
        case 3:
        case 4: return 'high';
        default: return 'mixed';
    }
}

function getSeverityText(severity) {
    switch(severity) {
        case 0: return 'Info';
        case 2: return 'Medium';
        case 3:
        case 4: return 'High';
        default: return 'Mixed';
    }
}
