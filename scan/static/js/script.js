$(document).ready(function() {
    var pageSize = 10; // Number of results per page
    var currentPage = 1; // Current page
    var currentSortColumn = null;
    var currentSortDirection = 'asc';

    $('#portScanForm').submit(function(event) {
        event.preventDefault(); // Prevent default form submission

        // Submit form via AJAX
        $.ajax({
            type: 'POST',
            url: $(this).attr('action'),
            data: $(this).serialize(), // Serialize form data
            success: function(data) {
                console.log("Data received:", data);
            
               // Parse the results string into a JavaScript object
		var parsedData = data.results;

		// Check if parsedData is a string, if so, parse it into an object
		if (typeof parsedData === 'string') {
		    try {
			parsedData = JSON.parse(parsedData);
			console.log("Wrote to console");
		    } catch (error) {
			console.error('Error parsing JSON:', error);
			// Handle the parsing error
			//$('#resultArea').html('<p style="border: 1px solid darkred; background: salmon">Error: Failed to parse scan results.</p>');
			return;
		    }
		}

		if (parsedData && parsedData.length > 0) {
		    displayResults(parsedData, currentPage);
		} else {
		    //$('#resultArea').html('<p style="border: 1px solid darkred; background: salmon">Error: No results found in the data.</p>');
		    console.log("No results found in the data:", data);
		}

        });
    });
    function displayResults(results, page) {
        var start = (page - 1) * pageSize;
        var end = start + pageSize;
        var html = '';
    
        // Check if results is an array or iterable object
        if (!Array.isArray(results) && typeof results !== 'object') {
            // If not, display an error message
            $('#resultArea').html('<p>Error: No results found.</p>');
            return;
        }
    
        // Convert results to an array if it's an object
        if (!Array.isArray(results)) {
            results = Object.values(results);
        }
    
        // Calculate total pages
        var totalPages = Math.ceil(results.length / pageSize);
    
        // Display results in a table
        html += '<table id="resultsTable" border="1">';
        html += '<thead><tr><th><button class="sortBtn" data-column="port">Port</button></th><th><button class="sortBtn" data-column="status">Status</button></th></tr></thead>';
        html += '<tbody>';
    
        // Display results in the specified range
        results.slice(start, end).forEach(function(result) {
            html += '<tr>';
            html += '<td>' + result.port + '</td>';
            html += '<td>' + result.status + '</td>';
            html += '</tr>';
        });
    
        html += '</tbody></table>';
        html += '<br>';
    
        // Add pager
        html += '<div>';
        if (currentPage > 1) {
            html += '<button id="prevPageBtn">Previous Page</button>';
        }
        if (currentPage < totalPages) {
            html += '<button id="nextPageBtn">Next Page</button>';
        }
        html += '</div>';
    
        $('#resultArea').html(html);
    
        // Attach event handlers for pager buttons
        $('#prevPageBtn').click(function() {
            currentPage--;
            displayResults(results, currentPage);
        });
    
        $('#nextPageBtn').click(function() {
            currentPage++;
            displayResults(results, currentPage);
        });
    
        // Attach event handler for sorting
        $('.sortBtn').click(function() {
            var column = $(this).data('column');
            if (column === currentSortColumn) {
                currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                currentSortColumn = column;
                currentSortDirection = 'asc';
            }
            displayResults(results, currentPage);
        });
    }
    

    function sortResults(results, column, direction) {
        return results.sort(function(a, b) {
            if (direction === 'asc') {
                if (!isNaN(parseFloat(a[column])) && isFinite(a[column]) &&
                    !isNaN(parseFloat(b[column])) && isFinite(b[column])) {
                    return parseFloat(a[column]) - parseFloat(b[column]);
                } else {
                    return a[column].toString().localeCompare(b[column].toString());
                }
            } else {
                if (!isNaN(parseFloat(a[column])) && isFinite(a[column]) &&
                    !isNaN(parseFloat(b[column])) && isFinite(b[column])) {
                    return parseFloat(b[column]) - parseFloat(a[column]);
                } else {
                    // Otherwise, compare them as strings
                    return b[column].toString().localeCompare(a[column].toString());
                }
            }
        });
    }
    
});
// handles default scans
    $(document).ready(function() {
        $('#runScriptBtn').click(function() {
            $.ajax({
                type: 'POST',
                url: '/script/',
                success: function(data) {
                    displayResults(data.result);
                },
                error: function(xhr, status, error) {
                    // Handle error
                    $('#resultTableArea').html('<p style="color: red;">Error: Unable to run the script.</p>');
                    console.error(xhr.responseText);
                }
            });
        });
    
        // Function to display port scan results in a table
        function displayResults(results) {
            if (!Array.isArray(results)) {
                console.error("Results is not an array.");
                return;
            }

            var table = '<table border="1">';
            table += '<thead><tr><th>Port</th><th>Status</th></tr></thead>';
            table += '<tbody>';

            results.forEach(function(result) {
                table += '<tr>';
                table += '<td>' + result.port + '</td>';
                table += '<td>' + result.status + '</td>';
                table += '</tr>';
            });

            table += '</tbody></table>';

            $('#resultTableArea').html(table);
        }
    });

$(document).on('click', '.vulnerabilityScanBtn', function() {
    var ip = $(this).data('ip');
    var port = $(this).data('port');
    // Send AJAX request to the vulnerability_scan view
    $.ajax({
        type: 'POST',
        url: '/vulnerability_scan/',
        data: {'ip_address': ip, 'port': port},
        success: function(data) {
            // Redirect to the vulnerability scan report page with the scan results
            window.location.href = '/vulnerability_scan_report/?ip=' + ip + '&port=' + port;
        },
        error: function(xhr, status, error) {
            console.error(xhr.responseText);
            alert('Error: Unable to perform vulnerability scan.');
        }
    });
});


$(document).on('click', '.vulnerabilityScanBtn', function() {
    var ip = $(this).data('ip');
    var port = $(this).data('port');
    // Send AJAX request to the run_dlkploit600 view
    $.ajax({
        type: 'POST',
        url: '/run_dlkploit600/',
        data: {'host': ip, 'range': ip, 'port': port, 'all': true},  // Assuming all options are required
        success: function(data) {
            window.location.href = data.report_url;  // Change 'report_url' to match the actual key in the returned JSON
        },
        error: function(xhr, status, error) {
            console.error(xhr.responseText);
            alert('Error: Unable to perform vulnerability scan.');
        }
    });
});

// junk

function displayResults(results) {
    if (Array.isArray(results)) {
        var html = '<table border="1"><thead><tr><th>Port</th><th>Status</th></tr></thead><tbody>';
        results.forEach(function(result) {
          
            html += '<tr><td>' + result.port + '</td><td>' + result.status + '</td></tr>';
            
        });
        html += '</tbody></table>';
        $('#resultArea').html(html);
    } else {
        console.error('Expected an array but received:', results);
        $('#resultArea').html('<p>Error: Data is not in expected format.</p>');
    }
}



document.getElementById('clearDataBtn').addEventListener('click', function() {
    if (confirm('Are you sure you want to clear all data? This action cannot be undone.')) {
        fetch('{% url "clear_data" %}', {
            method: 'POST',
            headers: {
                'X-CSRFToken': '{{ csrf_token }}'
            }
        })
        .then(response => response.json())
        .then(data => {
            if(data.success) {
                alert(data.success);
                // Optional: Reload or update page state
                window.location.reload();
            } else {
                alert(data.error);
            }
        })
        .catch(error => alert('Error: ' + error));
    }
});


