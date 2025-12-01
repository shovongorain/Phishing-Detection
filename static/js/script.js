// Main JavaScript for Phishing Detection System

// DOM Ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize everything when page loads
    loadRecentScans();
    loadStats();
    
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 70,
                    behavior: 'smooth'
                });
            }
        });
    });
    
    // Allow pressing Enter to scan
    document.getElementById('urlInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            scanURL();
        }
    });
});

// Main scan function
async function scanURL() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    
    if (!url) {
        displayError('Please enter a URL to scan');
        return;
    }
    
    // Basic URL validation
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        displayError('URL must start with http:// or https://');
        return;
    }
    
    // Show loading indicator
    document.getElementById('loading').style.display = 'block';
    document.getElementById('result').style.display = 'none';
    document.getElementById('error').style.display = 'none';
    
    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            displayResult(result);
            loadRecentScans();
            loadStats();
        } else {
            throw new Error(result.error || 'Scan failed. Please try again.');
        }
    } catch (error) {
        displayError(error.message);
    } finally {
        document.getElementById('loading').style.display = 'none';
    }
}

// Display result
function displayResult(result) {
    const resultDiv = document.getElementById('result');
    
    let riskClass = '';
    let riskIcon = '';
    let alertClass = '';
    
    switch(result.risk_level) {
        case 'High':
            riskClass = 'danger';
            riskIcon = 'fa-exclamation-triangle';
            alertClass = 'alert-danger';
            break;
        case 'Medium':
            riskClass = 'warning';
            riskIcon = 'fa-exclamation-circle';
            alertClass = 'alert-warning';
            break;
        case 'Low':
            riskClass = 'success';
            riskIcon = 'fa-check-circle';
            alertClass = 'alert-success';
            break;
    }
    
    // Create result HTML
    const resultHTML = `
        <div class="alert ${alertClass}">
            <div class="d-flex align-items-center">
                <div class="flex-shrink-0">
                    <i class="fas ${riskIcon} fa-2x"></i>
                </div>
                <div class="flex-grow-1 ms-3">
                    <h4 class="alert-heading">${result.prediction} - ${result.risk_level} Risk</h4>
                    <p class="mb-2"><strong>URL:</strong> <code>${result.url}</code></p>
                    <div class="row">
                        <div class="col-md-6">
                            <p class="mb-1"><strong>Confidence:</strong> ${result.confidence}%</p>
                        </div>
                        <div class="col-md-6">
                            <p class="mb-1"><strong>Risk Score:</strong> ${result.risk_score}/100</p>
                        </div>
                    </div>
                    <hr>
                    <div class="mb-0">
                        <a href="/result?url=${encodeURIComponent(result.url)}" class="btn btn-${riskClass}">
                            <i class="fas fa-chart-bar"></i> View Detailed Analysis
                        </a>
                        <button class="btn btn-outline-secondary" onclick="clearResult()">
                            <i class="fas fa-times"></i> Close
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    resultDiv.innerHTML = resultHTML;
    resultDiv.style.display = 'block';
    
    // Scroll to result
    resultDiv.scrollIntoView({ behavior: 'smooth' });
}

// Load recent scans
async function loadRecentScans() {
    try {
        const response = await fetch('/api/history?limit=5');
        const scans = await response.json();
        
        const recentScansDiv = document.getElementById('recentScans');
        const recentCount = document.getElementById('recentCount');
        
        if (scans.length === 0) {
            recentScansDiv.innerHTML = `
                <div class="text-center py-4">
                    <i class="fas fa-history fa-3x text-muted mb-3"></i>
                    <h5 class="text-muted">No scans yet</h5>
                    <p class="text-muted">Scan a URL to see results here</p>
                </div>
            `;
            if (recentCount) recentCount.textContent = '0';
            return;
        }
        
        if (recentCount) recentCount.textContent = scans.length;
        
        let html = '<div class="row">';
        scans.forEach(scan => {
            const badgeClass = scan.prediction === 'Phishing' ? 'badge-phishing' : 'badge-legitimate';
            const riskClass = scan.risk_level === 'High' ? 'text-danger' : 
                            scan.risk_level === 'Medium' ? 'text-warning' : 'text-success';
            
            html += `
                <div class="col-lg-6 col-md-12 mb-3">
                    <div class="recent-scan-item">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h6 class="mb-1">
                                    <span class="badge ${badgeClass} me-2">${scan.prediction}</span>
                                    <span class="${riskClass}">${scan.risk_level}</span>
                                </h6>
                                <p class="mb-1 small text-truncate" style="max-width: 300px;">
                                    <i class="fas fa-link text-muted"></i> ${scan.url}
                                </p>
                            </div>
                            <div class="text-end">
                                <small class="text-muted d-block">${scan.timestamp.split(' ')[1]}</small>
                                <span class="badge bg-secondary">${scan.confidence}%</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        
        recentScansDiv.innerHTML = html;
    } catch (error) {
        console.error('Error loading recent scans:', error);
        document.getElementById('recentScans').innerHTML = `
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle"></i>
                Unable to load recent scans. Please try again.
            </div>
        `;
    }
}

// Load statistics
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        // Update stats on page
        const totalScansElement = document.getElementById('totalScans');
        if (totalScansElement) {
            totalScansElement.textContent = stats.total_scans;
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Clear result
function clearResult() {
    document.getElementById('result').style.display = 'none';
    document.getElementById('urlInput').value = 'https://';
    document.getElementById('urlInput').focus();
}

// Display error message
function displayError(message) {
    const errorDiv = document.getElementById('error');
    const errorMessage = document.getElementById('errorMessage');
    
    if (errorDiv && errorMessage) {
        errorMessage.textContent = message;
        errorDiv.style.display = 'block';
        
        // Hide error after 5 seconds
        setTimeout(() => {
            errorDiv.style.display = 'none';
        }, 5000);
    } else {
        // Fallback alert if error elements not found
        alert('Error: ' + message);
    }
}

// Share result
async function shareResult() {
    const shareLinks = document.getElementById('shareLinks');
    if (shareLinks) {
        shareLinks.style.display = shareLinks.style.display === 'none' ? 'block' : 'none';
    }
}

// Copy to clipboard
function copyToClipboard() {
    const currentUrl = window.location.href;
    navigator.clipboard.writeText(currentUrl).then(() => {
        const alert = document.getElementById('copyAlert');
        if (alert) {
            alert.style.display = 'block';
            setTimeout(() => {
                alert.style.display = 'none';
            }, 3000);
        }
    });
}

// Report URL
function reportUrl() {
    if (confirm('Report this URL as malicious? This will help improve our detection system.')) {
        alert('Thank you for your report. The URL has been flagged for review.');
        // In a real application, you would send this to your backend
        fetch('/api/report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: window.location.href,
                reason: 'user_report'
            })
        });
    }
}

// Download result
function downloadResult(format) {
    const content = `
Phishing Detection System - Scan Report
========================================
URL: ${document.querySelector('code')?.textContent || 'N/A'}
Scan Time: ${new Date().toLocaleString()}

=== END OF REPORT ===
Generated by Phishing Detection System
`;
    
    if (format === 'text') {
        const blob = new Blob([content], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'phishing-scan-report.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }
}

// Print result
function printResult() {
    window.print();
}

// Scan another URL
function scanAnother() {
    clearResult();
}

// Load similar scans for result page
async function loadSimilarScans() {
    try {
        const response = await fetch('/api/history');
        const scans = await response.json();
        
        const similarScansDiv = document.getElementById('similarScans');
        if (!similarScansDiv) return;
        
        let html = '';
        
        // Filter scans with same prediction type
        const similarScans = scans
            .filter(scan => scan.prediction === document.querySelector('.alert-heading')?.textContent?.split(' - ')[0])
            .slice(0, 5);
        
        if (similarScans.length === 0) {
            html = '<tr><td colspan="5" class="text-center">No similar scans found</td></tr>';
        } else {
            similarScans.forEach(scan => {
                const riskClass = scan.risk_level === 'High' ? 'danger' : 
                                scan.risk_level === 'Medium' ? 'warning' : 'success';
                
                html += `
                    <tr>
                        <td>${scan.timestamp.split(' ')[1]}</td>
                        <td>
                            <small title="${scan.url}">
                                ${scan.url.substring(0, 30)}${scan.url.length > 30 ? '...' : ''}
                            </small>
                        </td>
                        <td>
                            <span class="badge bg-${scan.prediction === 'Phishing' ? 'danger' : 'success'}">
                                ${scan.prediction}
                            </span>
                        </td>
                        <td>
                            <span class="badge bg-${riskClass}">${scan.risk_level}</span>
                        </td>
                        <td>${scan.confidence}%</td>
                    </tr>
                `;
            });
        }
        
        similarScansDiv.innerHTML = html;
    } catch (error) {
        console.error('Error loading similar scans:', error);
        const similarScansDiv = document.getElementById('similarScans');
        if (similarScansDiv) {
            similarScansDiv.innerHTML = 
                '<tr><td colspan="5" class="text-center text-danger">Error loading similar scans</td></tr>';
        }
    }
}

// Batch scan URLs
async function batchScan() {
    const urlsInput = document.getElementById('batchUrls');
    if (!urlsInput) return;
    
    const urls = urlsInput.value.trim().split('\n').filter(url => url.trim());
    
    if (urls.length === 0) {
        alert('Please enter URLs to scan');
        return;
    }
    
    if (urls.length > 20) {
        alert('Maximum 20 URLs per batch');
        return;
    }
    
    try {
        const response = await fetch('/api/batch-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ urls: urls })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            // Display batch results
            const batchResultsDiv = document.getElementById('batchResults');
            if (batchResultsDiv) {
                let html = `
                    <div class="alert alert-info">
                        <h5>Batch Scan Results</h5>
                        <p>Scanned ${result.total_urls} URLs, ${result.successful_scans} successful</p>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>URL</th>
                                    <th>Result</th>
                                    <th>Risk</th>
                                    <th>Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                
                result.results.forEach(scan => {
                    const riskClass = scan.risk_level === 'High' ? 'danger' : 
                                    scan.risk_level === 'Medium' ? 'warning' : 'success';
                    
                    html += `
                        <tr>
                            <td><small>${scan.url.substring(0, 40)}${scan.url.length > 40 ? '...' : ''}</small></td>
                            <td><span class="badge bg-${scan.prediction === 'Phishing' ? 'danger' : 'success'}">${scan.prediction}</span></td>
                            <td><span class="badge bg-${riskClass}">${scan.risk_level}</span></td>
                            <td>${scan.confidence}%</td>
                        </tr>
                    `;
                });
                
                html += `
                            </tbody>
                        </table>
                    </div>
                `;
                
                batchResultsDiv.innerHTML = html;
                batchResultsDiv.style.display = 'block';
            }
        } else {
            throw new Error(result.error || 'Batch scan failed');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Clear batch results
function clearBatchResults() {
    const batchResultsDiv = document.getElementById('batchResults');
    if (batchResultsDiv) {
        batchResultsDiv.style.display = 'none';
    }
    const urlsInput = document.getElementById('batchUrls');
    if (urlsInput) {
        urlsInput.value = '';
    }
}

// Export scan history
function exportHistory() {
    fetch('/api/history?limit=100')
        .then(response => response.json())
        .then(scans => {
            const csv = convertToCSV(scans);
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'phishing-scan-history.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        })
        .catch(error => {
            console.error('Error exporting history:', error);
            alert('Error exporting history');
        });
}

// Convert data to CSV
function convertToCSV(data) {
    const headers = ['Timestamp', 'URL', 'Prediction', 'Risk Level', 'Confidence', 'Risk Score'];
    const rows = data.map(scan => [
        scan.timestamp,
        scan.url,
        scan.prediction,
        scan.risk_level,
        scan.confidence + '%',
        scan.risk_score
    ]);
    
    return [headers, ...rows].map(row => 
        row.map(cell => `"${cell}"`).join(',')
    ).join('\n');
}

// Initialize charts on dashboard
function initializeCharts() {
    // Distribution Chart
    const distCtx = document.getElementById('distributionChart');
    if (distCtx) {
        const distChart = new Chart(distCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Phishing', 'Legitimate'],
                datasets: [{
                    data: [window.phishingCount || 0, window.legitimateCount || 0],
                    backgroundColor: ['#dc3545', '#28a745'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    // Features Chart
    const featuresCtx = document.getElementById('featuresChart');
    if (featuresCtx) {
        const featuresChart = new Chart(featuresCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['URL Length', 'Special Chars', 'HTTPS', 'Subdomains', 'IP Check', 'Shortener'],
                datasets: [{
                    label: 'Importance',
                    data: [0.15, 0.12, 0.18, 0.10, 0.14, 0.11],
                    backgroundColor: 'rgba(54, 162, 235, 0.7)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Importance Score'
                        }
                    }
                }
            }
        });
    }
}

// Refresh dashboard data
async function refreshDashboard() {
    await loadRecentScans();
    await loadStats();
    
    // If on dashboard page, update charts
    if (window.location.pathname.includes('dashboard')) {
        initializeCharts();
    }
}

// Auto-refresh every 30 seconds
setInterval(refreshDashboard, 30000);