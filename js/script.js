// Main JavaScript for Phishing Detection System

async function scanURL() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    
    if (!url) {
        alert('Please enter a URL to scan');
        return;
    }
    
    // Show loading indicator
    document.getElementById('loading').style.display = 'block';
    document.getElementById('result').style.display = 'none';
    
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
        } else {
            throw new Error(result.error || 'Scan failed');
        }
    } catch (error) {
        displayError(error.message);
    } finally {
        document.getElementById('loading').style.display = 'none';
    }
}

function displayResult(result) {
    const resultDiv = document.getElementById('result');
    
    let riskClass = '';
    let riskIcon = '';
    
    switch(result.risk_level) {
        case 'High':
            riskClass = 'danger';
            riskIcon = 'fa-exclamation-triangle';
            break;
        case 'Medium':
            riskClass = 'warning';
            riskIcon = 'fa-exclamation-circle';
            break;
        case 'Low':
            riskClass = 'success';
            riskIcon = 'fa-check-circle';
            break;
    }
    
    let riskFactorsHtml = '';
    if (result.analysis && result.analysis.risk_factors) {
        riskFactorsHtml = result.analysis.risk_factors.map(factor => 
            `<li class="list-group-item">${factor}</li>`
        ).join('');
    }
    
    resultDiv.innerHTML = `
        <div class="alert alert-${riskClass}">
            <h4 class="alert-heading">
                <i class="fas ${riskIcon}"></i> ${result.prediction} - ${result.risk_level} Risk
            </h4>
            <p><strong>URL:</strong> ${result.url}</p>
            <hr>
            <p class="mb-0">
                <strong>Confidence:</strong> ${result.confidence}% |
                <strong>Risk Score:</strong> ${result.risk_score}/100
            </p>
        </div>
        
        <div class="row mt-3">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Domain Information</h5>
                    </div>
                    <div class="card-body">
                        <ul class="list-unstyled">
                            ${result.analysis.domain_info ? `
                                <li><strong>Domain:</strong> ${result.analysis.domain_info.full_domain}</li>
                                <li><strong>Protocol:</strong> ${result.analysis.domain_info.scheme}</li>
                                <li><strong>Path:</strong> ${result.analysis.domain_info.path || 'None'}</li>
                            ` : 'No domain information available'}
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Security Indicators</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            ${result.analysis.security_indicators ? `
                                <div class="col-6">
                                    <p><i class="fas ${result.analysis.security_indicators.has_https ? 'fa-check text-success' : 'fa-times text-danger'}"></i> HTTPS</p>
                                    <p><i class="fas ${result.analysis.security_indicators.has_ip ? 'fa-times text-danger' : 'fa-check text-success'}"></i> No IP</p>
                                </div>
                                <div class="col-6">
                                    <p><i class="fas ${!result.analysis.security_indicators.is_shortened ? 'fa-check text-success' : 'fa-times text-danger'}"></i> Not Shortened</p>
                                    <p><i class="fas ${!result.analysis.security_indicators.suspicious_tld ? 'fa-check text-success' : 'fa-times text-danger'}"></i> TLD</p>
                                </div>
                            ` : 'No security information available'}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        ${riskFactorsHtml ? `
            <div class="card mt-3">
                <div class="card-header bg-${riskClass} text-white">
                    <h5 class="mb-0">Risk Factors Detected</h5>
                </div>
                <div class="card-body">
                    <ul class="list-group">
                        ${riskFactorsHtml}
                    </ul>
                </div>
            </div>
        ` : ''}
        
        <div class="mt-3">
            <button class="btn btn-secondary" onclick="clearResult()">Clear Result</button>
            <button class="btn btn-primary" onclick="scanAnother()">Scan Another URL</button>
        </div>
    `;
    
    resultDiv.style.display = 'block';
}

function displayError(error) {
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = `
        <div class="alert alert-danger">
            <h4 class="alert-heading">Error</h4>
            <p>${error}</p>
            <hr>
            <p class="mb-0">Please try again with a valid URL.</p>
        </div>
        <button class="btn btn-primary mt-2" onclick="clearResult()">Try Again</button>
    `;
    resultDiv.style.display = 'block';
}

function clearResult() {
    document.getElementById('result').style.display = 'none';
    document.getElementById('urlInput').value = 'https://';
    document.getElementById('urlInput').focus();
}

function scanAnother() {
    clearResult();
}

async function loadRecentScans() {
    try {
        const response = await fetch('/api/history');
        const scans = await response.json();
        
        const recentScansDiv = document.getElementById('recentScans');
        
        if (scans.length === 0) {
            recentScansDiv.innerHTML = '<p class="text-muted">No scans yet. Enter a URL above to start scanning.</p>';
            return;
        }
        
        let html = '<div class="row">';
        scans.slice(0, 6).forEach(scan => {
            const badgeClass = scan.prediction === 'Phishing' ? 'bg-danger' : 'bg-success';
            const riskClass = scan.risk_level === 'High' ? 'text-danger' : 
                            scan.risk_level === 'Medium' ? 'text-warning' : 'text-success';
            
            html += `
                <div class="col-md-4 mb-3">
                    <div class="card h-100">
                        <div class="card-body">
                            <h6 class="card-title text-truncate" title="${scan.url}">
                                ${scan.url.substring(0, 40)}${scan.url.length > 40 ? '...' : ''}
                            </h6>
                            <span class="badge ${badgeClass}">${scan.prediction}</span>
                            <span class="badge ${riskClass}">${scan.risk_level}</span>
                            <p class="card-text small mt-2">
                                <strong>Confidence:</strong> ${scan.confidence}%<br>
                                <small class="text-muted">${scan.timestamp}</small>
                            </p>
                        </div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        
        recentScansDiv.innerHTML = html;
    } catch (error) {
        console.error('Error loading recent scans:', error);
    }
}

// Allow pressing Enter to scan
document.getElementById('urlInput').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        scanURL();
    }
});

// Load recent scans on page load
document.addEventListener('DOMContentLoaded', loadRecentScans);