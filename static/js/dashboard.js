// Real-Time IDS Dashboard Orchestrator
let trafficChart, threatChart, portChart;
const maxChartPoints = 20;
let packetCountHistory = [];
let chartLabels = [];

document.addEventListener('DOMContentLoaded', () => {
    // Initialize active page scripts
    const activePage = document.body.dataset.page;
    
    if (activePage === 'dashboard') {
        initDashboardCharts();
        initRealtimeStream();
    } else if (activePage === 'alerts') {
        initAlertsPage();
    } else if (activePage === 'logs') {
        initLogsPage();
    } else if (activePage === 'settings') {
        initSettingsPage();
    }
});

// ==========================================
// 1. REAL-TIME DATA STREAM (SSE)
// ==========================================
function initRealtimeStream() {
    const sse = new EventSource('/api/live-stream');
    
    // Track stats locally to compute PPS
    let livePpsCount = 0;
    
    // Update live metrics cards
    setInterval(() => {
        // Update PPS indicator card
        const ppsVal = document.getElementById('metric-pps');
        if (ppsVal) {
            ppsVal.textContent = livePpsCount;
            // Update throughput chart
            updateThroughputChart(livePpsCount);
            livePpsCount = 0;
        }
    }, 1000);

    sse.addEventListener('packet', (e) => {
        const packet = JSON.parse(e.data);
        livePpsCount++;
        
        // Update packets total count
        const totalPktSpan = document.getElementById('metric-total-packets');
        if (totalPktSpan) {
            totalPktSpan.textContent = parseInt(totalPktSpan.textContent) + 1;
        }
        
        // Add row to live packets feed table
        const tbody = document.getElementById('live-packets-tbody');
        if (tbody) {
            const row = document.createElement('tr');
            
            // Limit payload len display
            const protoClass = `proto-${packet.protocol.toLowerCase()}`;
            const classificationText = packet.classification === 'Normal' 
                ? `<span class="badge badge-low">Normal</span>` 
                : `<span class="badge badge-critical">${packet.classification}</span>`;
                
            row.innerHTML = `
                <td class="mono">${packet.timestamp}</td>
                <td>${packet.src_ip}</td>
                <td>${packet.dst_ip}</td>
                <td><span class="badge-protocol ${protoClass}">${packet.protocol}</span></td>
                <td class="mono">${packet.src_port || '-'}</td>
                <td class="mono">${packet.dst_port || '-'}</td>
                <td class="mono">${packet.length} B</td>
                <td>${classificationText}</td>
            `;
            
            tbody.insertBefore(row, tbody.firstChild);
            // Cap to 10 rows
            if (tbody.children.length > 10) {
                tbody.removeChild(tbody.lastChild);
            }
        }
    });

    sse.addEventListener('alert', (e) => {
        const alert = JSON.parse(e.data);
        
        // Increment alerts metrics counters
        const alertTotalSpan = document.getElementById('metric-total-alerts');
        if (alertTotalSpan) {
            alertTotalSpan.textContent = parseInt(alertTotalSpan.textContent) + 1;
        }
        
        // Update charts distributions
        updateThreatChartData(alert.severity);
        
        // Add to alert list feed panel
        const feedList = document.getElementById('alert-feed-list');
        if (feedList) {
            // Remove empty placeholder if any
            const placeholder = feedList.querySelector('.text-muted');
            if (placeholder && placeholder.textContent.includes('No alerts')) {
                feedList.innerHTML = '';
            }
            
            const item = document.createElement('div');
            item.className = 'alert-feed-item glass-panel';
            
            const sevBadgeClass = `badge-${alert.severity.toLowerCase()}`;
            const mlBadge = alert.is_ml ? `<span class="ml-tag"><i class="fas fa-brain"></i> ML AI</span>` : '';
            
            item.innerHTML = `
                <div class="alert-feed-header">
                    <span class="badge ${sevBadgeClass}">${alert.severity}</span>
                    <span class="alert-time">${alert.timestamp}</span>
                </div>
                <div class="alert-msg"><b>${alert.category}</b>: ${alert.message}</div>
                <div class="alert-meta">
                    <span>IP: ${alert.src_ip} &rarr; ${alert.dst_ip}</span>
                    ${mlBadge}
                </div>
            `;
            
            feedList.insertBefore(item, feedList.firstChild);
            
            // Cap at 15 items
            if (feedList.children.length > 15) {
                feedList.removeChild(feedList.lastChild);
            }
        }
    });
}

// ==========================================
// 2. DASHBOARD CHART GENERATION
// ==========================================
function initDashboardCharts() {
    const ctxThroughput = document.getElementById('chart-throughput').getContext('2d');
    const ctxThreats = document.getElementById('chart-threats').getContext('2d');
    const ctxPorts = document.getElementById('chart-ports').getContext('2d');
    
    // Initialize chart labels
    for (let i = maxChartPoints; i > 0; i--) {
        chartLabels.push('');
        packetCountHistory.push(0);
    }
    
    // 1. Throughput Line Chart
    trafficChart = new Chart(ctxThroughput, {
        type: 'line',
        data: {
            labels: chartLabels,
            datasets: [{
                label: 'Traffic Throughput (Packets/Sec)',
                data: packetCountHistory,
                borderColor: '#00f0ff',
                backgroundColor: 'rgba(0, 240, 255, 0.05)',
                borderWidth: 2,
                pointRadius: 0,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { display: false } },
                y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#94a3b8' }, min: 0 }
            }
        }
    });
    
    // Fetch distribution data for metrics charts from endpoint
    fetch('/api/stats-summary')
        .then(res => res.json())
        .then(data => {
            // 2. Threats Doughnut Chart
            threatChart = new Chart(ctxThreats, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        data: [
                            data.severity_counts.Critical || 0,
                            data.severity_counts.High || 0,
                            data.severity_counts.Medium || 0,
                            data.severity_counts.Low || 0
                        ],
                        backgroundColor: ['#ff3838', '#ff007f', '#ffe600', '#39ff14'],
                        borderWidth: 1,
                        borderColor: '#070913'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 12 } } }
                }
            });
            
            // 3. Top Attacking IPs / Targeted Ports Chart
            const portLabels = data.top_ports.map(p => `Port ${p[0]}`);
            const portValues = data.top_ports.map(p => p[1]);
            
            portChart = new Chart(ctxPorts, {
                type: 'bar',
                data: {
                    labels: portLabels.length ? portLabels : ['No Data'],
                    datasets: [{
                        data: portValues.length ? portValues : [0],
                        backgroundColor: 'rgba(0, 240, 255, 0.5)',
                        borderColor: '#00f0ff',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#94a3b8' } },
                        y: { ticks: { color: '#94a3b8' }, beginAtZero: true }
                    }
                }
            });
        });
}

function updateThroughputChart(pps) {
    if (!trafficChart) return;
    
    const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    chartLabels.push(now);
    packetCountHistory.push(pps);
    
    if (chartLabels.length > maxChartPoints) {
        chartLabels.shift();
        packetCountHistory.shift();
    }
    
    trafficChart.update();
}

function updateThreatChartData(severity) {
    if (!threatChart) return;
    const severityIdxMap = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
    const idx = severityIdxMap[severity];
    if (idx !== undefined) {
        threatChart.data.datasets[0].data[idx] += 1;
        threatChart.update();
    }
}

// ==========================================
// 3. ALERTS MANAGEMENT GRID
// ==========================================
function initAlertsPage() {
    // Action listeners for alerts grid
    const filterBtn = document.getElementById('apply-alerts-filter');
    if (filterBtn) {
        filterBtn.addEventListener('click', reloadAlertsGrid);
    }
    
    // Details modal trigger
    const alertsTable = document.querySelector('.data-table');
    if (alertsTable) {
        alertsTable.addEventListener('click', (e) => {
            const rowBtn = e.target.closest('.view-alert-details');
            if (rowBtn) {
                const alertId = rowBtn.dataset.id;
                openAlertDetails(alertId);
            }
        });
    }

    // Modal close controls
    const closeModalBtn = document.getElementById('close-details-modal');
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', () => {
            document.getElementById('details-modal').classList.remove('show');
        });
    }
}

function reloadAlertsGrid() {
    const sev = document.getElementById('filter-severity').value;
    const cat = document.getElementById('filter-category').value;
    const queryParams = new URLSearchParams();
    if (sev) queryParams.append('severity', sev);
    if (cat) queryParams.append('category', cat);
    
    window.location.href = `/alerts?${queryParams.toString()}`;
}

function openAlertDetails(alertId) {
    fetch(`/api/alert/${alertId}`)
        .then(res => res.json())
        .then(data => {
            if (data.error) return;
            
            document.getElementById('detail-id').textContent = data.id;
            document.getElementById('detail-time').textContent = data.timestamp;
            document.getElementById('detail-category').textContent = data.category;
            
            const sevBadge = document.getElementById('detail-severity');
            sevBadge.textContent = data.severity;
            sevBadge.className = `badge badge-${data.severity.toLowerCase()}`;
            
            document.getElementById('detail-src').textContent = data.src_ip;
            document.getElementById('detail-dst').textContent = data.dst_ip;
            document.getElementById('detail-msg').textContent = data.message;
            document.getElementById('detail-engine').textContent = data.is_ml ? `Machine Learning Anomaly Engine (Confidence: ${data.confidence * 100}%)` : 'Rule-Based Signatures & Heuristics';
            
            // Geolocation rendering
            const geo = data.geolocation;
            if (geo && geo.status === 'success') {
                document.getElementById('geo-country').textContent = geo.country + ` (${geo.countryCode})`;
                document.getElementById('geo-region').textContent = geo.regionName || 'N/A';
                document.getElementById('geo-city').textContent = geo.city || 'N/A';
                document.getElementById('geo-isp').textContent = geo.org || 'N/A';
                document.getElementById('geo-coords').textContent = `${geo.lat}, ${geo.lon}`;
            } else {
                document.getElementById('geo-country').textContent = 'Unknown (Lookup Failed)';
                document.getElementById('geo-region').textContent = '-';
                document.getElementById('geo-city').textContent = '-';
                document.getElementById('geo-isp').textContent = '-';
                document.getElementById('geo-coords').textContent = '-';
            }
            
            // Manage Alert Status Form inside details modal
            const statusForm = document.getElementById('update-status-form');
            if (statusForm) {
                statusForm.action = `/api/alert/${data.id}/update-status`;
                // Set active select
                document.getElementById('modal-status-select').value = data.status;
            }
            
            // Open modal
            document.getElementById('details-modal').classList.add('show');
        });
}

// ==========================================
// 4. HISTORICAL TRAFFIC LOGS
// ==========================================
function initLogsPage() {
    // Filter click
    const filterBtn = document.getElementById('apply-logs-filter');
    if (filterBtn) {
        filterBtn.addEventListener('click', () => {
            const ip = document.getElementById('filter-ip').value;
            const proto = document.getElementById('filter-proto').value;
            const queryParams = new URLSearchParams();
            if (ip) queryParams.append('ip', ip);
            if (proto) queryParams.append('protocol', proto);
            
            window.location.href = `/logs?${queryParams.toString()}`;
        });
    }
}

// ==========================================
// 5. SETTINGS PANEL CONTROL
// ==========================================
function initSettingsPage() {
    const trainBtn = document.getElementById('btn-train-ml');
    if (trainBtn) {
        trainBtn.addEventListener('click', () => {
            trainBtn.disabled = true;
            trainBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Training Model...`;
            
            fetch('/api/ml/train', { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    alert(data.message || 'Model trained successfully.');
                    location.reload();
                })
                .catch(err => {
                    alert('ML Training failed.');
                    trainBtn.disabled = false;
                    trainBtn.innerHTML = `<i class="fas fa-brain"></i> Retrain Anomaly Model`;
                });
        });
    }
}
