let trafficChart;
let currentMode = "MANUAL";
let selectedDeviceIp = null;

async function updateDashboard() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        if (data.mode !== currentMode) {
            updateModeButtons(data.mode);
        }

        const total = data.users.reduce((sum, u) => sum + u.usage, 0);
        document.getElementById('total-usage').innerText = `${total.toFixed(2)} Mbps`;
        
        // Update Health Score
        const healthEl = document.getElementById('health-score');
        if (healthEl) {
            healthEl.innerText = data.health;
            if (data.health > 80) healthEl.style.color = '#10b981';
            else if (data.health > 50) healthEl.style.color = '#f59e0b';
            else healthEl.style.color = '#ef4444';
        }

        // Industry Alert Logic
        data.users.forEach(user => {
            if (data.anomalies && data.anomalies[user.ip]) {
                addAlert('warning', `ANOMALY: Unusual activity detected for ${user.ip}`);
            }
            if (user.usage > user.limit * 0.95) {
                addAlert('error', `CRITICAL: ${user.ip} reached bandwidth limit!`);
            }
        });

        renderUserCards(data.users, data.predictions);
        updateChart(data.history);
        renderTopology(data.topology);

        if (selectedDeviceIp && data.users.some(user => user.ip === selectedDeviceIp)) {
            viewDeviceDetails(selectedDeviceIp, true);
        }

    } catch (err) {
        console.error("Dashboard update failed:", err);
    }
}

function updateModeButtons(mode) {
    currentMode = mode;
    document.querySelectorAll('.mode-btn').forEach(btn => btn.classList.remove('active'));
    if (mode === 'MANUAL') {
        const btn = document.getElementById('btn-manual');
        if (btn) btn.classList.add('active');
    } else {
        const btn = document.getElementById('btn-auto');
        if (btn) btn.classList.add('active');
    }
}

async function setMode(mode) {
    const response = await fetch('/api/set_mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
    });
    const data = await response.json();
    if (data.status === 'success') {
        updateModeButtons(data.mode);
        updateDashboard();
    }
}

async function scanNetwork() {
    showToast("Scanning network... please wait.");
    const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
    });
    const data = await response.json();
    if (data.status === 'success') {
        showToast(`Scan complete! Found ${data.devices.length} devices.`);
        updateDashboard();
    } else {
        showToast(data.message || 'Scan failed');
    }
}

async function checkManualIP() {
    const ipInput = document.getElementById('manual-ip');
    if (!ipInput) return;

    const manualIp = ipInput.value.trim();
    if (!manualIp) {
        showToast('Please enter an IP address');
        return;
    }

    const response = await fetch('/api/manual_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: manualIp })
    });

    const data = await response.json();
    if (data.status === 'success') {
        const reachText = data.reachable ? 'reachable' : 'not reachable';
        showToast(`Manual IP check complete: ${manualIp} is ${reachText}`);
        ipInput.value = '';
        updateDashboard();
    } else {
        showToast(data.message || 'Manual IP check failed');
    }
}

async function addManualUserIP() {
    const ipInput = document.getElementById('manual-user-ip');
    const nameInput = document.getElementById('manual-user-name');
    const roleInput = document.getElementById('manual-user-role');

    if (!ipInput || !nameInput || !roleInput) return;

    const ip = ipInput.value.trim();
    const name = nameInput.value.trim();
    const role = roleInput.value;

    if (!ip) {
        showToast('Please enter user IP');
        return;
    }

    const response = await fetch('/api/manual_user_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, name, role })
    });

    const data = await response.json();
    if (data.status === 'success') {
        const reachText = data.reachable ? 'reachable' : 'not reachable';
        showToast(`Saved user IP ${ip} (${reachText})`);
        ipInput.value = '';
        nameInput.value = '';
        updateDashboard();
    } else {
        showToast(data.message || 'Failed to add user IP');
    }
}

async function cleanupUnnecessaryIPs() {
    const response = await fetch('/api/cleanup_devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
    });

    const data = await response.json();
    if (data.status === 'success') {
        showToast(`Cleanup complete: removed ${data.removed} unnecessary IP(s)`);
        updateDashboard();
    } else {
        showToast(data.message || 'Cleanup failed');
    }
}

function initManualIpInput() {
    const ipInput = document.getElementById('manual-ip');
    if (!ipInput) return;

    ipInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            checkManualIP();
        }
    });
}

function initManualUserInput() {
    const ipInput = document.getElementById('manual-user-ip');
    const nameInput = document.getElementById('manual-user-name');
    if (ipInput) {
        ipInput.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault();
                addManualUserIP();
            }
        });
    }
    if (nameInput) {
        nameInput.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault();
                addManualUserIP();
            }
        });
    }
}

async function toggleBlock(ip, currentStatus) {
    const action = currentStatus === 'BLOCKED' ? 'unblock' : 'block';
    const response = await fetch(`/api/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });
    const data = await response.json();
    if (data.status === 'success') {
        showToast(`IP ${ip} ${action}ed successfully`);
        updateDashboard();
    }
}

async function generateReport() {
    showToast("Generating usage report...");
    const response = await fetch('/api/generate_report', { method: 'POST' });
    const data = await response.json();
    if (data.status === 'success') {
        showToast(`Report generated: ${data.file.split('\\').pop()}`);
    }
}

function addAlert(type, message) {
    const list = document.getElementById('alert-list');
    if (!list) return;

    const time = new Date().toLocaleTimeString();
    const alert = document.createElement('div');
    alert.className = `alert-item ${type}`;
    alert.innerHTML = `<span style="opacity: 0.5;">[${time}]</span> ${message}`;
    
    list.prepend(alert);
    if (list.children.length > 5) {
        list.lastElementChild.remove();
    }
}

function renderUserCards(users, predictions = {}) {
    const grid = document.getElementById('user-grid');
    if (!grid) return;
    grid.innerHTML = '';

    users.forEach(user => {
        const pct = (user.usage / user.limit) * 100;
        const colorClass = user.role.toLowerCase();
        const isBlocked = user.status === 'BLOCKED';
        const prediction = predictions[user.ip] || 0;

        const card = document.createElement('div');
        card.className = `card ${isBlocked ? 'blocked-card' : ''}`;
        if (selectedDeviceIp === user.ip) {
            card.style.borderColor = '#6366f1';
            card.style.boxShadow = '0 0 0 1px rgba(99,102,241,0.35)';
        }
        card.innerHTML = `
            <div class="user-card-header">
                <div>
                    <span class="badge badge-${colorClass}">${user.role}</span>
                    <p style="font-weight: 700; margin-top: 5px;">${user.name} ${isBlocked ? '🛑' : ''}</p>
                    <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">Type: ${user.device_type || 'Unknown'}</p>
                </div>
                <div style="text-align: right;">
                    <span class="ip-label" style="display: block;">${user.ip}</span>
                    <span class="ip-label" style="font-size: 0.65rem; opacity: 0.7;">${user.mac}</span>
                </div>
            </div>
            <div style="display: flex; align-items: baseline; gap: 10px; margin-bottom: 15px;">
                <div class="usage-value" style="${isBlocked ? 'color: #999;' : ''}">
                    ${isBlocked ? '0.00' : user.usage.toFixed(2)} <span class="usage-unit">Mbps</span>
                </div>
                <div style="font-size: 0.7rem; color: #6366f1; font-weight: 600;">
                    ${isBlocked ? '' : '↗ AI Predict: ' + prediction.toFixed(2)}
                </div>
            </div>
            <div class="progress-bar-bg">
                <div class="progress-bar-fill" style="width: ${isBlocked ? 0 : Math.min(pct, 100)}%; background: ${isBlocked ? '#444' : ''}"></div>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted);">
                <span>Limit: ${user.limit} Mbps</span>
                <span>${isBlocked ? 'BLOCKED' : pct.toFixed(1) + '% Usage'}</span>
            </div>
            <hr style="margin: 1rem 0; border: none; border-top: 1px solid var(--border);">
            <div class="controls" style="justify-content: space-between; align-items: center;">
                <div style="display: flex; gap: 5px;">
                    <button onclick="changePriority('${user.ip}', 'Admin')" class="prio-btn ${user.role === 'Admin' ? 'active' : ''}">A</button>
                    <button onclick="changePriority('${user.ip}', 'Teacher')" class="prio-btn ${user.role === 'Teacher' ? 'active' : ''}">T</button>
                    <button onclick="changePriority('${user.ip}', 'Student')" class="prio-btn ${user.role === 'Student' ? 'active' : ''}">S</button>
                    <button onclick="changePriority('${user.ip}', 'Guest')" class="prio-btn ${user.role === 'Guest' ? 'active' : ''}">G</button>
                </div>
                <div style="display: flex; gap: 8px;">
                    <button onclick="viewDeviceDetails('${user.ip}')" class="prio-btn">DETAILS</button>
                    <button onclick="toggleBlock('${user.ip}', '${user.status}')" class="prio-btn" style="background: ${isBlocked ? '#10b981' : '#ef4444'}; border-color: ${isBlocked ? '#10b981' : '#ef4444'}">
                        ${isBlocked ? 'UNBLOCK' : 'BLOCK'}
                    </button>
                </div>
            </div>
        `;

        card.addEventListener('click', () => viewDeviceDetails(user.ip));
        grid.appendChild(card);
    });
}

async function viewDeviceDetails(ip, silent = false) {
    const panel = document.getElementById('device-details-content');
    if (!panel) return;

    selectedDeviceIp = ip;

    if (!silent) {
        panel.innerHTML = `Loading device details for ${ip}...`;
    }
    try {
        const response = await fetch(`/api/device/${encodeURIComponent(ip)}/details`);
        const data = await response.json();
        if (data.status !== 'success') {
            panel.innerHTML = data.message || 'Failed to fetch device details';
            if (!silent) {
                showToast(data.message || 'Failed to fetch device details');
            }
            return;
        }

        const device = data.device;
        const split = data.network_division;
        panel.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px;">
                <div class="card" style="padding: 1rem; border-radius: 12px;">
                    <div style="font-size: 0.75rem; color: var(--text-muted);">Device</div>
                    <div style="font-size: 1rem; font-weight: 700;">${device.name}</div>
                    <div style="font-size: 0.82rem; color: var(--text-muted);">${device.ip} • ${device.device_type}</div>
                </div>
                <div class="card" style="padding: 1rem; border-radius: 12px;">
                    <div style="font-size: 0.75rem; color: var(--text-muted);">Current Usage</div>
                    <div style="font-size: 1.15rem; font-weight: 700;">${split.current_usage_mbps} Mbps</div>
                    <div style="font-size: 0.82rem; color: var(--text-muted);">Usage share: ${split.usage_share_percent}%</div>
                </div>
                <div class="card" style="padding: 1rem; border-radius: 12px;">
                    <div style="font-size: 0.75rem; color: var(--text-muted);">Allocated Limit</div>
                    <div style="font-size: 1.15rem; font-weight: 700;">${split.allocated_limit_mbps} Mbps</div>
                    <div style="font-size: 0.82rem; color: var(--text-muted);">Limit share: ${split.limit_share_percent}%</div>
                </div>
                <div class="card" style="padding: 1rem; border-radius: 12px;">
                    <div style="font-size: 0.75rem; color: var(--text-muted);">Predicted Next</div>
                    <div style="font-size: 1.15rem; font-weight: 700;">${split.predicted_next_mbps} Mbps</div>
                    <div style="font-size: 0.82rem; color: var(--text-muted);">Role: ${device.role} • Status: ${device.status}</div>
                </div>
            </div>
        `;
    } catch (error) {
        panel.innerHTML = 'Failed to fetch device details';
        if (!silent) {
            showToast('Failed to fetch device details');
        }
    }
}

function renderTopology(topology) {
    const panel = document.getElementById('topology-content');
    if (!panel || !topology) return;

    const typeCounts = topology.device_type_counts || {};

    panel.innerHTML = `
        <div style="margin-bottom: 0.6rem;">
            <span class="badge badge-student">${topology.topology || 'Unknown'}</span>
            <span style="margin-left: 8px; color: var(--text-muted);">${topology.summary || ''}</span>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.45rem;">Likely layout: ${topology.likely_layout || 'N/A'}</div>
        <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.45rem;">Nodes: ${(topology.nodes || []).length} • Links: ${(topology.links || []).length} • Subnets: ${topology.subnet_count || 0}</div>
        <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.7rem;">This PC: ${typeCounts['This PC'] || 0} • PC: ${typeCounts['PC'] || 0} • Laptop: ${typeCounts['Laptop'] || 0} • Mobile: ${typeCounts['Mobile'] || 0} • Unknown: ${typeCounts['Unknown'] || 0}</div>
        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
            ${(topology.nodes || []).map(node => `<span class="badge badge-guest">${node.label}</span>`).join('')}
        </div>
    `;
}

async function changePriority(ip, prio) {
    const response = await fetch('/api/update_priority', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, priority: prio })
    });
    const data = await response.json();
    if (data.status === 'success') {
        updateDashboard();
    } else {
        showToast(data.message || "Priority update failed");
    }
}

function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    if (!ctx) return;
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: { labels: [], datasets: [] },
        options: {
            animation: false,
            responsive: true,
            interaction: { intersect: false, mode: 'index' },
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8e9297' } },
                x: { grid: { display: false }, ticks: { color: '#8e9297' } }
            },
            plugins: {
                legend: { labels: { color: '#fff', font: { family: 'Outfit', size: 10 } }, position: 'top' }
            }
        }
    });
}

function updateChart(history) {
    const ips = Object.keys(history);
    if (ips.length === 0 || !trafficChart) return;

    const colors = ['#6366f1', '#ef4444', '#f59e0b', '#10b981', '#ec4899'];
    const labels = history[ips[0]].map(h => h.time);

    const datasets = ips.map((ip, idx) => ({
        label: ip,
        data: history[ip].map(h => h.val),
        borderColor: colors[idx % colors.length],
        backgroundColor: colors[idx % colors.length] + '22',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0
    }));

    trafficChart.data.labels = labels;
    trafficChart.data.datasets = datasets;
    trafficChart.update('none');
}

function showToast(msg) {
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        toast.className = 'toast';
        document.body.appendChild(toast);
    }
    toast.innerText = msg;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
}

initChart();
initManualIpInput();
initManualUserInput();
setInterval(updateDashboard, 1000);
updateDashboard();
