let chartInstance = null;
let lastUpdate = Date.now();

async function fetchDevices() {
    try {
        const response = await fetch('/devices');
        return await response.json();
    } catch (e) {
        console.error("Failed to fetch devices:", e);
        return [];
    }
}

async function fetchUsage() {
    try {
        const response = await fetch('/usage');
        return await response.json();
    } catch (e) {
        console.error("Failed to fetch usage:", e);
        return {};
    }
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function updateChart(devices, usageData) {
    const ctx = document.getElementById('usageChart').getContext('2d');
    
    const labels = [];
    const data = [];
    const backgroundColors = [];
    
    // Sort devices by usage
    const sortedDevices = [...devices].sort((a, b) => (usageData[b.ip] || 0) - (usageData[a.ip] || 0));

    sortedDevices.forEach((device, index) => {
        labels.push(device.name !== "Unknown" ? device.name : device.ip);
        data.push(usageData[device.ip] || 0);
        
        let hue = (index * 137.5 + 200) % 360;
        backgroundColors.push(`hsla(${hue}, 70%, 60%, 0.7)`);
    });

    if (chartInstance) {
        chartInstance.data.labels = labels;
        chartInstance.data.datasets[0].data = data;
        chartInstance.data.datasets[0].backgroundColor = backgroundColors;
        chartInstance.update();
    } else {
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = '#334155';
        
        chartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Bytes Used',
                    data: data,
                    backgroundColor: backgroundColors,
                    borderWidth: 1,
                    borderColor: backgroundColors.map(c => c.replace('0.7', '1'))
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return formatBytes(context.raw);
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                return formatBytes(value);
                            }
                        }
                    }
                }
            }
        });
    }
}

function updateUI(devices, usage) {
    // 1. Update Top User
    let topUser = null;
    let maxUsage = -1;
    
    for (const [ip, bytes] of Object.entries(usage)) {
        if (bytes > maxUsage) {
            maxUsage = bytes;
            topUser = ip;
        }
    }
    
    const topUserDiv = document.getElementById('top-user');
    if (topUser && devices.length > 0) {
        let device = devices.find(d => d.ip === topUser);
        let name = device ? device.name : topUser;
        if (name === "Unknown") name = topUser;
        topUserDiv.innerHTML = `<p>${name}</p><small>${formatBytes(maxUsage)}</small>`;
    } else {
        topUserDiv.innerHTML = `<p>No data yet</p><small>Waiting for packets...</small>`;
    }

    // 2. Update Table
    const tbody = document.getElementById('devices-table-body');
    tbody.innerHTML = '';
    
    devices.forEach(device => {
        const used = usage[device.ip] || 0;
        const tr = document.createElement('tr');
        
        let nameDisplay = device.name;
        if (nameDisplay === "Unknown" || nameDisplay === "Unknown Device") {
            nameDisplay = `<span class="unknown-badge">Unknown</span>`;
        }
        
        tr.innerHTML = `
            <td>${device.ip}</td>
            <td style="font-family: monospace;">${device.mac}</td>
            <td>${nameDisplay}</td>
            <td style="font-weight: bold; color: var(--accent-color);">${formatBytes(used)}</td>
        `;
        tbody.appendChild(tr);
    });

    // 3. Update Chart
    updateChart(devices, usage);
    
    // Update status
    const statusSpan = document.querySelector('#status span');
    statusSpan.textContent = 'Live - Last Updated: ' + new Date().toLocaleTimeString();
    statusSpan.style.color = '#4ade80';
}

async function refreshData() {
    const devices = await fetchDevices();
    const usage = await fetchUsage();
    updateUI(devices, usage);
}

// Initial fetch and set interval (every 5 seconds)
refreshData();
setInterval(refreshData, 5000);
