// ── Chart global defaults ──
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#21262d';

// ── Chart instances ──
const frequencyChart = new Chart(document.getElementById('frequencyChart'), {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            data: [],
            borderColor: '#388bfd',
            backgroundColor: 'rgba(56,139,253,0.08)',
            borderWidth: 2,
            tension: 0.4,
            fill: true,
            pointRadius: 2,
            pointBackgroundColor: '#388bfd',
        }]
    },
    options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
            x: {
                grid: { color: '#21262d' },
                ticks: { color: '#8b949e', font: { size: 10 } }
            },
            y: {
                grid: { color: '#21262d' },
                ticks: { color: '#8b949e', stepSize: 2, font: { size: 10 } },
                beginAtZero: true
            }
        }
    }
});

const typeChart = new Chart(document.getElementById('typeChart'), {
    type: 'doughnut',
    data: {
        labels: ['ARP_SPOOF', 'PORT_SCAN', 'SYN_FLOOD'],
        datasets: [{
            data: [0, 0, 0],
            backgroundColor: ['#f85149', '#d29922', '#388bfd'],
            borderColor: '#161b22',
            borderWidth: 3,
            hoverOffset: 6,
        }]
    },
    options: {
        responsive: true,
        cutout: '65%',
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    color: '#8b949e',
                    padding: 20,
                    font: { size: 11 },
                    usePointStyle: true,
                    pointStyleWidth: 8,
                }
            }
        }
    }
});

const ipChart = new Chart(document.getElementById('ipChart'), {
    type: 'bar',
    data: {
        labels: [],
        datasets: [{
            data: [],
            backgroundColor: '#388bfd',
            borderRadius: 3,
            barThickness: 14,
        }]
    },
    options: {
        indexAxis: 'y',
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
            x: {
                grid: { color: '#21262d' },
                ticks: { color: '#8b949e', font: { size: 10 } },
                beginAtZero: true
            },
            y: {
                grid: { display: false },
                ticks: { color: '#8b949e', font: { size: 10 } }
            }
        }
    }
});

// ── Shared state ──
const state = {
    total: 0, high: 0, medium: 0, low: 0,
    byType:   { ARP_SPOOF: 0, PORT_SCAN: 0, SYN_FLOOD: 0 },
    byIp:     {},
    byMinute: {},
};

// ── Update functions ──
function updateStats() {
    document.getElementById('stat-total').textContent  = state.total;
    document.getElementById('stat-high').textContent   = state.high;
    document.getElementById('stat-medium').textContent = state.medium;
    document.getElementById('stat-low').textContent    = state.low;
}

function updateFrequency() {
    const labels = Object.keys(state.byMinute).slice(-20);
    frequencyChart.data.labels = labels;
    frequencyChart.data.datasets[0].data = labels.map(k => state.byMinute[k]);
    frequencyChart.update('none');
}

function updateType() {
    typeChart.data.datasets[0].data = [
        state.byType.ARP_SPOOF,
        state.byType.PORT_SCAN,
        state.byType.SYN_FLOOD,
    ];
    typeChart.update('none');
}

function updateIp() {
    const sorted = Object.entries(state.byIp)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);
    ipChart.data.labels = sorted.map(e => e[0]);
    ipChart.data.datasets[0].data = sorted.map(e => e[1]);
    ipChart.update('none');
}

function addToFeed(alert) {
    const feed = document.getElementById('alert-feed');
    const empty = feed.querySelector('.empty-state');
    if (empty) empty.remove();

    const time = alert.timestamp
        ? alert.timestamp.split('T')[1].split('.')[0]
        : '--:--:--';

    const item = document.createElement('div');
    item.className = `alert-item ${alert.severity}`;
    item.innerHTML = `
        <div class="alert-left">
            <span class="severity-badge badge-${alert.severity}">${alert.severity}</span>
        </div>
        <div class="alert-body">
            <div class="alert-top">
                <span class="alert-type">${alert.attack_type}</span>
                <span class="alert-ip">${alert.source_ip}</span>
            </div>
            <div class="alert-message">${alert.message}</div>
        </div>
        <div class="alert-time">${time}</div>
    `;

    feed.prepend(item);
    while (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

// ── Core: process one alert through all components ──
function processAlert(alert) {
    state.total++;
    if      (alert.severity === 'HIGH')   state.high++;
    else if (alert.severity === 'MEDIUM') state.medium++;
    else if (alert.severity === 'LOW')    state.low++;

    if (state.byType[alert.attack_type] !== undefined)
        state.byType[alert.attack_type]++;

    state.byIp[alert.source_ip] = (state.byIp[alert.source_ip] || 0) + 1;

    const minute = alert.timestamp
        ? alert.timestamp.split('T')[1].substring(0, 5)
        : 'unknown';
    state.byMinute[minute] = (state.byMinute[minute] || 0) + 1;

    updateStats();
    updateFrequency();
    updateType();
    updateIp();
    addToFeed(alert);
}

// ── Load history on page load ──
fetch('/api/alerts/history')
    .then(r => r.json())
    .then(alerts => {
        alerts.forEach(a => {
            const m = a.raw.match(
                /\[(.+?)\] \[(.+?)\] (.+?) \| src: (.+?) \| (.+)/
            );
            if (m) {
                processAlert({
                    timestamp:   m[1],
                    severity:    m[2],
                    attack_type: m[3],
                    source_ip:   m[4],
                    message:     m[5],
                });
            }
        });
    });

// ── SSE connection ──
const evtSource = new EventSource('/api/alerts/stream');

evtSource.onopen = function() {
    document.getElementById('live-dot').classList.remove('disconnected');
    document.getElementById('live-text').textContent = 'Live';
};

evtSource.onmessage = function(event) {
    processAlert(JSON.parse(event.data));
};

evtSource.onerror = function() {
    document.getElementById('live-dot').classList.add('disconnected');
    document.getElementById('live-text').textContent = 'Disconnected';
};