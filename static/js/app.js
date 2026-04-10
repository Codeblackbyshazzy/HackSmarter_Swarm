const socket = io();

// UI Elements
const terminal = document.getElementById('terminal');
const statusBadge = document.getElementById('swarmStatus');
const historyList = document.getElementById('historyItems');
const markdownArea = document.getElementById('markdownArea');

// State
let isRunning = false;

// Handle Socket Logs
socket.on('log', (msg) => {
    const line = document.createElement('div');
    line.className = 'log-line';
    
    // Auto-coloring based on prefixes
    if (msg.data.includes('[*]')) line.classList.add('system');
    if (msg.data.includes('[!]')) line.style.color = '#ff9d00'; // Warning
    if (msg.data.includes('[ERROR]')) line.style.color = '#ff4a4a';
    
    line.textContent = msg.data;
    terminal.appendChild(line);
    
    // Auto-scroll to bottom
    terminal.scrollTop = terminal.scrollHeight;

    if (msg.data === "SWARM_COMPLETE") {
        setRunningState(false);
        refreshHistory();
    }
});

function deploySwarm() {
    if (isRunning) return;

    const targets = document.getElementById('targets').value;
    const clientName = document.getElementById('clientName').value;
    const excludes = Array.from(document.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value);

    if (!targets) {
        alert("Please enter at least one target.");
        return;
    }

    setRunningState(true);
    terminal.innerHTML = '<div class="log-line system">[*] Initializing Swarm Deployment...</div>';

    socket.emit('start_swarm', {
        targets: targets,
        client_name: clientName || 'default',
        exclude: excludes
    });
}

function setRunningState(running) {
    isRunning = running;
    const btn = document.getElementById('deployBtn');
    if (running) {
        btn.disabled = true;
        btn.textContent = "SWARM ACTIVE...";
        btn.classList.remove('pulse');
        statusBadge.textContent = "Deploying";
        statusBadge.style.color = "#7000ff";
        statusBadge.style.borderColor = "#7000ff";
    } else {
        btn.disabled = false;
        btn.textContent = "DEPLOY SWARM";
        btn.classList.add('pulse');
        statusBadge.textContent = "Standby";
        statusBadge.style.color = "#00f2ff";
        statusBadge.style.borderColor = "#00f2ff";
    }
}

// History & Report Management
async function refreshHistory() {
    try {
        const response = await fetch('/api/clients');
        const clients = await response.json();
        
        historyList.innerHTML = '';
        clients.forEach(client => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.textContent = client;
            div.onclick = () => loadReport(client);
            historyList.appendChild(div);
        });
    } catch (e) {
        console.error("Failed to load history", e);
    }
}

async function loadReport(client) {
    try {
        const response = await fetch(`/api/reports/${client}`);
        const data = await response.json();
        
        if (data.error) {
            alert(data.error);
            return;
        }

        markdownArea.innerHTML = marked.parse(data.content);
        showView('report');
    } catch (e) {
        alert("Failed to load report.");
    }
}

function showView(view) {
    document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
    document.querySelectorAll('.nav-item').forEach(v => v.classList.remove('active'));

    if (view === 'dashboard') {
        document.getElementById('dashboardView').classList.remove('hidden');
        document.querySelector('.nav-item:nth-child(1)').classList.add('active');
    } else if (view === 'report') {
        document.getElementById('reportView').classList.remove('hidden');
    }
}

// Initialization
refreshHistory();
setInterval(refreshHistory, 10000); // Polling for new folders every 10s
