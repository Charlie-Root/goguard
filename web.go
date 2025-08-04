package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
)

// WebServer provides a simple web interface
type WebServer struct {
	monitor *Monitor
	config  *Config
}

// NewWebServer creates a new web server
func NewWebServer(monitor *Monitor, config *Config) *WebServer {
	return &WebServer{
		monitor: monitor,
		config:  config,
	}
}

// Start starts the web server
func (w *WebServer) Start() error {
	if !w.config.Web.Enabled {
		return nil
	}

	http.HandleFunc("/", w.handleDashboard)
	http.HandleFunc("/api/stats", w.handleStats)
	http.HandleFunc("/api/unban", w.handleUnban)

	addr := fmt.Sprintf(":%d", w.config.Web.Port)
	log.Printf("Starting web server on %s", addr)

	return http.ListenAndServe(addr, nil)
}

// handleDashboard serves the main dashboard
func (w *WebServer) handleDashboard(rw http.ResponseWriter, r *http.Request) {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>GoGuard - Security Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #3498db;
            --success: #27ae60;
            --danger: #e74c3c;
            --warning: #f39c12;
            --light: #ecf0f1;
            --dark: #34495e;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .navbar {
            background: var(--primary);
            color: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .navbar h1 {
            margin: 0;
            font-size: 1.5rem;
            display: flex;
            align-items: center;
        }
                
        .container { 
            max-width: 1400px; 
            margin: 2rem auto; 
            padding: 0 2rem;
        }
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 1.5rem; 
            margin-bottom: 2rem; 
        }
        
        .stat-card { 
            background: white; 
            padding: 2rem; 
            border-radius: 12px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            border-left: 4px solid var(--secondary);
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 15px rgba(0,0,0,0.2);
        }
        
        .stat-card.danger { border-left-color: var(--danger); }
        .stat-card.success { border-left-color: var(--success); }
        .stat-card.warning { border-left-color: var(--warning); }
        
        .stat-number { 
            font-size: 2.5rem; 
            font-weight: 700; 
            color: var(--primary);
            margin-bottom: 0.5rem;
        }
        
        .stat-label { 
            font-size: 0.9rem; 
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
            overflow: hidden;
        }
        
        .card-header {
            background: var(--light);
            padding: 1.5rem 2rem;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .card-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--primary);
            margin: 0;
        }
        
        .card-body {
            padding: 2rem;
        }
        
        .btn { 
            background: var(--secondary); 
            color: white; 
            border: none; 
            padding: 0.75rem 1.5rem; 
            border-radius: 6px; 
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            transition: all 0.2s ease;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn:hover { 
            background: #2980b9; 
            transform: translateY(-1px);
        }
        
        .btn-danger { background: var(--danger); }
        .btn-danger:hover { background: #c0392b; }
        
        .btn-success { background: var(--success); }
        .btn-success:hover { background: #229954; }
        
        .btn-small {
            padding: 0.5rem 1rem;
            font-size: 0.8rem;
        }
        
        table { 
            width: 100%; 
            border-collapse: collapse;
        }
        
        th, td { 
            padding: 1rem; 
            text-align: left; 
            border-bottom: 1px solid #dee2e6; 
        }
        
        th { 
            background: var(--light); 
            font-weight: 600; 
            color: var(--primary);
            position: sticky;
            top: 0;
        }
        
        tr:hover td {
            background: #f8f9fa;
        }
        
        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .alert {
            padding: 1rem;
            border-radius: 6px;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }
        
        .alert-info {
            background: #d1ecf1;
            border-color: #bee5eb;
            color: #0c5460;
        }
        
        .search-box {
            position: relative;
            margin-bottom: 1rem;
        }
        
        .search-input {
            width: 100%;
            padding: 0.75rem 1rem 0.75rem 2.5rem;
            border: 2px solid #dee2e6;
            border-radius: 6px;
            font-size: 1rem;
            transition: border-color 0.2s ease;
        }
        
        .search-input:focus {
            outline: none;
            border-color: var(--secondary);
        }
        
        .search-icon {
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            color: #666;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid var(--secondary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .config-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }
        
        .config-item {
            background: white;
            padding: 1rem;
            border-radius: 6px;
            border: 1px solid #dee2e6;
        }
        
        .config-label {
            font-weight: 600;
            color: var(--primary);
            display: block;
            margin-bottom: 0.5rem;
        }
        
        .config-value {
            color: #666;
        }
        
        .badge {
            background: var(--warning);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 3px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        @media (max-width: 768px) {
            .container { padding: 0 1rem; }
            .navbar { padding: 1rem; }
            .card-body { padding: 1rem; }
            .stats-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>GoGuard Security Dashboard</h1>
    </nav>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card danger">
                <div class="stat-number" id="totalBans">-</div>
                <div class="stat-label">Active Bans</div>
            </div>
            <div class="stat-card success">
                <div class="status-indicator">
                    <span class="status-dot"></span>
                    <div class="stat-number" id="status">Running</div>
                </div>
                <div class="stat-label">System Status</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="totalAttempts">-</div>
                <div class="stat-label">Failed Attempts Today</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-number" id="recentBans">-</div>
                <div class="stat-label">Bans Last Hour</div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Active Bans</h2>
                <div>
                    <button class="btn btn-success btn-small" onclick="loadStats()">
                        Refresh
                    </button>
                    <button class="btn btn-small" onclick="exportBans()">
                        Export
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div class="search-box">
                    <input type="text" class="search-input" id="searchInput" placeholder="Search IP addresses..." onkeyup="filterBans()">
                </div>
                
                <div style="overflow-x: auto;">
                    <table id="bansTable">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Reason</th>
                                <th>Banned At</th>
                                <th>Expires At</th>
                                <th>Duration</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="bansBody">
                            <tr><td colspan="6" style="text-align: center;"><div class="loading"></div> Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2 class="card-title">Configuration Overview</h2>
            </div>
            <div class="card-body">
                <div class="config-grid">
                    <div class="config-item">
                        <span class="config-label">Monitored Log Files</span>
                        <span class="config-value">{{.LogFiles}}</span>
                    </div>
                    <div class="config-item">
                        <span class="config-label">Whitelist Entries</span>
                        <span class="config-value">{{.Whitelist}}</span>
                    </div>
                    <div class="config-item">
                        <span class="config-label">Web Interface Port</span>
                        <span class="config-value">{{.WebPort}}</span>
                    </div>
                    <div class="config-item">
                        <span class="config-label">Abuse Reporting</span>
                        <span class="config-value">{{.AbuseReporting}}</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let allBans = [];
        
        function loadStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('totalBans').textContent = data.total_bans || 0;
                    document.getElementById('totalAttempts').textContent = data.total_attempts || 0;
                    document.getElementById('recentBans').textContent = data.recent_bans || 0;
                    
                    allBans = data.active_bans || [];
                    displayBans(allBans);
                })
                .catch(error => {
                    console.error('Error loading stats:', error);
                    document.getElementById('bansBody').innerHTML = 
                        '<tr><td colspan="6" style="text-align: center; color: #e74c3c;">❌ Error loading data</td></tr>';
                });
        }

        function displayBans(bans) {
            const tbody = document.getElementById('bansBody');
            
            if (bans && bans.length > 0) {
                tbody.innerHTML = bans.map(function(ban) {
                    const bannedAt = new Date(ban.banned_at);
                    const expiresAt = new Date(ban.expires_at);
                    const duration = formatDuration(expiresAt - bannedAt);
                    
                    return '<tr>' +
                        '<td><code>' + ban.ip + '</code></td>' +
                        '<td><span class="badge">' + ban.reason + '</span></td>' +
                        '<td>' + bannedAt.toLocaleString() + '</td>' +
                        '<td>' + expiresAt.toLocaleString() + '</td>' +
                        '<td>' + duration + '</td>' +
                        '<td>' +
                            '<button class="btn btn-danger btn-small" onclick="unbanIP(\'' + ban.ip + '\')">Unban</button> ' +
                            '<button class="btn btn-small" onclick="showIPInfo(\'' + ban.ip + '\')">ℹInfo</button>' +
                        '</td>' +
                    '</tr>';
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #27ae60;">No active bans</td></tr>';
            }
        }

        function filterBans() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const filteredBans = allBans.filter(function(ban) {
                return ban.ip.toLowerCase().includes(searchTerm) ||
                       ban.reason.toLowerCase().includes(searchTerm);
            });
            displayBans(filteredBans);
        }

        function formatDuration(ms) {
            const hours = Math.floor(ms / (1000 * 60 * 60));
            const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
            return hours + 'h ' + minutes + 'm';
        }

        function unbanIP(ip) {
            if (confirm('Are you sure you want to unban ' + ip + '?')) {
                fetch('/api/unban', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: ip})
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        loadStats();
                        showNotification('Successfully unbanned ' + ip, 'success');
                    } else {
                        showNotification('Failed to unban ' + ip + ': ' + data.error, 'error');
                    }
                })
                .catch(error => {
                    showNotification('Error unbanning ' + ip + ': ' + error, 'error');
                });
            }
        }

        function showIPInfo(ip) {
            alert('IP Information for ' + ip + '\\n\\nThis feature could show:\\n- Geolocation\\n- ISP information\\n- Threat intelligence\\n- Historical data');
        }

        function exportBans() {
            const csv = [
                ['IP Address', 'Reason', 'Banned At', 'Expires At']
            ].concat(allBans.map(function(ban) {
                return [
                    ban.ip,
                    ban.reason,
                    new Date(ban.banned_at).toISOString(),
                    new Date(ban.expires_at).toISOString()
                ];
            })).map(function(row) {
                return row.join(',');
            }).join('\\n');
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'goguard-bans-' + new Date().toISOString().split('T')[0] + '.csv';
            a.click();
            window.URL.revokeObjectURL(url);
        }

        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.className = 'alert alert-' + type;
            notification.textContent = message;
            notification.style.position = 'fixed';
            notification.style.top = '20px';
            notification.style.right = '20px';
            notification.style.zIndex = '1000';
            notification.style.minWidth = '300px';
            
            document.body.appendChild(notification);
            
            setTimeout(function() {
                notification.remove();
            }, 5000);
        }

        loadStats();
        setInterval(loadStats, 30000);
    </script>
</body>
</html>`

	// Prepare template data
	data := struct {
		LogFiles       string
		Whitelist      string
		WebPort        int
		AbuseReporting string
	}{
		LogFiles:       fmt.Sprintf("%d files", len(w.config.LogFiles)),
		Whitelist:      fmt.Sprintf("%d entries", len(w.config.Whitelist)),
		WebPort:        w.config.Web.Port,
		AbuseReporting: "Enabled", // You can make this dynamic based on config
	}

	t, err := template.New("dashboard").Parse(tmpl)
	if err != nil {
		http.Error(rw, "Template error", http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "text/html")
	t.Execute(rw, data)
}

// handleStats returns current statistics as JSON
func (w *WebServer) handleStats(rw http.ResponseWriter, r *http.Request) {
	stats := w.monitor.GetStats()

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(stats)
}

// handleUnban handles manual IP unbanning
func (w *WebServer) handleUnban(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Remove from bans using action manager
	w.monitor.mu.Lock()
	defer w.monitor.mu.Unlock()

	if _, exists := w.monitor.state.Bans[req.IP]; !exists {
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(map[string]interface{}{
			"success": false,
			"error":   "IP not found in ban list",
		})
		return
	}

	// Remove from firewall using action manager
	if err := w.monitor.actionManager.Unban(req.IP); err != nil {
		log.Printf("Failed to unban IP %s: %v", req.IP, err)
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to unban IP: %v", err),
		})
		return
	}

	// Remove from memory
	delete(w.monitor.state.Bans, req.IP)
	delete(w.monitor.state.FailureCounts, req.IP)
	w.monitor.saveState()

	log.Printf("Manually unbanned IP: %s", req.IP)

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]interface{}{
		"success": true,
	})
}
