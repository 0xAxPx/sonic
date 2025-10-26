import React, { useState, useEffect } from 'react';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api/v1';
const API_KEY = process.env.REACT_APP_API_KEY || 'dev-api-key-12345';

function App() {
  const [stats, setStats] = useState({
    total_threats: 0,
    total_normal: 0,
    total_processed: 0
  });
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchData();
    // Refresh every 5 seconds
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      // Fetch stats
      const statsResponse = await fetch(`${API_URL}/stats`, {
        headers: {
          'X-API-Key': API_KEY
        }
      });
      
      if (statsResponse.ok) {
        const statsData = await statsResponse.json();
        setStats(statsData.stats || stats);
      }

      // Fetch alerts
      const alertsResponse = await fetch(`${API_URL}/alerts`, {
        headers: {
          'X-API-Key': API_KEY
        }
      });
      
      if (alertsResponse.ok) {
        const alertsData = await alertsResponse.json();
        setAlerts(alertsData.data || []);
      }

      setLoading(false);
      setError(null);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="App">
        <div className="loading">Loading...</div>
      </div>
    );
  }

  return (
    <div className="App">
      <header className="App-header">
        <h1>🛡️ Cybersecurity Threat Detector</h1>
        <p>Real-time Network Threat Monitoring</p>
      </header>

      {error && (
        <div className="error-banner">
          ⚠️ Error connecting to API: {error}
        </div>
      )}

      <main className="dashboard">
        {/* Stats Cards */}
        <section className="stats-grid">
          <div className="stat-card">
            <h3>Total Processed</h3>
            <p className="stat-value">{stats.total_processed}</p>
          </div>
          <div className="stat-card threats">
            <h3>Threats Detected</h3>
            <p className="stat-value">{stats.total_threats}</p>
          </div>
          <div className="stat-card normal">
            <h3>Normal Traffic</h3>
            <p className="stat-value">{stats.total_normal}</p>
          </div>
          <div className="stat-card">
            <h3>Threat Rate</h3>
            <p className="stat-value">
              {stats.total_processed > 0 
                ? ((stats.total_threats / stats.total_processed) * 100).toFixed(1)
                : 0}%
            </p>
          </div>
        </section>

        {/* Recent Alerts */}
        <section className="alerts-section">
          <h2>Recent Alerts</h2>
          {alerts.length === 0 ? (
            <div className="empty-state">
              <p>✅ No threats detected yet. System is monitoring...</p>
            </div>
          ) : (
            <div className="alerts-list">
              {alerts.map((alert, index) => (
                <div key={index} className="alert-item">
                  <div className="alert-header">
                    <span className={`severity ${alert.severity}`}>
                      {alert.severity?.toUpperCase()}
                    </span>
                    <span className="alert-time">
                      {new Date(alert.created_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="alert-description">
                    {alert.description || 'Threat detected'}
                  </p>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Status Indicator */}
        <section className="status-bar">
          <div className="status-indicator">
            <span className="status-dot active"></span>
            <span>System Active - Last updated: {new Date().toLocaleTimeString()}</span>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;