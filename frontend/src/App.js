import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = 'http://localhost:8001';

function App() {
  const [threats, setThreats] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);
        
        const [threatsRes, summaryRes] = await Promise.all([
          axios.get(`${API_BASE}/api/threats`),
          axios.get(`${API_BASE}/api/dashboard/summary`)
        ]);
        
        setThreats(threatsRes.data.threats || []);
        setSummary(summaryRes.data || {});
      } catch (err) {
        setError(`Failed to fetch data: ${err.message}`);
        console.error('API Error:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return '#ff4444';
      case 'high': return '#ff8800';
      case 'medium': return '#ffaa00';
      case 'low': return '#88aa00';
      default: return '#888888';
    }
  };

  if (error) {
    return (
      <div style={{ background: '#0a0a0a', color: '#fff', minHeight: '100vh', padding: '20px', fontFamily: 'monospace' }}>
        <div style={{ textAlign: 'center', marginTop: '100px' }}>
          <h1 style={{ color: '#ff4444' }}>Connection Error</h1>
          <p>{error}</p>
          <p style={{ color: '#888' }}>Make sure the backend is running at {API_BASE}</p>
        </div>
      </div>
    );
  }

  if (loading && threats.length === 0) {
    return (
      <div style={{ background: '#0a0a0a', color: '#fff', minHeight: '100vh', padding: '20px', fontFamily: 'monospace' }}>
        <div style={{ textAlign: 'center', marginTop: '100px' }}>
          <h1 style={{ color: '#00ff88' }}>Loading threat data...</h1>
        </div>
      </div>
    );
  }

  return (
    <div style={{ background: '#0a0a0a', color: '#fff', minHeight: '100vh', padding: '20px', fontFamily: 'monospace' }}>
      <h1 style={{ color: '#00ff88', marginBottom: '20px' }}>🛡️ Cybersecurity Threat Monitor</h1>
      <div style={{ marginBottom: '20px', fontSize: '14px', color: '#888' }}>
        Last updated: {new Date().toLocaleTimeString()} | Auto-refresh every 5s
        {loading && <span style={{ color: '#00ff88' }}> (Refreshing...)</span>}
      </div>

      {summary && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '15px', marginBottom: '30px' }}>
          <div style={{ background: '#1a1a1a', padding: '15px', borderRadius: '8px', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', color: '#00ff88', fontWeight: 'bold' }}>{summary.total_threats || 0}</div>
            <div style={{ color: '#888' }}>Total Threats</div>
          </div>
          <div style={{ background: '#1a1a1a', padding: '15px', borderRadius: '8px', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', color: '#ff4444', fontWeight: 'bold' }}>{summary.critical_threats || 0}</div>
            <div style={{ color: '#888' }}>Critical</div>
          </div>
          <div style={{ background: '#1a1a1a', padding: '15px', borderRadius: '8px', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', color: '#0088ff', fontWeight: 'bold' }}>{summary.blocked_connections || 0}</div>
            <div style={{ color: '#888' }}>Blocked</div>
          </div>
          <div style={{ background: '#1a1a1a', padding: '15px', borderRadius: '8px', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', color: '#ffaa00', fontWeight: 'bold' }}>{summary.monitored_processes || 0}</div>
            <div style={{ color: '#888' }}>Processes</div>
          </div>
        </div>
      )}

      <h2 style={{ color: '#00ff88', borderLeft: '4px solid #00ff88', paddingLeft: '10px', marginBottom: '20px' }}>
        Recent Threats ({threats.length})
      </h2>

      {threats.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#00ff88', background: '#0a2a0a', borderRadius: '8px', border: '1px solid #004400' }}>
          🎉 No active threats detected
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
          {threats.map((threat, index) => (
            <div key={index} style={{ background: '#1a1a1a', border: '1px solid #333', borderRadius: '8px', padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <span style={{ 
                  background: getSeverityColor(threat.severity), 
                  color: '#fff', 
                  padding: '4px 12px', 
                  borderRadius: '20px', 
                  fontSize: '12px', 
                  fontWeight: 'bold' 
                }}>
                  {threat.severity?.toUpperCase() || 'UNKNOWN'}
                </span>
                <span style={{ color: '#888', fontSize: '14px' }}>
                  {formatTimestamp(threat.timestamp)}
                </span>
              </div>
              <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#ff8800', marginBottom: '8px' }}>
                {threat.type}
              </div>
              <div style={{ color: '#ccc', lineHeight: '1.5', marginBottom: '15px' }}>
                {threat.description}
              </div>
              {threat.details && (
                <div style={{ background: '#0f0f0f', border: '1px solid #2a2a2a', borderRadius: '4px', padding: '10px', fontSize: '14px' }}>
                  {Object.entries(threat.details).map(([key, value]) => (
                    <div key={key} style={{ marginBottom: '5px', color: '#aaa' }}>
                      <strong>{key}:</strong> {JSON.stringify(value)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default App;