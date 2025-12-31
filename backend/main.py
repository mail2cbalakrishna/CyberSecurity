"""
CyberSecurity AI Platform - Main FastAPI Application
Advanced Network Anomaly Detection and Threat Intelligence Platform
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
from system_monitor import MacOSThreatDetector
from datetime import datetime

# Create FastAPI app
app = FastAPI(
    title="CyberSecurity AI Platform",
    description="Advanced Network Anomaly Detection and Threat Intelligence Platform",
    version="1.0.0"
)

# Initialize threat detector
threat_detector = MacOSThreatDetector()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Basic health check endpoint
@app.get("/")
async def root():
    return {
        "message": "CyberSecurity AI Platform API",
        "version": "1.0.0",
        "status": "active"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/api/dashboard/summary")
async def dashboard_summary():
    """Get real-time dashboard summary with actual system data"""
    try:
        system_threats = threat_detector.get_system_threats()
        system_health = threat_detector.get_system_health()
        process_summary = threat_detector.get_running_processes_summary()
        
        # Count active threats and critical threats
        total_threats = (
            len(system_threats.get("process_threats", [])) +
            len(system_threats.get("network_threats", [])) +
            len(system_threats.get("file_threats", []))
        )
        
        # Count critical threats
        critical_threats = 0
        for threat_list in [system_threats.get("process_threats", []), 
                           system_threats.get("network_threats", []), 
                           system_threats.get("file_threats", [])]:
            for threat in threat_list:
                if threat.get("severity", "").lower() == "critical":
                    critical_threats += 1
        
        return {
            "stats": {
                "totalAlerts": len(system_threats.get("process_threats", [])) + len(system_threats.get("network_threats", [])),
                "activeThreats": total_threats,
                "total_threats": total_threats,
                "critical_threats": critical_threats,
                "systemStatus": system_health.get("status", "unknown"),
                "detectionRate": 98.5,  # This would be calculated based on actual detection metrics
                "networkHealth": 100 - (len(system_threats.get("network_threats", [])) * 10),
                "malwareBlocked": len(system_threats.get("process_threats", [])),
                "blocked_connections": len(system_threats.get("network_threats", [])),
                "monitored_processes": process_summary.get("process_count", 0),
                "cpuUsage": system_health.get("cpu_percent", 0),
                "memoryUsage": system_health.get("memory_percent", 0),
                "diskUsage": system_health.get("disk_percent", 0),
                "processCount": process_summary.get("process_count", 0)
            },
            "timeSeriesData": {
                "labels": ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"],
                "anomalies": [12, 19, 8, 15, 22, len(system_threats.get("network_threats", []))],
                "threats": [5, 8, 3, 7, 12, total_threats],
                "alerts": [18, 25, 12, 20, 31, len(system_threats.get("process_threats", []))]
            },
            "lastUpdated": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting dashboard data: {str(e)}")

# Anomalies endpoint
@app.get("/api/anomalies")
async def get_anomalies():
    return {
        "anomalies": [
            {
                "id": "anom-001",
                "timestamp": "2025-10-14T10:30:00Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.50",
                "protocol": "TCP",
                "anomaly_type": "traffic_anomaly",
                "confidence_score": 0.95,
                "severity": "high",
                "status": "open",
                "description": "Unusual traffic pattern detected"
            }
        ],
        "totalPages": 1
    }

# Threats endpoint  
@app.get("/api/threats")
async def get_threats():
    """Get real-time threats detected on the system"""
    try:
        system_threats = threat_detector.get_system_threats()
        
        threats = []
        threat_id = 1
        
        # Add process threats
        for proc_threat in system_threats.get("process_threats", []):
            threats.append({
                "id": f"threat-{threat_id:03d}",
                "timestamp": proc_threat["timestamp"],
                "threat_type": "suspicious_process",
                "severity": proc_threat["severity"],
                "status": "active",
                "source": "system_monitor",
                "title": f"Suspicious Process: {proc_threat['name']}",
                "description": proc_threat["description"],
                "confidence_score": 0.85,
                "details": {
                    "pid": proc_threat["pid"],
                    "cpu_percent": proc_threat["cpu_percent"],
                    "memory_percent": proc_threat["memory_percent"]
                }
            })
            threat_id += 1
        
        # Add network threats
        for net_threat in system_threats.get("network_threats", []):
            threats.append({
                "id": f"threat-{threat_id:03d}",
                "timestamp": net_threat["timestamp"],
                "threat_type": "network_anomaly",
                "severity": net_threat["severity"],
                "status": "active",
                "source": "network_monitor",
                "title": f"Suspicious Network Activity",
                "description": net_threat["description"],
                "confidence_score": 0.90,
                "details": {
                    "remote_ip": net_threat.get("remote_ip"),
                    "remote_port": net_threat.get("remote_port"),
                    "local_port": net_threat.get("local_port")
                }
            })
            threat_id += 1
            
        # Add file threats
        for file_threat in system_threats.get("file_threats", []):
            threats.append({
                "id": f"threat-{threat_id:03d}",
                "timestamp": file_threat["timestamp"],
                "threat_type": "file_anomaly",
                "severity": file_threat["severity"],
                "status": "active",
                "source": "file_monitor",
                "title": f"Suspicious File Activity",
                "description": file_threat["description"],
                "confidence_score": 0.75,
                "details": {
                    "filepath": file_threat.get("filepath"),
                    "directory": file_threat.get("directory"),
                    "modified_time": file_threat.get("modified_time")
                }
            })
            threat_id += 1
        
        return {
            "threats": threats,
            "totalPages": 1,
            "totalCount": len(threats),
            "lastUpdated": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting threats: {str(e)}")

# Alerts endpoint
@app.get("/api/alerts")
async def get_alerts():
    return {
        "alerts": [
            {
                "id": "alert-001",
                "timestamp": "2025-10-14T10:35:00Z",
                "type": "security_breach",
                "severity": "critical",
                "status": "open",
                "title": "Potential Security Breach",
                "message": "Unauthorized access attempt detected",
                "source": "network_monitor",
                "acknowledged": False
            }
        ],
        "totalPages": 1
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)