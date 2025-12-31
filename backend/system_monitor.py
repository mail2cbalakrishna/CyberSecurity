"""
Real-time macOS System Threat Detection
Monitors actual system threats and security events
"""

import psutil
import socket
import subprocess
import json
import re
from datetime import datetime
from typing import List, Dict, Any
import hashlib
import os

class MacOSThreatDetector:
    def __init__(self):
        self.suspicious_processes = [
            'coinminer', 'cryptominer', 'bitcoin', 'monero',
            'backdoor', 'keylogger', 'trojan', 'malware',
            'suspicious', 'hack', 'exploit'
        ]
        
        self.suspicious_network_ports = [
            4444, 5555, 6666, 7777, 8888, 9999,  # Common backdoor ports
            1337, 31337,  # Leet ports
            6667, 6697,  # IRC ports (potential botnets)
        ]
        
        self.high_risk_directories = [
            '/tmp', '/var/tmp', '/private/tmp',
            '/Library/LaunchDaemons', '/Library/LaunchAgents',
            '/System/Library/LaunchDaemons'
        ]

    def get_system_threats(self) -> Dict[str, Any]:
        """Get comprehensive system threat assessment"""
        threats = {
            "process_threats": self.detect_suspicious_processes(),
            "network_threats": self.detect_network_anomalies(),
            "file_threats": self.detect_file_anomalies(),
            "system_health": self.get_system_health(),
            "active_connections": self.get_suspicious_connections(),
            "timestamp": datetime.now().isoformat()
        }
        return threats

    def detect_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Detect potentially malicious processes"""
        suspicious = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name'].lower()
                    
                    # Check for suspicious process names
                    is_suspicious = any(sus in proc_name for sus in self.suspicious_processes)
                    
                    # Check for high CPU usage (potential cryptominer)
                    high_cpu = proc_info['cpu_percent'] > 80
                    
                    # Check for unusual command line arguments
                    cmdline = ' '.join(proc_info['cmdline'] or []).lower()
                    has_crypto_keywords = any(keyword in cmdline for keyword in 
                                            ['mining', 'pool', 'stratum', 'crypto', 'coin'])
                    
                    if is_suspicious or (high_cpu and has_crypto_keywords):
                        threat_level = "critical" if is_suspicious else "high"
                        suspicious.append({
                            "id": f"proc-{proc_info['pid']}",
                            "type": "suspicious_process",
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "cpu_percent": proc_info['cpu_percent'],
                            "memory_percent": proc_info['memory_percent'],
                            "severity": threat_level,
                            "description": f"Suspicious process detected: {proc_info['name']}",
                            "timestamp": datetime.now().isoformat()
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Error in process detection: {e}")
            
        return suspicious

    def detect_network_anomalies(self) -> List[Dict[str, Any]]:
        """Detect suspicious network activity"""
        anomalies = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    local_port = conn.laddr.port
                    
                    # Check for suspicious ports
                    if remote_port in self.suspicious_network_ports or local_port in self.suspicious_network_ports:
                        anomalies.append({
                            "id": f"net-{local_port}-{remote_port}",
                            "type": "suspicious_connection",
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "severity": "high",
                            "description": f"Connection to suspicious port {remote_port}",
                            "timestamp": datetime.now().isoformat()
                        })
                    
                    # Check for connections to known malicious IPs (simplified check)
                    if self.is_suspicious_ip(remote_ip):
                        anomalies.append({
                            "id": f"ip-{remote_ip}",
                            "type": "malicious_ip",
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "severity": "critical",
                            "description": f"Connection to potentially malicious IP: {remote_ip}",
                            "timestamp": datetime.now().isoformat()
                        })
                        
        except Exception as e:
            print(f"Error in network detection: {e}")
            
        return anomalies

    def detect_file_anomalies(self) -> List[Dict[str, Any]]:
        """Detect suspicious file system activity"""
        anomalies = []
        
        try:
            # Check for files in high-risk directories
            for directory in self.high_risk_directories:
                if os.path.exists(directory):
                    try:
                        for filename in os.listdir(directory):
                            filepath = os.path.join(directory, filename)
                            
                            # Check for recently modified files
                            if os.path.isfile(filepath):
                                stat = os.stat(filepath)
                                # Files modified in last hour
                                if (datetime.now().timestamp() - stat.st_mtime) < 3600:
                                    anomalies.append({
                                        "id": f"file-{hashlib.md5(filepath.encode()).hexdigest()[:8]}",
                                        "type": "suspicious_file",
                                        "filepath": filepath,
                                        "directory": directory,
                                        "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                        "severity": "medium",
                                        "description": f"Recently modified file in sensitive directory: {filename}",
                                        "timestamp": datetime.now().isoformat()
                                    })
                    except PermissionError:
                        continue
                        
        except Exception as e:
            print(f"Error in file detection: {e}")
            
        return anomalies

    def get_system_health(self) -> Dict[str, Any]:
        """Get current system health metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Determine health status
            health_status = "healthy"
            if cpu_percent > 90 or memory.percent > 90 or disk.percent > 90:
                health_status = "warning"
            if cpu_percent > 95 or memory.percent > 95 or disk.percent > 95:
                health_status = "critical"
                
            return {
                "status": health_status,
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": disk.percent,
                "uptime": datetime.now().timestamp() - psutil.boot_time(),
                "process_count": len(psutil.pids())
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def get_suspicious_connections(self) -> List[Dict[str, Any]]:
        """Get currently active network connections for analysis"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    connections.append({
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "status": conn.status,
                        "pid": conn.pid
                    })
        except Exception as e:
            print(f"Error getting connections: {e}")
            
        return connections

    def is_suspicious_ip(self, ip: str) -> bool:
        """Simple check for potentially suspicious IPs"""
        # This is a simplified check - in production, you'd use threat intelligence feeds
        suspicious_patterns = [
            r'^0\.', r'^127\.', r'^255\.',  # Invalid/local IPs in external connections
            r'^10\.',  # Private IP range 10.0.0.0/8
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',  # Private IP range 172.16.0.0/12 only
            r'^192\.168\.'  # Private IP range 192.168.0.0/16
        ]
        
        return any(re.match(pattern, ip) for pattern in suspicious_patterns)

    def get_running_processes_summary(self) -> Dict[str, Any]:
        """Get summary of running processes"""
        try:
            processes = []
            total_cpu = 0
            total_memory = 0
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    total_cpu += info['cpu_percent'] or 0
                    total_memory += info['memory_percent'] or 0
                    
                    # Only include processes using significant resources
                    if (info['cpu_percent'] or 0) > 5 or (info['memory_percent'] or 0) > 5:
                        processes.append({
                            "pid": info['pid'],
                            "name": info['name'],
                            "cpu_percent": info['cpu_percent'],
                            "memory_percent": info['memory_percent']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            return {
                "process_count": len(psutil.pids()),
                "high_resource_processes": sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:10],
                "total_cpu_usage": total_cpu,
                "system_memory_usage": psutil.virtual_memory().percent
            }
        except Exception as e:
            return {"error": str(e)}