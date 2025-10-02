#!/usr/bin/env python3
"""
app.py - Flask Dashboard for Digital Forensics Toolkit

This module provides a web-based GUI interface for the incident response
and forensics toolkit. It offers real-time monitoring, evidence collection,
analysis controls, and visualization of forensic findings.

Features:
- Evidence collection dashboard
- Memory dump analysis interface
- File system forensics viewer
- Network packet analysis
- Timeline generation and visualization
- Encryption/decryption tools

Author: rahit91890
License: MIT
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import json
from datetime import datetime
import logging

# Import core modules
try:
    from core.evidence import EvidenceCollector
    from core.memdump import MemoryAnalyzer
    from core.fs_forensics import FileSystemForensics
    from core.packet_analysis import PacketAnalyzer
    from core.timeline import TimelineGenerator
    from core.crypto import CryptoSupport
except ImportError as e:
    logging.warning(f"Core modules not fully available: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-in-production-use-secrets'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'output'

# Ensure required directories exist
for folder in [app.config['UPLOAD_FOLDER'], app.config['OUTPUT_FOLDER']]:
    os.makedirs(folder, exist_ok=True)

# Global state management
analysis_state = {
    'active_collections': [],
    'completed_analyses': [],
    'timeline_data': [],
    'alerts': []
}


@app.route('/')
def index():
    """
    Main dashboard page.
    Provides overview of all forensics tools and active analyses.
    """
    return render_template('dashboard.html',
                         active_collections=analysis_state['active_collections'],
                         recent_analyses=analysis_state['completed_analyses'][-10:])


@app.route('/api/status')
def get_status():
    """
    Get current system and analysis status.
    Returns JSON with system health, active processes, and statistics.
    """
    status = {
        'timestamp': datetime.now().isoformat(),
        'active_collections': len(analysis_state['active_collections']),
        'completed_analyses': len(analysis_state['completed_analyses']),
        'alerts': len(analysis_state['alerts']),
        'system_health': 'operational'
    }
    return jsonify(status)


@app.route('/api/evidence/collect', methods=['POST'])
def collect_evidence():
    """
    Start evidence collection process.
    Supports disk imaging, memory dumps, and log extraction.
    """
    try:
        data = request.get_json()
        collection_type = data.get('type', 'disk')
        target = data.get('target', '')
        
        logger.info(f"Starting evidence collection: {collection_type} from {target}")
        
        # Initialize evidence collector
        # collector = EvidenceCollector()
        # result = collector.start_collection(collection_type, target)
        
        # Placeholder response
        result = {
            'collection_id': f"COL-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'type': collection_type,
            'target': target,
            'status': 'started',
            'timestamp': datetime.now().isoformat()
        }
        
        analysis_state['active_collections'].append(result)
        return jsonify(result), 202
        
    except Exception as e:
        logger.error(f"Evidence collection error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/memory/analyze', methods=['POST'])
def analyze_memory():
    """
    Analyze memory dump files.
    Extracts processes, network connections, and suspicious artifacts.
    """
    try:
        data = request.get_json()
        dump_file = data.get('dump_file', '')
        profile = data.get('profile', 'Win10x64')
        
        logger.info(f"Starting memory analysis: {dump_file} with profile {profile}")
        
        # analyzer = MemoryAnalyzer()
        # result = analyzer.analyze_dump(dump_file, profile)
        
        # Placeholder response
        result = {
            'analysis_id': f"MEM-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'dump_file': dump_file,
            'profile': profile,
            'processes': [],
            'connections': [],
            'suspicious_artifacts': [],
            'status': 'analyzing'
        }
        
        return jsonify(result), 202
        
    except Exception as e:
        logger.error(f"Memory analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/filesystem/analyze', methods=['POST'])
def analyze_filesystem():
    """
    Analyze file system from disk image.
    Supports FAT, NTFS, ext4 file systems.
    """
    try:
        data = request.get_json()
        image_file = data.get('image_file', '')
        fs_type = data.get('fs_type', 'auto')
        
        logger.info(f"Starting filesystem analysis: {image_file} ({fs_type})")
        
        # fs_analyzer = FileSystemForensics()
        # result = fs_analyzer.analyze_image(image_file, fs_type)
        
        # Placeholder response
        result = {
            'analysis_id': f"FS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'image_file': image_file,
            'fs_type': fs_type,
            'files_found': 0,
            'deleted_files': 0,
            'suspicious_files': [],
            'status': 'analyzing'
        }
        
        return jsonify(result), 202
        
    except Exception as e:
        logger.error(f"Filesystem analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/packets/analyze', methods=['POST'])
def analyze_packets():
    """
    Analyze network packet capture files.
    Extracts HTTP, DNS, TLS traffic and identifies anomalies.
    """
    try:
        data = request.get_json()
        pcap_file = data.get('pcap_file', '')
        
        logger.info(f"Starting packet analysis: {pcap_file}")
        
        # packet_analyzer = PacketAnalyzer()
        # result = packet_analyzer.analyze_pcap(pcap_file)
        
        # Placeholder response
        result = {
            'analysis_id': f"PKT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'pcap_file': pcap_file,
            'total_packets': 0,
            'protocols': {},
            'suspicious_traffic': [],
            'status': 'analyzing'
        }
        
        return jsonify(result), 202
        
    except Exception as e:
        logger.error(f"Packet analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/timeline/generate', methods=['POST'])
def generate_timeline():
    """
    Generate forensic timeline from multiple evidence sources.
    Correlates events across file system, memory, and network data.
    """
    try:
        data = request.get_json()
        sources = data.get('sources', [])
        
        logger.info(f"Generating timeline from {len(sources)} sources")
        
        # timeline_gen = TimelineGenerator()
        # result = timeline_gen.generate(sources)
        
        # Placeholder response
        result = {
            'timeline_id': f"TL-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'sources': sources,
            'events': [],
            'start_time': None,
            'end_time': None,
            'status': 'generating'
        }
        
        analysis_state['timeline_data'].append(result)
        return jsonify(result), 202
        
    except Exception as e:
        logger.error(f"Timeline generation error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/crypto/decrypt', methods=['POST'])
def decrypt_volume():
    """
    Decrypt encrypted volumes.
    Supports BitLocker, LUKS, and VeraCrypt.
    """
    try:
        data = request.get_json()
        volume_path = data.get('volume_path', '')
        crypto_type = data.get('type', 'bitlocker')
        password = data.get('password', '')
        
        logger.info(f"Attempting to decrypt {crypto_type} volume: {volume_path}")
        
        # crypto_support = CryptoSupport()
        # result = crypto_support.decrypt_volume(volume_path, crypto_type, password)
        
        # Placeholder response
        result = {
            'decrypt_id': f"DEC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'volume_path': volume_path,
            'type': crypto_type,
            'status': 'attempting',
            'mount_point': None
        }
        
        return jsonify(result), 202
        
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """
    Generate comprehensive forensic report.
    Includes all findings, timelines, and evidence artifacts.
    """
    try:
        data = request.get_json()
        analysis_ids = data.get('analysis_ids', [])
        report_format = data.get('format', 'pdf')
        
        logger.info(f"Generating {report_format} report for {len(analysis_ids)} analyses")
        
        # Placeholder response
        result = {
            'report_id': f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'analysis_ids': analysis_ids,
            'format': report_format,
            'status': 'generating',
            'download_url': None
        }
        
        return jsonify(result), 202
        
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Development server
    # For production, use gunicorn or uwsgi
    logger.info("Starting Digital Forensics Toolkit Dashboard")
    logger.info("Dashboard will be available at http://localhost:5000")
    logger.warning("This is a development server. Do not use in production!")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )
