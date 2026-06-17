from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
import db_manager

# Define Prometheus metrics
SCANS_TOTAL = Counter(
    'forensics_scans_total', 
    'Total number of files scanned by the platform', 
    ['risk_level', 'source']
)

MONITOR_ACTIVE = Gauge(
    'forensics_monitor_active', 
    'Folder monitor active state (1 = active, 0 = inactive)'
)

AVG_THREAT_SCORE = Gauge(
    'forensics_average_threat_score', 
    'Average threat score of all files scanned'
)

ZERO_DAYS_TOTAL = Counter(
    'forensics_zero_days_total',
    'Total number of potential zero-day malware detected'
)

metrics_initialized = False

def init_metrics():
    """Sync metrics with the database state on startup."""
    global metrics_initialized
    if metrics_initialized:
        return
        
    try:
        stats = db_manager.get_stats()
        
        # Note: Counter values are strictly increasing, so we cannot set them directly.
        # But we can increment them by the historical count to seed them at startup.
        # If the app restarts, counters in memory restart from 0, which is normal for Prometheus.
        # We populate counters on first start.
        if stats['safe'] > 0:
            SCANS_TOTAL.labels(risk_level='Safe', source='historical').inc(stats['safe'])
        if stats['suspicious'] > 0:
            SCANS_TOTAL.labels(risk_level='Suspicious', source='historical').inc(stats['suspicious'])
        if stats['malicious'] > 0:
            SCANS_TOTAL.labels(risk_level='Malicious', source='historical').inc(stats['malicious'])
            
        if stats['zero_days'] > 0:
            ZERO_DAYS_TOTAL.inc(stats['zero_days'])
            
        AVG_THREAT_SCORE.set(stats['avg_score'])
        
        # Check folder monitor state
        monitored = db_manager.get_monitored_paths()
        active = 1 if any(p['active'] == 1 for p in monitored) else 0
        MONITOR_ACTIVE.set(active)
        
        metrics_initialized = True
        print("Prometheus metrics initialized from MySQL.")
    except Exception as e:
        print(f"Failed to initialize metrics: {e}")

def record_scan_metrics(risk_level, source, threat_score, is_zero_day=False):
    """Update metrics when a new scan is processed."""
    try:
        # Increment counter
        SCANS_TOTAL.labels(risk_level=risk_level, source=source).inc()
        
        if is_zero_day:
            ZERO_DAYS_TOTAL.inc()
            
        # Re-calculate average threat score from database
        stats = db_manager.get_stats()
        AVG_THREAT_SCORE.set(stats['avg_score'])
    except Exception as e:
        print(f"Failed to record scan metrics: {e}")

def update_monitor_state(is_active):
    """Update the monitoring state gauge."""
    MONITOR_ACTIVE.set(1 if is_active else 0)

def export_metrics():
    """Generates the metrics buffer in Prometheus text format."""
    # Ensure metrics are initialized
    init_metrics()
    return generate_latest(), CONTENT_TYPE_LATEST
