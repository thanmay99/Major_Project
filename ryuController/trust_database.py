# trust_database.py
import sqlite3
import time
import json
from typing import Dict, List, Optional

class TrustDatabase:
    """
    SQLite database for storing region trust history and metrics
    """
    
    def __init__(self, db_path: str = "trust_history.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
    
    def _create_tables(self):
        """Create necessary tables if they don't exist"""
        # Current trust scores
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS region_trust (
                region TEXT PRIMARY KEY,
                trust_score REAL NOT NULL,
                last_updated REAL NOT NULL,
                created_at REAL NOT NULL
            )
        ''')
        
        # Trust change history
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS trust_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                region TEXT NOT NULL,
                old_score REAL,
                new_score REAL NOT NULL,
                reason TEXT NOT NULL,
                timestamp REAL NOT NULL,
                FOREIGN KEY (region) REFERENCES region_trust (region)
            )
        ''')
        
        # Region metrics history
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS region_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                region TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                metric_value REAL NOT NULL,
                timestamp REAL NOT NULL
            )
        ''')
        
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_trust_history_region ON trust_history(region)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_trust_history_timestamp ON trust_history(timestamp)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_metrics_region ON region_metrics(region)')
        
        self.conn.commit()
    
    def update_trust_score(self, region: str, new_score: float, reason: str = "update") -> bool:
        """Update trust score and log the change"""
        try:
            current_time = time.time()
            
            # Get old score for history
            old_score = self.get_trust_score(region)
            
            # Update or insert current trust
            self.conn.execute(
                '''INSERT OR REPLACE INTO region_trust 
                   (region, trust_score, last_updated, created_at) 
                   VALUES (?, ?, ?, COALESCE((SELECT created_at FROM region_trust WHERE region = ?), ?))''',
                (region, new_score, current_time, region, current_time)
            )
            
            # Log to history
            self.conn.execute(
                "INSERT INTO trust_history (region, old_score, new_score, reason, timestamp) VALUES (?, ?, ?, ?, ?)",
                (region, old_score, new_score, reason, current_time)
            )
            
            self.conn.commit()
            return True
            
        except Exception as e:
            print(f"Database error updating trust score: {e}")
            self.conn.rollback()
            return False
    
    def get_trust_score(self, region: str) -> Optional[float]:
        """Get current trust score for a region"""
        try:
            cursor = self.conn.execute(
                "SELECT trust_score FROM region_trust WHERE region = ?", 
                (region,)
            )
            result = cursor.fetchone()
            return float(result[0]) if result else None
        except Exception as e:
            print(f"Database error getting trust score: {e}")
            return None
    
    def get_all_trust_scores(self) -> Dict[str, float]:
        """Get all current trust scores"""
        try:
            cursor = self.conn.execute("SELECT region, trust_score FROM region_trust")
            return {row[0]: float(row[1]) for row in cursor.fetchall()}
        except Exception as e:
            print(f"Database error getting all trust scores: {e}")
            return {}
    
    def get_trust_history(self, region: str, limit: int = 100) -> List[dict]:
        """Get trust history for a region"""
        try:
            cursor = self.conn.execute(
                "SELECT old_score, new_score, reason, timestamp FROM trust_history WHERE region = ? ORDER BY timestamp DESC LIMIT ?",
                (region, limit)
            )
            return [
                {
                    'old_score': row[0],
                    'new_score': row[1],
                    'reason': row[2],
                    'timestamp': row[3],
                    'time_ago': time.time() - row[3]
                }
                for row in cursor.fetchall()
            ]
        except Exception as e:
            print(f"Database error getting trust history: {e}")
            return []
    
    def save_region_metric(self, region: str, metric_type: str, metric_value: float):
        """Save region metric (congestion, latency, etc.)"""
        try:
            self.conn.execute(
                "INSERT INTO region_metrics (region, metric_type, metric_value, timestamp) VALUES (?, ?, ?, ?)",
                (region, metric_type, metric_value, time.time())
            )
            self.conn.commit()
        except Exception as e:
            print(f"Database error saving metric: {e}")
    
    def get_region_metrics(self, region: str, metric_type: str, hours: int = 24) -> List[dict]:
        """Get metrics for a region within time range"""
        try:
            time_threshold = time.time() - (hours * 3600)
            cursor = self.conn.execute(
                "SELECT metric_value, timestamp FROM region_metrics WHERE region = ? AND metric_type = ? AND timestamp > ? ORDER BY timestamp",
                (region, metric_type, time_threshold)
            )
            return [{'value': row[0], 'timestamp': row[1]} for row in cursor.fetchall()]
        except Exception as e:
            print(f"Database error getting metrics: {e}")
            return []
    
    def get_most_problematic_regions(self, limit: int = 5) -> List[dict]:
        """Get regions with lowest average trust"""
        try:
            cursor = self.conn.execute('''
                SELECT region, trust_score, last_updated 
                FROM region_trust 
                ORDER BY trust_score ASC 
                LIMIT ?
            ''', (limit,))
            
            return [
                {
                    'region': row[0],
                    'trust_score': row[1],
                    'last_updated': row[2]
                }
                for row in cursor.fetchall()
            ]
        except Exception as e:
            print(f"Database error getting problematic regions: {e}")
            return []
    
    def get_trust_statistics(self) -> dict:
        """Get overall trust statistics"""
        try:
            cursor = self.conn.execute('''
                SELECT 
                    COUNT(*) as total_regions,
                    AVG(trust_score) as avg_trust,
                    MIN(trust_score) as min_trust,
                    MAX(trust_score) as max_trust
                FROM region_trust
            ''')
            result = cursor.fetchone()
            
            return {
                'total_regions': result[0],
                'average_trust': round(result[1], 3) if result[1] else 0,
                'min_trust': result[2] or 0,
                'max_trust': result[3] or 0
            }
        except Exception as e:
            print(f"Database error getting statistics: {e}")
            return {}
    
    def emergency_reset_trust(self, regions: list, target_score: float = 0.7):
        """Emergency function to reset trust scores and break congestion death spiral"""
        try:
            current_time = time.time()
            for region in regions:
                # Reset trust score
                self.conn.execute(
                    '''INSERT OR REPLACE INTO region_trust 
                       (region, trust_score, last_updated, created_at) 
                       VALUES (?, ?, ?, COALESCE((SELECT created_at FROM region_trust WHERE region = ?), ?))''',
                    (region, target_score, current_time, region, current_time)
                )
                
                # Log emergency reset
                self.conn.execute(
                    "INSERT INTO trust_history (region, old_score, new_score, reason, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (region, self.get_trust_score(region), target_score, "EMERGENCY_RESET_BREAK_DEATH_SPIRAL", current_time)
                )
            
            self.conn.commit()
            print(f"🆘 EMERGENCY RESET: {len(regions)} regions set to {target_score}")
            return True
            
        except Exception as e:
            print(f"Emergency reset failed: {e}")
            self.conn.rollback()
            return False
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()