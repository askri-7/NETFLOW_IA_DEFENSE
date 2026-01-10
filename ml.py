#!/usr/bin/env python3

"""
OSSEC Network Traffic Anomaly Defender - Phase 3: ML Detection (Real-Time)
Uses Isolation Forest for unsupervised anomaly detection
Reads features from Queue, predicts anomalies, sends alerts to Queue
Continuous processing for real-time detection
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os
import time
from multiprocessing import Queue
import queue
import json
from datetime import datetime

# Configuration
MODEL_DIR = 'models'
MODEL_FILE = os.path.join(MODEL_DIR, 'isolation_forest.joblib')
ALERTS_DIR = 'alerts'
ALERTS_FILE = os.path.join(ALERTS_DIR, 'alerts.jsonl')

# ML Parameters
CONTAMINATION = 0.1  # Expected percentage of anomalies (10%)
RANDOM_STATE = 42

# Metadata columns (don't use for prediction)
METADATA_COLS = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'start_timestamp']

class MLDetector:
    def __init__(self, input_queue, output_queue, shutdown_event):
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.shutdown_event = shutdown_event
        
        # Create directories
        os.makedirs(MODEL_DIR, exist_ok=True)
        os.makedirs(ALERTS_DIR, exist_ok=True)
        
        # Load or create model
        self.model = self._load_or_create_model()
        
        # Stats
        self.stats = {
            'batches_processed': 0,
            'total_flows': 0,
            'total_anomalies': 0,
            'alerts_sent': 0
        }
        
        print(f"[ML] 🚀 Started (Queue-based)")
    
    def _load_or_create_model(self):
        """Load existing model or create new one"""
        if os.path.exists(MODEL_FILE):
            try:
                model = joblib.load(MODEL_FILE)
                print(f"[ML] ✅ Loaded trained model from {MODEL_FILE}")
                return model
            except Exception as e:
                print(f"[ML] ⚠️  Error loading model: {e}")
        
        print(f"[ML] 🆕 Creating new Isolation Forest model")
        model = IsolationForest(
            contamination=CONTAMINATION,
            random_state=RANDOM_STATE,
            n_estimators=100,
            max_samples='auto',
            n_jobs=-1  # Use all CPU cores
        )
        
        return model
    
    def run(self):
        """Main detection loop"""
        print(f"[ML] 👂 Waiting for features from feature engineering...")
        
        first_batch = True
        
        while not self.shutdown_event.is_set():
            try:
                # Get features from queue (timeout 1s)
                data = self.input_queue.get(timeout=1)
                
                features_list = data['features']
                timestamp = data['timestamp']
                count = data['count']
                
                print(f"\n[ML] 📥 Received {count} feature vectors")
                
                # Convert to DataFrame
                df = pd.DataFrame(features_list)
                
                if len(df) == 0:
                    continue
                
                # Separate metadata from features
                metadata_df = df[METADATA_COLS].copy()
                feature_cols = [col for col in df.columns if col not in METADATA_COLS]
                X = df[feature_cols].values
                
                # First batch: Train the model
                if first_batch:
                    print(f"[ML] 🎓 Training model on first batch ({len(X)} samples)...")
                    self.model.fit(X)
                    
                    # Save model
                    joblib.dump(self.model, MODEL_FILE)
                    print(f"[ML] 💾 Model saved to {MODEL_FILE}")
                    
                    first_batch = False
                
                # Predict anomalies
                predictions = self.model.predict(X)  # 1 = normal, -1 = anomaly
                scores = self.model.score_samples(X)  # Anomaly scores (lower = more anomalous)
                
                # Find anomalies
                anomaly_mask = predictions == -1
                num_anomalies = anomaly_mask.sum()
                
                if num_anomalies > 0:
                    print(f"[ML] 🚨 Detected {num_anomalies} anomalies out of {len(X)} flows!")
                    
                    # Get anomalous flows with metadata
                    anomalies_df = metadata_df[anomaly_mask].copy()
                    anomalies_df['anomaly_score'] = scores[anomaly_mask]
                    anomalies_df['timestamp'] = timestamp
                    
                    # Generate alerts
                    self._generate_alerts(anomalies_df)
                    
                    self.stats['total_anomalies'] += num_anomalies
                else:
                    print(f"[ML] ✅ No anomalies detected ({len(X)} flows analyzed)")
                
                self.stats['batches_processed'] += 1
                self.stats['total_flows'] += len(X)
                
                # Show stats every 10 batches
                if self.stats['batches_processed'] % 10 == 0:
                    self._print_stats()
            
            except queue.Empty:
                continue
            
            except Exception as e:
                if not self.shutdown_event.is_set():
                    print(f"[ML] ⚠️  Error: {e}")
                    import traceback
                    traceback.print_exc()
                time.sleep(0.1)
        
        print(f"[ML] 🛑 Shutting down...")
        self._print_stats()
    
    def _generate_alerts(self, anomalies_df):
        """Generate and send alerts for anomalies"""
        
        for idx, row in anomalies_df.iterrows():
            alert = {
                'timestamp': datetime.fromtimestamp(row['timestamp']).isoformat(),
                'src_ip': row['src_ip'],
                'dst_ip': row['dst_ip'],
                'src_port': int(row['src_port']),
                'dst_port': int(row['dst_port']),
                'protocol': row['protocol'],
                'anomaly_score': float(row['anomaly_score']),
                'severity': self._calculate_severity(row['anomaly_score']),
                'type': 'ml_anomaly'
            }
            
            # Print alert
            self._print_alert(alert)
            
            # Save to file
            self._save_alert(alert)
            
            # Send to queue (for OSSEC integration later)
            try:
                self.output_queue.put(alert, block=False)
                self.stats['alerts_sent'] += 1
            except:
                pass
    
    def _calculate_severity(self, score):
        """Calculate severity based on anomaly score"""
        # Scores typically range from -0.5 (very anomalous) to 0.5 (normal)
        if score < -0.3:
            return 'CRITICAL'
        elif score < -0.2:
            return 'HIGH'
        elif score < -0.1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _print_alert(self, alert):
        """Print alert to console"""
        severity_icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        icon = severity_icons.get(alert['severity'], '⚪')
        
        print(f"\n{'='*70}")
        print(f"{icon} ANOMALY ALERT - {alert['severity']}")
        print(f"{'='*70}")
        print(f"Time:     {alert['timestamp']}")
        print(f"Source:   {alert['src_ip']}:{alert['src_port']}")
        print(f"Dest:     {alert['dst_ip']}:{alert['dst_port']}")
        print(f"Protocol: {alert['protocol']}")
        print(f"Score:    {alert['anomaly_score']:.4f} (lower = more suspicious)")
        print(f"{'='*70}\n")
    
    def _save_alert(self, alert):
        """Save alert to JSONL file"""
        try:
            with open(ALERTS_FILE, 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except Exception as e:
            print(f"[ML] ⚠️  Error saving alert: {e}")
    
    def _print_stats(self):
        """Print detection statistics"""
        detection_rate = (self.stats['total_anomalies'] / self.stats['total_flows'] * 100) if self.stats['total_flows'] > 0 else 0
        
        print(f"\n[ML] 📊 Statistics:")
        print(f"     Batches processed: {self.stats['batches_processed']}")
        print(f"     Total flows: {self.stats['total_flows']}")
        print(f"     Anomalies detected: {self.stats['total_anomalies']} ({detection_rate:.2f}%)")
        print(f"     Alerts sent: {self.stats['alerts_sent']}")

def run_detector(input_queue, output_queue, shutdown_event):
    """Main ML detector process entry point"""
    detector = MLDetector(input_queue, output_queue, shutdown_event)
    detector.run()
