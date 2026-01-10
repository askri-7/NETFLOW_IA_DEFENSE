#!/usr/bin/env python3
"""
OSSEC Real-Time Detection System
Launches all processes with Queue communication
"""

from multiprocessing import Process, Queue, Event
import signal
import sys
import time

# Import process functions
from parser_realtime import run_parser
from features_realtime import run_features
from ml import run_detector

def signal_handler(sig, frame, shutdown_event):
    """Handle Ctrl+C gracefully"""
    print("\n\n⚠️  Interrupt received, shutting down...")
    shutdown_event.set()
    time.sleep(2)
    sys.exit(0)

def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║     OSSEC Real-Time Network Anomaly Detection System      ║
║          Queue-Based Multi-Process Architecture           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Create queues
    flows_queue = Queue(maxsize=10000)
    features_queue = Queue(maxsize=5000)
    alerts_queue = Queue(maxsize=1000)
    
    # Shutdown event
    shutdown_event = Event()
    
    # Setup signal handler
    signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, shutdown_event))
    
    # Create processes
    print("🚀 Starting processes...\n")
    
    p1 = Process(
        target=run_parser,
        args=(flows_queue, shutdown_event),
        name="Parser"
    )
    
    p2 = Process(
        target=run_features,
        args=(flows_queue, features_queue, shutdown_event),
        name="Features"
    )
    
    p3 = Process(
        target=run_detector,
        args=(features_queue, alerts_queue, shutdown_event),
        name="ML_Detector"
    )
    
    # Start all processes
    p1.start()
    print(f"✅ Process 1: Parser (PID: {p1.pid})")
    
    p2.start()
    print(f"✅ Process 2: Features (PID: {p2.pid})")
    
    p3.start()
    print(f"✅ Process 3: ML Detector (PID: {p3.pid})")
    
    print(f"\n{'='*70}")
    print(f"🎯 All processes running! Press Ctrl+C to stop")
    print(f"{'='*70}\n")
    
    # Monitor
    try:
        while not shutdown_event.is_set():
            time.sleep(5)
            
            # Queue status
            print(f"\r📊 Queues: Flows={flows_queue.qsize()} | "
                  f"Features={features_queue.qsize()} | "
                  f"Alerts={alerts_queue.qsize()}", end="")
    
    except KeyboardInterrupt:
        pass
    
    # Cleanup
    print("\n\n🛑 Shutting down all processes...")
    shutdown_event.set()
    
    p1.join(timeout=10)
    p2.join(timeout=10)
    p3.join(timeout=10)
    
    print("✅ All processes stopped")

if __name__ == "__main__":
    main()
