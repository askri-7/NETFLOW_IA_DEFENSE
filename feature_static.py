#!/usr/bin/env python3

"""
OSSEC Network Traffic Anomaly Defender - Phase 2: Feature Engineering
Transforms raw flows into ML-ready feature vectors
Normalizes, cleans, and creates aggregation features for attack detection
Session-based architecture: Analyzes latest session only
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler, StandardScaler
import joblib
import os
import time
import glob

# ==================== Configuration ====================
FLOWS_DIR = 'flows'  # Session files directory
OUTPUT_DIR = 'engineered'  # Output directory for engineered features
SCALER_FILE = "feature_scaler.joblib"

# Time windows for aggregation features (seconds)
SCAN_WINDOW = 300  # 5 minutes - for port scan detection
C2_WINDOW = 600  # 10 minutes - for C2 beacon detection

# Feature normalization method: 'minmax' or 'standard'
NORMALIZATION_METHOD = 'minmax'  # Min-Max (0-1) for Isolation Forest

# Outlier handling: percentile to clip extreme values
OUTLIER_CLIP_PERCENTILE = 99  # Cap at 99th percentile

# Metadata columns (don't normalize these)
METADATA_COLS = [
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
    'start_timestamp'
]

print("""
╔═══════════════════════════════════════════════════════════╗
║   OSSEC Anomaly Defender - Phase 2: Feature Engineering   ║
║        Transform Flows → ML-Ready Feature Vectors         ║
║             Session-Based Analysis                        ║
╚═══════════════════════════════════════════════════════════╝
""")

# ==================== Helper Functions ====================

def get_latest_session():
    """Find the latest session file"""
    session_files = glob.glob(os.path.join(FLOWS_DIR, 'flows_session_*.csv'))
    
    if not session_files:
        print(f"❌ Error: No session files found in {FLOWS_DIR}/")
        print("   Run parser.py first to generate session files")
        return None
    
    # Sort by session number
    session_files.sort()
    latest = session_files[-1]
    
    # Extract session number
    basename = os.path.basename(latest)
    session_num = basename.split('_')[2].split('.')[0]
    
    return latest, session_num

def get_session_by_number(session_num):
    """Get specific session file by number"""
    session_file = os.path.join(FLOWS_DIR, f'flows_session_{session_num:03d}.csv')
    
    if not os.path.exists(session_file):
        return None
    
    return session_file

# ==================== Step 0: Select Session ====================

print("📂 Step 0: Selecting session to analyze...")

# Check if user specified a session number (optional enhancement)
# For now, always use latest session
INPUT_FILE, session_id = get_latest_session()

if INPUT_FILE is None:
    exit(1)

print(f"✅ Selected Session #{session_id}")
print(f"   File: {os.path.basename(INPUT_FILE)}\n")

# Create output directory
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Output file for this session
OUTPUT_FILE = os.path.join(OUTPUT_DIR, f'flows_engineered_session_{session_id}.csv')

# ==================== Step 1: Load Raw Flows ====================

print("📂 Step 1: Loading raw flow data...")
start_time = time.time()

df = pd.read_csv(INPUT_FILE)
original_count = len(df)

print(f"✅ Loaded {len(df):,} flows from Session #{session_id}")
print(f"   Columns: {df.shape[1]}")
print(f"   Memory: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

if 'start_timestamp' in df.columns:
    print(f"   Date range: {pd.to_datetime(df['start_timestamp'], unit='s').min()} to {pd.to_datetime(df['start_timestamp'], unit='s').max()}\n")
else:
    print()

# ==================== Step 2: Data Quality Checks ====================

print("🔍 Step 2: Data quality assessment...")

# Check for missing values
missing_per_col = df.isnull().sum()
cols_with_missing = missing_per_col[missing_per_col > 0]

if len(cols_with_missing) > 0:
    print(f"   ⚠️  Found missing values in {len(cols_with_missing)} columns:")
    for col, count in cols_with_missing.items():
        print(f"      - {col}: {count} ({count/len(df)*100:.2f}%)")
else:
    print(f"   ✅ No missing values found")

# Check for infinite values
feature_cols = [col for col in df.columns if col not in METADATA_COLS]
inf_count = 0

for col in feature_cols:
    if df[col].dtype in [np.float64, np.float32, np.int64, np.int32]:
        inf_in_col = np.isinf(df[col]).sum()
        if inf_in_col > 0:
            print(f"   ⚠️  Found {inf_in_col} infinite values in '{col}'")
            inf_count += inf_in_col

if inf_count == 0:
    print(f"   ✅ No infinite values found")

print()

# ==================== Step 3: Handle Missing/Infinite Values ====================

print("🧹 Step 3: Cleaning data...")

# Replace infinity with NaN first, then fill
for col in feature_cols:
    if df[col].dtype in [np.float64, np.float32, np.int64, np.int32]:
        df[col].replace([np.inf, -np.inf], np.nan, inplace=True)

# Fill NaN with 0 (safe assumption for network features)
before_fill = df.isnull().sum().sum()
df.fillna(0, inplace=True)
after_fill = df.isnull().sum().sum()

print(f"   Cleaned {before_fill} missing/infinite values")
print(f"   Remaining NaN: {after_fill}")
print(f"   ✅ Data cleaning complete\n")

# ==================== Step 4: Outlier Handling ====================

print(f"🎯 Step 4: Handling outliers (clipping at {OUTLIER_CLIP_PERCENTILE}th percentile)...")

outlier_stats = []

for col in feature_cols:
    if df[col].dtype in [np.float64, np.float32, np.int64, np.int32]:
        # Skip binary/flag columns (only 0 and 1)
        if df[col].nunique() <= 2:
            continue
        
        # Calculate percentile threshold
        upper_limit = df[col].quantile(OUTLIER_CLIP_PERCENTILE / 100)
        
        # Count values above threshold
        outliers = (df[col] > upper_limit).sum()
        
        if outliers > 0:
            # Clip outliers
            df[col] = df[col].clip(upper=upper_limit)
            outlier_stats.append({
                'column': col,
                'outliers_clipped': outliers,
                'threshold': upper_limit
            })

if outlier_stats:
    print(f"   Clipped outliers in {len(outlier_stats)} columns:")
    for stat in outlier_stats[:5]:  # Show first 5
        print(f"      - {stat['column']}: {stat['outliers_clipped']} values clipped at {stat['threshold']:.2f}")
    if len(outlier_stats) > 5:
        print(f"      ... and {len(outlier_stats) - 5} more columns")
else:
    print(f"   ✅ No extreme outliers detected")

print()

# ==================== Step 5: Aggregation Features ====================

print("📊 Step 5: Creating aggregation features for attack detection...")

# Sort by timestamp for time-based aggregations
if 'start_timestamp' in df.columns:
    df = df.sort_values('start_timestamp').reset_index(drop=True)

print("   Computing per-source-IP aggregations...")

# ===== Port Scan Detection Features =====
# Count unique destination ports per source IP in time window
port_scan_features = df.groupby('src_ip').agg({
    'dst_port': lambda x: x.nunique(),  # Unique ports contacted
    'dst_ip': lambda x: x.nunique(),  # Unique IPs contacted
    'duration': 'sum',  # Total active time
    'total_fwd_packets': 'sum'  # Total packets sent
}).rename(columns={
    'dst_port': 'unique_dst_ports_per_src',
    'dst_ip': 'unique_dst_ips_per_src',
    'duration': 'total_src_duration',
    'total_fwd_packets': 'total_src_packets'
})

# Merge back to original dataframe
df = df.merge(port_scan_features, left_on='src_ip', right_index=True, how='left')
print(f"   ✅ Added: unique_dst_ports_per_src, unique_dst_ips_per_src")

# ===== DDoS Detection Features =====
# Count unique source IPs per destination IP
ddos_features = df.groupby('dst_ip').agg({
    'src_ip': lambda x: x.nunique(),
    'total_bwd_packets': 'sum'
}).rename(columns={
    'src_ip': 'unique_src_ips_per_dst',
    'total_bwd_packets': 'total_dst_packets'
})

df = df.merge(ddos_features, left_on='dst_ip', right_index=True, how='left')
print(f"   ✅ Added: unique_src_ips_per_dst (for DDoS detection)")

# ===== Protocol Distribution =====
# Count unique protocols per source IP
protocol_diversity = df.groupby('src_ip')['protocol'].nunique().rename('unique_protocols_per_src')
df = df.merge(protocol_diversity, left_on='src_ip', right_index=True, how='left')
print(f"   ✅ Added: unique_protocols_per_src")

# Fill any NaN from merges
df.fillna(0, inplace=True)
print(f"\n   Total features now: {df.shape[1]} columns\n")

# ==================== Step 6: Feature Normalization ====================

print(f"📏 Step 6: Normalizing features ({NORMALIZATION_METHOD})...")

# Separate metadata from features
numeric_feature_cols = [col for col in df.columns if col not in METADATA_COLS]

# Extract feature matrix
X = df[numeric_feature_cols].copy()

print(f"   Features to normalize: {len(numeric_feature_cols)}")
print(f"   Feature matrix shape: {X.shape}")

# Choose scaler based on configuration
if NORMALIZATION_METHOD == 'minmax':
    scaler = MinMaxScaler()  # Scales to [0, 1]
    print(f"   Using Min-Max Scaler (range: 0 to 1)")
elif NORMALIZATION_METHOD == 'standard':
    scaler = StandardScaler()  # Mean=0, Std=1
    print(f"   Using Standard Scaler (mean=0, std=1)")
else:
    print(f"   ❌ Unknown normalization method: {NORMALIZATION_METHOD}")
    exit(1)

# Fit and transform
X_normalized = scaler.fit_transform(X)

# Convert back to DataFrame
df_normalized = pd.DataFrame(X_normalized, columns=numeric_feature_cols)

# Verify normalization
print(f"\n   Normalization results:")
if NORMALIZATION_METHOD == 'minmax':
    print(f"      Min value: {df_normalized.min().min():.6f}")
    print(f"      Max value: {df_normalized.max().max():.6f}")
else:
    print(f"      Mean: {df_normalized.mean().mean():.6f}")
    print(f"      Std: {df_normalized.std().mean():.6f}")

# Save scaler for later use
scaler_file = os.path.join(OUTPUT_DIR, f'scaler_session_{session_id}.joblib')
joblib.dump(scaler, scaler_file)
print(f"\n💾 Scaler saved to: {scaler_file}\n")

# ==================== Step 7: Combine and Export ====================

print("📦 Step 7: Combining metadata + normalized features...")

# Combine metadata columns with normalized features
metadata_df = df[METADATA_COLS].reset_index(drop=True)
final_df = pd.concat([metadata_df, df_normalized], axis=1)

print(f"   Final dataset shape: {final_df.shape}")
print(f"   Metadata columns: {len(METADATA_COLS)}")
print(f"   Feature columns: {len(numeric_feature_cols)}")

# ==================== Step 8: Quality Verification ====================

print("\n✅ Step 8: Final quality checks...")

# Check for any remaining issues
final_nulls = final_df.isnull().sum().sum()
final_infs = np.isinf(final_df.select_dtypes(include=[np.number])).sum().sum()

print(f"   Null values: {final_nulls}")
print(f"   Infinite values: {final_infs}")
print(f"   Total rows: {len(final_df):,}")

if final_nulls == 0 and final_infs == 0:
    print(f"   ✅ Dataset is clean and ready for ML!\n")
else:
    print(f"   ⚠️  Warning: Dataset still has quality issues!\n")

# ==================== Step 9: Save Results ====================

print("💾 Step 9: Saving engineered features...")

final_df.to_csv(OUTPUT_FILE, index=False)

print(f"✅ Saved to: {OUTPUT_FILE}")
print(f"   File size: {os.path.getsize(OUTPUT_FILE) / 1024**2:.2f} MB\n")

# ==================== Step 10: Feature Statistics ====================

print("📊 Step 10: Feature Engineering Summary:")
print("=" * 70)

# Show some interesting statistics
top_port_scanners = df.nlargest(5, 'unique_dst_ports_per_src')[['src_ip', 'unique_dst_ports_per_src', 'unique_dst_ips_per_src']]

if len(top_port_scanners) > 0:
    print("\n🚨 Top 5 IPs by unique ports contacted (potential port scans):")
    for idx, row in top_port_scanners.iterrows():
        print(f"   {row['src_ip']}: {int(row['unique_dst_ports_per_src'])} ports, {int(row['unique_dst_ips_per_src'])} IPs")

top_ddos_targets = df.nlargest(5, 'unique_src_ips_per_dst')[['dst_ip', 'unique_src_ips_per_dst']]

if len(top_ddos_targets) > 0:
    print("\n🎯 Top 5 IPs by unique sources (potential DDoS targets):")
    for idx, row in top_ddos_targets.iterrows():
        print(f"   {row['dst_ip']}: contacted by {int(row['unique_src_ips_per_dst'])} unique sources")

# Protocol distribution
print("\n📡 Protocol distribution:")
protocol_counts = df['protocol'].value_counts().head(10)
for proto, count in protocol_counts.items():
    print(f"   {proto}: {count:,} flows ({count/len(df)*100:.1f}%)")

print("\n" + "=" * 70)

# ==================== Final Summary ====================

total_time = time.time() - start_time

print(f"\n{'='*70}")
print(f"📊 PHASE 2 COMPLETE - SESSION #{session_id} ENGINEERED")
print("=" * 70)
print(f"⏱️  Execution time: {total_time:.2f}s")
print(f"📦 Input flows: {original_count:,}")
print(f"📦 Output flows: {len(final_df):,}")
print(f"🎯 Total features: {len(numeric_feature_cols)}")
print(f"   - Original parser features: ~53")
print(f"   - New aggregation features: {len(numeric_feature_cols) - 53}")
print(f"📁 Input file: {os.path.basename(INPUT_FILE)}")
print(f"📁 Output file: {os.path.basename(OUTPUT_FILE)}")
print(f"💾 Scaler saved: {os.path.basename(scaler_file)}")
print(f"🔄 Normalization: {NORMALIZATION_METHOD}")
print(f"✅ Ready for Phase 3: Machine Learning (Isolation Forest)")
print(f"{'='*70}\n")
