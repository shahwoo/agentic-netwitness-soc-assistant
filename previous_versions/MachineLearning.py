import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# 1. Create Mock Data (NumPy)
# Normal traffic: random intervals between 10 and 300 seconds
normal_intervals = np.random.randint(10, 300, size=100)

# Attack traffic (Beaconing): 5 requests exactly 60 seconds apart
attack_intervals = np.array([60, 60, 60, 60, 60])

# Combine them
all_data = np.concatenate([normal_intervals, attack_intervals]).reshape(-1, 1)

# 2. Organize Data (Pandas)
df = pd.DataFrame(all_data, columns=['seconds_between_requests'])

# 3. Detect Anomalies (Scikit-Learn)
# IsolationForest is great for finding 'rare' and 'different' points
model = IsolationForest(contamination=0.05) # We guess ~5% of data is bad
model.fit(df)

# Predict: 1 = Normal, -1 = Anomaly
df['is_anomaly'] = model.predict(df)

# 4. Show the "Findings" (Package Outputs)
anomalies = df[df['is_anomaly'] == -1]
print("--- Potential Beaconing Detected ---")
print(anomalies)
