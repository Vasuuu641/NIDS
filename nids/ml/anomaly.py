import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
from scapy.all import PcapReader
from nids.ml.features import extract_features


# --- Model state ---
_model = IsolationForest(
    n_estimators=100,
    contamination=0.01,  # expect ~1% anomalies in training data
    random_state=42
)
_trained = False


def extract_feature_matrix(pcap_path: str, max_packets: int = 100000, skip: int = 0) -> np.ndarray:
    """
    Read packets from a PCAP file and extract feature vectors.
    Returns a numpy array of shape (n_samples, 4).
    """
    vectors = []
    count = 0
    processed = 0

    print(f"Extracting features from {pcap_path} (skip={skip}, max={max_packets})...")

    with PcapReader(pcap_path) as reader:
        for packet in reader:
            count += 1
            if count <= skip:
                continue
            if processed >= max_packets:
                break

            now = datetime.fromtimestamp(float(packet.time))
            features = extract_features(packet, now=now)

            if features is not None:
                vectors.append(features)
                processed += 1

            if processed % 10000 == 0 and processed > 0:
                print(f"  Processed {processed} packets...")

    print(f"  Done — {len(vectors)} feature vectors extracted")
    return np.array(vectors)


def train(pcap_path: str, skip: int = 3000000, max_packets: int = 100000) -> None:
    """
    Train the Isolation Forest on normal traffic.
    Default skip=3000000 jumps past the DDoS portion of the Friday PCAP.
    """
    global _trained

    X_train = extract_feature_matrix(pcap_path, max_packets=max_packets, skip=skip)

    if len(X_train) == 0:
        print("No features extracted — check PCAP file and filter settings")
        return

    print(f"Training Isolation Forest on {len(X_train)} samples...")
    _model.fit(X_train)
    _trained = True
    print("Training complete")


def predict(features: list) -> str:
    """
    Given a feature vector, return 'anomaly' or 'normal'.
    """
    if not _trained:
        raise RuntimeError("Model not trained — call train() first")

    X = np.array(features).reshape(1, -1)
    result = _model.predict(X)
    return "anomaly" if result[0] == -1 else "normal"


def evaluate(pcap_path: str, max_packets: int = 100000, skip: int = 0) -> dict:
    """
    Run the trained model against a PCAP and return detection stats.
    """
    if not _trained:
        raise RuntimeError("Model not trained — call train() first")

    X = extract_feature_matrix(pcap_path, max_packets=max_packets, skip=skip)

    if len(X) == 0:
        print("No features extracted")
        return {}

    predictions = _model.predict(X)
    anomalies = int(np.sum(predictions == -1))
    normal = int(np.sum(predictions == 1))

    result = {
        "total_samples": len(X),
        "anomalies": anomalies,
        "normal": normal,
        "anomaly_rate": round(anomalies / len(X) * 100, 2)
    }

    print(f"\n--- Evaluation Results ---")
    print(f"Total samples : {result['total_samples']}")
    print(f"Anomalies     : {result['anomalies']}")
    print(f"Normal        : {result['normal']}")
    print(f"Anomaly rate  : {result['anomaly_rate']}%")

    return result