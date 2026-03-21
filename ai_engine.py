import collections
try:
    from sklearn.linear_model import LinearRegression
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
from logger import logger
from config import AI_WINDOW_SIZE

class BWAIEngine:
    def __init__(self):
        self.window_size = AI_WINDOW_SIZE
        self.history = collections.defaultdict(lambda: collections.deque(maxlen=self.window_size))
        self.models = {}  # Store ML models per IP

    def add_data_point(self, ip, value):
        self.history[ip].append(value)
        # Retrain model when enough data
        if ML_AVAILABLE and len(self.history[ip]) >= 5:
            self._train_model(ip)

    def _train_model(self, ip):
        if not ML_AVAILABLE:
            return
        data = list(self.history[ip])
        if len(data) < 5:
            return
        # Use time steps as features
        X = np.array(range(len(data))).reshape(-1, 1)
        y = np.array(data)
        model = LinearRegression()
        model.fit(X, y)
        self.models[ip] = model

    def predict_next(self, ip):
        """
        Predicts the next bandwidth value using ML regression or fallback.
        """
        data = list(self.history[ip])
        if not data:
            return 0.0
        
        if ML_AVAILABLE and ip in self.models:
            # Predict next value
            next_x = np.array([[len(data)]])
            prediction = self.models[ip].predict(next_x)[0]
            return max(0.1, round(prediction, 2))
        
        # Fallback to trend
        if len(data) >= 2:
            current = data[-1]
            previous = data[-2]
            user_prediction = current + (current - previous)
            return max(0.1, round(user_prediction, 2))
            
        # SMA
        sma = sum(data) / len(data)
        return round(max(0.1, sma), 2)

    def detect_anomaly(self, ip, current_value):
        """Detects if current usage is anomalous."""
        if not ML_AVAILABLE:
            return False
        data = list(self.history[ip])
        if len(data) < 5:
            return False
        mean = np.mean(data)
        std = np.std(data)
        if std == 0:
            return abs(current_value - mean) > 10  # Arbitrary threshold
        z_score = abs(current_value - mean) / std
        return z_score > 2.5  # Anomaly if > 2.5 std devs

    def get_network_health(self, users):
        """Calculates a health score from 0-100."""
        if not users:
            return 100
        
        # Health decreases as usage approaches limits
        total_stress = 0
        anomalies = 0
        for u in users:
            if u['limit'] > 0:
                stress = (u['usage'] / u['limit'])
                total_stress += min(1.0, stress)
            if ML_AVAILABLE and self.detect_anomaly(u['ip'], u['usage']):
                anomalies += 1
        
        avg_stress = total_stress / len(users)
        anomaly_penalty = (anomalies / len(users)) * 20  # Reduce health by up to 20 for anomalies
        health_score = max(0, int(100 - (avg_stress * 100) - anomaly_penalty))
        return health_score

ai_engine = BWAIEngine()
