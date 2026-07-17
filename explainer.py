import joblib
import numpy as np
from feature_extractor import extract_features

# Global configuration for feature mapping
FEATURE_NAMES = [
    "URL Length",
    "Subdomain Count",
    "Brand Spoofing (Hyphens)",
    "HTTPS Encryption Status",
    "IP Address Obfuscation",
    "Credential Harvesting (@ Symbol)",
    "Domain Length",
    "Social Engineering Keywords"
]

class ThreatExplainer:
    def __init__(self, model_path: str = "url_model.pkl"):
        """Initializes the explainer and loads the trained AI model."""
        try:
            self.model = joblib.load(model_path)
        except Exception as e:
            print(f"[!] Warning: Could not load model for explainability. {e}")
            self.model = None

    def analyze_weights(self, url: str) -> list:
        """Returns the top contributing features for a given URL's classification."""
        if self.model is None:
            return ["Explainability unavailable: Model not loaded."]

        try:
            # Extract features and format for the model
            raw_features = extract_features(url)
            features = np.array(raw_features).reshape(1, -1)

            # Get model weights (feature importances)
            importances = self.model.feature_importances_

            # Map weights to human-readable feature names and sort them
            explanation = list(zip(FEATURE_NAMES, importances))
            explanation.sort(key=lambda x: x[1], reverse=True)

            # Format the top 4 findings for the report
            results = []
            for name, weight in explanation[:4]:
                if weight > 0:  # Only report features that actually influenced the decision
                    results.append(f"{name} (Impact: {round(weight * 100, 1)}%)")

            return results

        except Exception as e:
            return [f"Explainability processing error: {str(e)}"]