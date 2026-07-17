import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
from feature_extractor import extract_features

def train_phishing_model(dataset_path: str = "dataset.csv", output_model: str = "url_model.pkl"):
    """Trains a Random Forest classifier on URL features to detect phishing."""
    print("[*] Initializing model training pipeline...")
    
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"[!] Error: Could not find training data at {dataset_path}")
        return

    # Clean and map labels
    df["label"] = df["label"].map({"benign": 0, "phishing": 1})
    df = df.dropna()

    print(f"[*] Processing {len(df)} records...")
    
    # Feature extraction loop
    X, y = [], []
    for _, row in df.iterrows():
        X.append(extract_features(row["URL"]))
        y.append(row["label"])

    X = np.array(X)
    y = np.array(y)

    # 80/20 Train-Test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Initialize and train the Random Forest
    print("[*] Training Random Forest Classifier (200 estimators)...")
    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print("\n" + "="*30)
    print(f"🔥 Model Accuracy: {accuracy*100:.2f}%")
    print("="*30)
    print("\nDetailed Forensic Metrics:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Phishing"]))

    # Serialize and save the trained model
    joblib.dump(model, output_model)
    print(f"[+] Model successfully saved to {output_model}")

if __name__ == "__main__":
    train_phishing_model()