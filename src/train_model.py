# src/train_model.py

"""
Optional: train a sklearn model if you have a features CSV.
This expects a CSV with columns matching features returned by extract_simple_features
and a 'label' column with values 'spoof' or 'legit'.

Example usage (after you prepare features.csv):
    python -m src.train_model
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

def train(path_csv="data/features.csv", out_model="models/rf_spoof.pkl"):
    
    df = pd.read_csv(path_csv)
    if "label" not in df.columns:
        raise ValueError("CSV must contain a 'label' column")
    X = df.drop(columns=["label"])
    y = (df["label"] == "spoof").astype(int)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    print(classification_report(y_test, preds))
    joblib.dump(clf, out_model)
    print(f"Saved model to {out_model}")

if __name__ == "__main__":
    train()
