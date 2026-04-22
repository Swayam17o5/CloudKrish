import os
import pickle

import pandas as pd
from sklearn.ensemble import RandomForestClassifier


def build_training_data():
    data = [
        {"duration": 2, "src_bytes": 120, "dst_bytes": 80, "label": 0},
        {"duration": 5, "src_bytes": 300, "dst_bytes": 260, "label": 0},
        {"duration": 3, "src_bytes": 150, "dst_bytes": 120, "label": 0},
        {"duration": 8, "src_bytes": 450, "dst_bytes": 430, "label": 0},
        {"duration": 4, "src_bytes": 200, "dst_bytes": 180, "label": 0},
        {"duration": 12, "src_bytes": 9500, "dst_bytes": 220, "label": 1},
        {"duration": 18, "src_bytes": 12000, "dst_bytes": 260, "label": 1},
        {"duration": 20, "src_bytes": 15000, "dst_bytes": 500, "label": 1},
        {"duration": 11, "src_bytes": 8700, "dst_bytes": 300, "label": 1},
        {"duration": 25, "src_bytes": 18000, "dst_bytes": 600, "label": 1},
    ]
    return pd.DataFrame(data)


def train_and_save_model():
    df = build_training_data()
    features = ["duration", "src_bytes", "dst_bytes"]

    x_train = df[features]
    y_train = df["label"]

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(x_train, y_train)

    model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
    with open(model_path, "wb") as model_file:
        pickle.dump(model, model_file)

    print(f"Model trained and saved to {model_path}")


if __name__ == "__main__":
    train_and_save_model()
