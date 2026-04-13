from datetime import datetime, timezone
from uuid import uuid4
import json
import os
import pickle

from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "zero-day-logs")
ENABLE_S3_LOGGING = os.getenv("ENABLE_S3_LOGGING", "false").lower() == "true"

app = Flask(__name__)
CORS(app)

with open(MODEL_PATH, "rb") as model_file:
    model = pickle.load(model_file)

s3_client = None
if ENABLE_S3_LOGGING:
    try:
        import boto3

        s3_client = boto3.client("s3")
    except Exception as exc:
        print(f"Failed to initialize S3 client: {exc}")


def log_request_to_s3(payload):
    if not ENABLE_S3_LOGGING or s3_client is None:
        return

    timestamp = datetime.now(timezone.utc)
    key = (
        f"traffic-logs/{timestamp.strftime('%Y/%m/%d')}/"
        f"{timestamp.strftime('%H%M%S')}_{uuid4().hex}.json"
    )

    try:
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=key,
            Body=json.dumps(payload).encode("utf-8"),
            ContentType="application/json",
        )
    except Exception as exc:
        print(f"S3 logging error: {exc}")


@app.route("/", methods=["GET"])
def health_check():
    return "Backend is running"


@app.route("/detect", methods=["POST"])
def detect_attack():
    data = request.get_json(silent=True) or {}
    required_fields = ["duration", "src_bytes", "dst_bytes"]
    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        return jsonify({"error": f"Missing fields: {', '.join(missing_fields)}"}), 400

    try:
        duration = float(data["duration"])
        src_bytes = float(data["src_bytes"])
        dst_bytes = float(data["dst_bytes"])
    except (TypeError, ValueError):
        return jsonify({"error": "All fields must be numeric values."}), 400

    features = pd.DataFrame(
        [[duration, src_bytes, dst_bytes]],
        columns=["duration", "src_bytes", "dst_bytes"],
    )
    prediction = int(model.predict(features)[0])

    if hasattr(model, "predict_proba"):
        threat_score = round(float(model.predict_proba(features)[0][1]) * 100, 2)
    else:
        threat_score = 100.0 if prediction == 1 else 0.0

    result_text = "Attack 🚨" if prediction == 1 else "Normal ✅"

    response_payload = {
        "prediction": prediction,
        "result": result_text,
        "threat_score": threat_score,
    }

    log_request_to_s3(
        {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "request": {
                "duration": duration,
                "src_bytes": src_bytes,
                "dst_bytes": dst_bytes,
            },
            "response": response_payload,
        }
    )

    return jsonify(response_payload)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
