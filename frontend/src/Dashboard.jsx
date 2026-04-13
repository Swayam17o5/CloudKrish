import { useMemo, useState } from "react";

const DETECT_API_URL =
  process.env.REACT_APP_DETECT_URL || "http://<EC2-IP>:5000/detect";

const initialForm = {
  duration: "",
  src_bytes: "",
  dst_bytes: "",
};

function Dashboard() {
  const [form, setForm] = useState(initialForm);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState("");

  const historyRows = useMemo(() => history.slice().reverse(), [history]);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const analyzeTraffic = async () => {
    setError("");

    const payload = {
      duration: Number(form.duration),
      src_bytes: Number(form.src_bytes),
      dst_bytes: Number(form.dst_bytes),
    };

    if (Object.values(payload).some((value) => Number.isNaN(value))) {
      setError("Please enter valid numeric values in all fields.");
      return;
    }

    setIsLoading(true);

    try {
      const response = await fetch(DETECT_API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to analyze traffic.");
      }

      setResult(data);
      setHistory((prev) => [
        ...prev,
        {
          ...payload,
          result: data.result,
          threat_score: data.threat_score,
          timestamp: new Date().toLocaleString(),
        },
      ]);

      if (data.prediction === 1) {
        window.alert("Alert: Potential zero-day attack detected.");
      }

      setForm(initialForm);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <section className="dashboard-card">
      <h2>Traffic Analyzer</h2>
      <p className="subtle">
        API endpoint: <span>{DETECT_API_URL}</span>
      </p>

      <div className="form-grid">
        <label>
          Duration
          <input
            type="number"
            name="duration"
            value={form.duration}
            onChange={handleChange}
            placeholder="Ex: 12"
          />
        </label>

        <label>
          Source Bytes
          <input
            type="number"
            name="src_bytes"
            value={form.src_bytes}
            onChange={handleChange}
            placeholder="Ex: 6000"
          />
        </label>

        <label>
          Destination Bytes
          <input
            type="number"
            name="dst_bytes"
            value={form.dst_bytes}
            onChange={handleChange}
            placeholder="Ex: 350"
          />
        </label>
      </div>

      <button type="button" onClick={analyzeTraffic} disabled={isLoading}>
        {isLoading ? "Analyzing..." : "Analyze Traffic"}
      </button>

      {error && <p className="error-message">{error}</p>}

      {result && (
        <div className="result-panel">
          <h3>Latest Result</h3>
          <p>
            <strong>Prediction:</strong> {result.result}
          </p>
          <p>
            <strong>Threat Score:</strong> {result.threat_score}%
          </p>
        </div>
      )}

      <h3>History</h3>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Duration</th>
              <th>Src Bytes</th>
              <th>Dst Bytes</th>
              <th>Result</th>
              <th>Threat %</th>
            </tr>
          </thead>
          <tbody>
            {historyRows.length === 0 ? (
              <tr>
                <td colSpan="6">No records yet. Run your first analysis.</td>
              </tr>
            ) : (
              historyRows.map((row, index) => (
                <tr key={`${row.timestamp}-${index}`}>
                  <td>{row.timestamp}</td>
                  <td>{row.duration}</td>
                  <td>{row.src_bytes}</td>
                  <td>{row.dst_bytes}</td>
                  <td>{row.result}</td>
                  <td>{row.threat_score}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default Dashboard;
