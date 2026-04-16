import { useEffect, useMemo, useState } from "react";
import { jsPDF } from "jspdf";

const HELLO_API_URL = "/api/hello";
const DETECT_API_URL = "/api/detect";

const initialForm = {
  duration: "",
  src_bytes: "",
  dst_bytes: "",
};

const formatRequestError = (requestError) => {
  const message = requestError?.message || "";

  if (!message) {
    return "Something unexpected happened. Please try again.";
  }

  if (message.toLowerCase().includes("failed to fetch")) {
    return "The backend service is not reachable right now. Please verify it is running and try again.";
  }

  if (message.toLowerCase().includes("network")) {
    return "A network issue interrupted the request. Please retry.";
  }

  if (message.includes("Unexpected token '<'")) {
    return "The frontend received HTML instead of JSON. Confirm the backend is running and local API proxying is enabled.";
  }

  if (message.toLowerCase().includes("not json")) {
    return "The API did not return JSON. Please verify backend routing and try again.";
  }

  return message;
};

const getRowType = (resultText = "") =>
  resultText.toLowerCase().includes("attack") ? "threat" : "safe";

const formatThreatScore = (value) => {
  const numericValue = Number(value);
  return Number.isFinite(numericValue) ? `${numericValue.toFixed(2)}%` : "--";
};

function Dashboard() {
  const [form, setForm] = useState(initialForm);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState("");
  const [backendStatus, setBackendStatus] = useState(
    "Checking backend connectivity..."
  );
  const [isBackendOnline, setIsBackendOnline] = useState(false);
  const [activePage, setActivePage] = useState("dashboard");
  const [threatAlert, setThreatAlert] = useState(null);

  const historyRows = useMemo(() => history.slice().reverse(), [history]);
  const latestThreatScore = result
    ? Math.max(0, Math.min(100, Number(result.threat_score) || 0))
    : 0;
  const latestResultType = result?.prediction === 1 ? "threat" : "safe";

  useEffect(() => {
    const checkBackend = async () => {
      try {
        const response = await fetch(HELLO_API_URL, {
          headers: {
            Accept: "application/json",
          },
        });
        const contentType = response.headers.get("content-type") || "";

        if (!response.ok) {
          throw new Error("Backend hello endpoint is not reachable.");
        }

        if (!contentType.toLowerCase().includes("application/json")) {
          throw new Error("Backend hello response is not JSON.");
        }

        const data = await response.json();
        setBackendStatus(data.message || "Backend connected");
        setIsBackendOnline(true);
      } catch (requestError) {
        setBackendStatus(formatRequestError(requestError));
        setIsBackendOnline(false);
      }
    };

    checkBackend();
  }, []);

  useEffect(() => {
    if (!threatAlert) {
      return undefined;
    }

    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        setThreatAlert(null);
      }
    };

    window.addEventListener("keydown", handleKeyDown);

    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [threatAlert]);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const analyzeTraffic = async () => {
    setError("");

    if (Object.values(form).some((value) => value === "")) {
      setError(
        "Please fill in Duration, Source Bytes, and Destination Bytes before analyzing."
      );
      return;
    }

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

      const data = await response.json().catch(() => ({}));

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
        setThreatAlert({
          threatScore: data.threat_score,
          detectedAt: new Date().toLocaleString(),
        });
      }

      setForm(initialForm);
    } catch (requestError) {
      setError(formatRequestError(requestError));
    } finally {
      setIsLoading(false);
    }
  };

  const downloadPdfReport = () => {
    const doc = new jsPDF();
    const createdAt = new Date();
    const latestThreat = result ? formatThreatScore(result.threat_score) : "--";
    const latestVerdict = result
      ? latestResultType === "threat"
        ? "Suspicious"
        : "Normal"
      : "No recent result";

    let cursorY = 16;

    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.text("ZeroSentinel Security Report", 14, cursorY);

    cursorY += 8;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.text(`Generated: ${createdAt.toLocaleString()}`, 14, cursorY);

    cursorY += 6;
    doc.text(`Backend status: ${isBackendOnline ? "Online" : "Offline"}`, 14, cursorY);

    cursorY += 6;
    doc.text(`Endpoint: ${DETECT_API_URL}`, 14, cursorY);

    cursorY += 8;
    doc.setFont("helvetica", "bold");
    doc.text("Latest Detection", 14, cursorY);

    cursorY += 6;
    doc.setFont("helvetica", "normal");
    doc.text(`Verdict: ${latestVerdict}`, 14, cursorY);

    cursorY += 6;
    doc.text(`Threat score: ${latestThreat}`, 14, cursorY);

    cursorY += 10;
    doc.setFont("helvetica", "bold");
    doc.text("Scan History", 14, cursorY);

    cursorY += 6;

    if (historyRows.length === 0) {
      doc.setFont("helvetica", "normal");
      doc.text("No records yet. Run your first analysis.", 14, cursorY);
    } else {
      doc.setFont("courier", "normal");
      doc.setFontSize(9);
      doc.text("Time | Duration | Src | Dst | Result | Threat%", 14, cursorY);

      cursorY += 5;
      doc.text("-------------------------------------------------------------", 14, cursorY);

      historyRows.forEach((row) => {
        if (cursorY > 278) {
          doc.addPage();
          cursorY = 16;
          doc.setFont("courier", "normal");
          doc.setFontSize(9);
        }

        cursorY += 6;

        const timeText = String(row.timestamp).slice(0, 19);
        const durationText = String(row.duration);
        const srcText = String(row.src_bytes);
        const dstText = String(row.dst_bytes);
        const resultText = getRowType(row.result) === "threat" ? "Suspicious" : "Normal";
        const threatText = formatThreatScore(row.threat_score);

        const line = `${timeText} | ${durationText} | ${srcText} | ${dstText} | ${resultText} | ${threatText}`;
        doc.text(line, 14, cursorY);
      });
    }

    const fileStamp = createdAt
      .toISOString()
      .replace(/[:.]/g, "-")
      .slice(0, 19);

    const fileName = `zero-sentinel-report-${fileStamp}.pdf`;
    const pdfBlob = doc.output("blob");
    const blobUrl = URL.createObjectURL(pdfBlob);

    const previewWindow = window.open(blobUrl, "_blank", "noopener,noreferrer");
    if (previewWindow && typeof previewWindow.focus === "function") {
      previewWindow.focus();
    }

    const downloadLink = document.createElement("a");
    downloadLink.href = blobUrl;
    downloadLink.download = fileName;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);

    window.setTimeout(() => {
      URL.revokeObjectURL(blobUrl);
    }, 120000);
  };

  const closeThreatAlert = () => {
    setThreatAlert(null);
  };

  return (
    <div className="page-root">
      <header className="site-header">
        <div className="header-brand">
          <div className="brand-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" focusable="false">
              <path
                d="m12 2.2 8 3.2V11c0 4.6-2.9 8.8-7.3 10.5L12 21.8l-.7-.3C6.9 19.8 4 15.6 4 11V5.4l8-3.2Zm0 2.2L6 6.9V11c0 3.7 2.3 7.1 5.8 8.6l.2.1.2-.1C15.7 18.1 18 14.7 18 11V6.9l-6-2.5Z"
                fill="currentColor"
              />
            </svg>
          </div>
          <p className="brand-name">ZeroSentinel</p>
        </div>

        <nav className="header-nav" aria-label="Primary navigation">
          <button
            className={`nav-item ${activePage === "dashboard" ? "active" : ""}`}
            type="button"
            onClick={() => setActivePage("dashboard")}
          >
            Dashboard
          </button>
          <button
            className={`nav-item ${activePage === "reports" ? "active" : ""}`}
            type="button"
            onClick={() => setActivePage("reports")}
          >
            Reports
          </button>
        </nav>

        <div className={`header-status ${isBackendOnline ? "online" : "offline"}`}>
          <span className="status-dot" aria-hidden="true" />
          {isBackendOnline ? "System Online" : "System Offline"}
        </div>
      </header>

      <div className="mobile-nav" aria-label="Mobile navigation">
        <button
          className={`mobile-tab ${activePage === "dashboard" ? "active" : ""}`}
          type="button"
          onClick={() => setActivePage("dashboard")}
        >
          Dashboard
        </button>
        <button
          className={`mobile-tab ${activePage === "reports" ? "active" : ""}`}
          type="button"
          onClick={() => setActivePage("reports")}
        >
          Reports
        </button>
      </div>

      <main className="main-content">
        <section className="hero-block">
          <div className="hero-text">
            <p className="hero-eyebrow">CLOUD SECURITY MONITORING</p>
            <h1 className="hero-title">
              Cloud-Based Zero-Day Attack Detection System
            </h1>
            <p className="hero-sub">
              Submit traffic metrics and instantly classify the activity as normal
              or suspicious.
            </p>
            <div className="hero-tags">
              <span className="hero-tag subtle-tag">Endpoint {DETECT_API_URL}</span>
              <span
                className={`hero-tag ${isBackendOnline ? "online-tag" : "offline-tag"}`}
              >
                <span className={`tag-dot ${isBackendOnline ? "green" : ""}`} />
                {isBackendOnline ? "Backend Online" : "Backend Offline"}
              </span>
              <span className="hero-tag">
                <span className="tag-dot green" />
                Live Indicator
              </span>
            </div>
          </div>

          <div className="hero-stats" aria-label="System metrics">
            <div className="hero-stat">
              <div
                className={`hs-value ${
                  result && latestResultType === "threat" ? "threat" : ""
                }`}
              >
                {result ? `${latestThreatScore.toFixed(1)}%` : "--"}
              </div>
              <p className="hs-label">Threat Score</p>
            </div>
            <span className="hero-stat-divider" aria-hidden="true" />
            <div className="hero-stat">
              <div className="hs-value">{historyRows.length}</div>
              <p className="hs-label">Total Scans</p>
            </div>
          </div>
        </section>

        {activePage === "dashboard" ? (
          <section className="analyzer-card" aria-label="Traffic analyzer">
          <div className="analyzer-header">
            <div>
              <h2 className="section-title">Traffic Analyzer</h2>
              <p className="section-sub">
                Enter network traffic metrics to classify activity in real time.
              </p>
            </div>
            <div
              className={`status-badge ${isBackendOnline ? "online" : "offline"}`}
            >
              <span className="badge-dot" aria-hidden="true" />
              {isBackendOnline ? "Backend Online" : "Backend Offline"}
            </div>
          </div>

          <p className="meta-line">
            API endpoint <span>{DETECT_API_URL}</span>
          </p>
          <p className="meta-line">{backendStatus}</p>

          {error && (
            <div className="error-banner" role="alert" aria-live="polite">
              <span className="error-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" focusable="false">
                  <path
                    d="M12 2 1 21h22L12 2Zm0 6c.5 0 .9.4.9.9v5.2a.9.9 0 0 1-1.8 0V8.9c0-.5.4-.9.9-.9Zm0 10a1.1 1.1 0 1 1 0-2.2 1.1 1.1 0 0 1 0 2.2Z"
                    fill="currentColor"
                  />
                </svg>
              </span>
              <div>
                <p className="error-title">Unable to analyze this request.</p>
                <p className="error-copy">{error}</p>
              </div>
            </div>
          )}

          <div className="form-row">
            <div className="field">
              <label className="field-label" htmlFor="duration">
                Duration
              </label>
              <input
                className="field-input"
                id="duration"
                type="number"
                name="duration"
                value={form.duration}
                onChange={handleChange}
                placeholder="Ex: 12"
              />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="src_bytes">
                Source Bytes
              </label>
              <input
                className="field-input"
                id="src_bytes"
                type="number"
                name="src_bytes"
                value={form.src_bytes}
                onChange={handleChange}
                placeholder="Ex: 6000"
              />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="dst_bytes">
                Destination Bytes
              </label>
              <input
                className="field-input"
                id="dst_bytes"
                type="number"
                name="dst_bytes"
                value={form.dst_bytes}
                onChange={handleChange}
                placeholder="Ex: 350"
              />
            </div>
          </div>

          <button
            className="analyze-btn"
            type="button"
            onClick={analyzeTraffic}
            disabled={isLoading}
            aria-busy={isLoading}
          >
            {isLoading && <span className="btn-spinner" aria-hidden="true" />}
            <span>{isLoading ? "Analyzing Traffic..." : "Analyze Traffic"}</span>
          </button>

          {result && (
            <div
              className={`result-card ${latestResultType}`}
              role="status"
              aria-live="polite"
            >
              <div className="result-left">
                <span className="result-icon-wrap" aria-hidden="true">
                  {latestResultType === "threat" ? (
                    <svg viewBox="0 0 24 24" focusable="false">
                      <path
                        d="M7.1 5.7 12 10.6l4.9-4.9 1.4 1.4-4.9 4.9 4.9 4.9-1.4 1.4-4.9-4.9-4.9 4.9-1.4-1.4 4.9-4.9-4.9-4.9 1.4-1.4Z"
                        fill="currentColor"
                      />
                    </svg>
                  ) : (
                    <svg viewBox="0 0 24 24" focusable="false">
                      <path
                        d="m10.2 16.6-4.4-4.4 1.4-1.4 3 3 6.6-6.6 1.4 1.4-8 8Z"
                        fill="currentColor"
                      />
                    </svg>
                  )}
                </span>
                <div>
                  <p className="result-verdict">
                    {latestResultType === "threat" ? "Suspicious" : "Normal"}
                  </p>
                  <p className="result-score-label">
                    Threat score {formatThreatScore(result.threat_score)}
                  </p>
                </div>
              </div>
              <div className="result-bar-bg" aria-hidden="true">
                <div
                  className={`result-bar-fill ${latestResultType}`}
                  style={{ width: `${latestThreatScore}%` }}
                />
              </div>
            </div>
          )}

          <section className="history-section" aria-label="Analysis history">
            <div className="history-header">
              <h3 className="section-title">History</h3>
            </div>

            {historyRows.length === 0 ? (
              <div className="empty-state" role="status" aria-live="polite">
                <span className="empty-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" focusable="false">
                    <path
                      d="m12 2.2 8 3.2V11c0 4.6-2.9 8.8-7.3 10.5L12 21.8l-.7-.3C6.9 19.8 4 15.6 4 11V5.4l8-3.2Zm0 2.2L6 6.9V11c0 3.7 2.3 7.1 5.8 8.6l.2.1.2-.1C15.7 18.1 18 14.7 18 11V6.9l-6-2.5Z"
                      fill="currentColor"
                    />
                  </svg>
                </span>
                <p className="empty-title">No records yet. Run your first analysis.</p>
                <p className="empty-sub">Your recent scan activity appears here.</p>
              </div>
            ) : (
              <div className="table-scroll">
                <table>
                  <caption className="sr-only">Traffic analysis history table</caption>
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
                    {historyRows.map((row, index) => {
                      const rowType = getRowType(row.result);
                      const scoreClass = rowType === "threat" ? "score-threat" : "score-safe";

                      return (
                        <tr key={`${row.timestamp}-${index}`}>
                          <td className="td-time">{row.timestamp}</td>
                          <td>{row.duration}</td>
                          <td>{row.src_bytes}</td>
                          <td>{row.dst_bytes}</td>
                          <td>
                            <span className={`result-pill ${rowType}`}>
                              {rowType === "threat" ? "Suspicious" : "Normal"}
                            </span>
                          </td>
                          <td className={scoreClass}>{formatThreatScore(row.threat_score)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </section>
        ) : (
          <section className="reports-card" aria-label="Reports">
            <div className="reports-header">
              <div>
                <h2 className="section-title">Reports</h2>
                <p className="section-sub">
                  Generate and download a PDF summary of detections and scan history.
                </p>
              </div>
              <button className="download-btn" type="button" onClick={downloadPdfReport}>
                Download PDF Report
              </button>
            </div>

            <div className="reports-grid">
              <article className="report-metric">
                <p className="report-label">Total Scans</p>
                <p className="report-value">{historyRows.length}</p>
              </article>

              <article className="report-metric">
                <p className="report-label">Latest Verdict</p>
                <p className="report-value">
                  {result ? (latestResultType === "threat" ? "Suspicious" : "Normal") : "--"}
                </p>
              </article>

              <article className="report-metric">
                <p className="report-label">Latest Threat %</p>
                <p
                  className={`report-value ${
                    result && latestResultType === "threat" ? "threat-value" : "safe-value"
                  }`}
                >
                  {result ? formatThreatScore(result.threat_score) : "--"}
                </p>
              </article>
            </div>

            <p className="report-note">
              The exported report includes endpoint status, latest detection result, and full scan history.
            </p>
          </section>
        )}
      </main>

      {threatAlert && (
        <div className="threat-popup-overlay" role="presentation" onClick={closeThreatAlert}>
          <section
            className="threat-popup"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="threat-alert-title"
            aria-describedby="threat-alert-copy"
            onClick={(event) => event.stopPropagation()}
          >
            <span className="threat-popup-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" focusable="false">
                <path
                  d="M12 2 1 21h22L12 2Zm0 6c.5 0 .9.4.9.9v5.2a.9.9 0 0 1-1.8 0V8.9c0-.5.4-.9.9-.9Zm0 10a1.1 1.1 0 1 1 0-2.2 1.1 1.1 0 0 1 0 2.2Z"
                  fill="currentColor"
                />
              </svg>
            </span>

            <div className="threat-popup-body">
              <p className="threat-popup-kicker">Priority Security Alert</p>
              <h2 className="threat-popup-title" id="threat-alert-title">
                Potential zero-day activity detected
              </h2>
              <p className="threat-popup-copy" id="threat-alert-copy">
                Threat score {formatThreatScore(threatAlert.threatScore)} at {threatAlert.detectedAt}.
                Review this detection in the dashboard history and continue monitoring traffic.
              </p>

              <div className="threat-popup-actions">
                <button className="threat-popup-btn" type="button" onClick={closeThreatAlert}>
                  Acknowledge Alert
                </button>
              </div>
            </div>
          </section>
        </div>
      )}

      <footer className="site-footer">
        <span>ZeroSentinel</span>
        <span>Cloud-native threat detection and response telemetry.</span>
      </footer>
    </div>
  );
}

export default Dashboard;
