import Dashboard from "./Dashboard";

function App() {
  return (
    <main className="app-shell">
      <header className="hero">
        <p className="kicker">Cloud Security Monitoring</p>
        <h1>Cloud-Based Zero-Day Attack Detection System</h1>
        <p>
          Submit traffic metrics and instantly classify the activity as normal or
          suspicious.
        </p>
      </header>
      <Dashboard />
    </main>
  );
}

export default App;
