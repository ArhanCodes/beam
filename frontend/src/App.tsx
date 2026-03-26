import { useState } from "react";
import { SendPanel } from "./components/SendPanel";
import { ReceivePanel } from "./components/ReceivePanel";
import "./App.css";

type Tab = "send" | "receive";

export default function App() {
  const [tab, setTab] = useState<Tab>("send");

  return (
    <>
      <div className="header">
        <h1>
          <span>beam</span>
        </h1>
        <p>instant file transfer</p>
      </div>

      <div className="badges">
        <div className="badge">
          <div className="badge-dot" />
          End-to-end encrypted
        </div>
        <div className="badge">
          <div className="badge-dot" />
          No file size limit
        </div>
        <div className="badge">
          <div className="badge-dot" />
          No account needed
        </div>
      </div>

      <div className="container">
        <div className="tabs">
          <button
            className={`tab ${tab === "send" ? "active" : ""}`}
            onClick={() => setTab("send")}
          >
            Send
          </button>
          <button
            className={`tab ${tab === "receive" ? "active" : ""}`}
            onClick={() => setTab("receive")}
          >
            Receive
          </button>
        </div>

        {tab === "send" && <SendPanel />}
        {tab === "receive" && <ReceivePanel />}
      </div>

      <div className="footer">
        beam &mdash; end-to-end encrypted file transfer built with Rust
      </div>
    </>
  );
}
