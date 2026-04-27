import { useCallback, useRef, useState } from "react";
import { generateKey, exportKey, encryptData } from "../lib/crypto";
import { uploadFile } from "../lib/api";
import { formatSize } from "../lib/utils";
import { ProgressBar } from "./ProgressBar";

type SendState = "idle" | "uploading" | "done";

export function SendPanel() {
  const [state, setState] = useState<SendState>("idle");
  const [dragover, setDragover] = useState(false);
  const [status, setStatus] = useState("");
  const [percent, setPercent] = useState(0);
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("");
  const [fileSize, setFileSize] = useState(0);
  const [error, setError] = useState("");
  const [copyText, setCopyText] = useState("Copy code");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(async (file: File) => {
    setState("uploading");
    setError("");
    setFilename(file.name);
    setFileSize(file.size);

    try {
      setStatus("Generating encryption key...");
      setPercent(0);
      const key = await generateKey();
      const keyStr = await exportKey(key);

      setStatus("Reading file...");
      setPercent(10);
      const arrayBuffer = await file.arrayBuffer();

      setStatus("Encrypting...");
      setPercent(30);
      const encrypted = await encryptData(key, arrayBuffer);

      setStatus("Uploading encrypted file...");
      const encryptedBlob = new Blob([encrypted.buffer as ArrayBuffer], {
        type: "application/octet-stream",
      });

      const result = await uploadFile(encryptedBlob, file.name, (p) => {
        const mapped = 30 + Math.round(p * 0.7);
        setPercent(mapped);
        setStatus(mapped < 100 ? "Uploading encrypted file..." : "Finalizing...");
      });

      const fullCode = result.code + "#" + keyStr;
      setCode(fullCode);
      setState("done");
    } catch (err) {
      setState("idle");
      setError(err instanceof Error ? err.message : "Upload failed");
    }
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragover(false);
      if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]);
    },
    [handleFile]
  );

  const copyCode = () => {
    navigator.clipboard.writeText(code);
    setCopyText("Copied!");
    setTimeout(() => setCopyText("Copy code"), 2000);
  };

  const reset = () => {
    setState("idle");
    setCode("");
    setError("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  return (
    <>
      {state === "idle" && (
        <div
          className={`dropzone ${dragover ? "dragover" : ""}`}
          onClick={() => fileInputRef.current?.click()}
          onDragEnter={(e) => {
            e.preventDefault();
            setDragover(true);
          }}
          onDragOver={(e) => {
            e.preventDefault();
            setDragover(true);
          }}
          onDragLeave={(e) => {
            e.preventDefault();
            setDragover(false);
          }}
          onDrop={handleDrop}
        >
          <div className="dropzone-icon">&#8593;</div>
          <div className="dropzone-text">Drop a file here or click to browse</div>
          <div className="dropzone-hint">
            Any file, any size - encrypted before upload
          </div>
        </div>
      )}

      <input
        type="file"
        ref={fileInputRef}
        className="file-input"
        onChange={(e) => {
          if (e.target.files?.[0]) handleFile(e.target.files[0]);
        }}
      />

      {state === "uploading" && <ProgressBar status={status} percent={percent} />}

      {state === "done" && (
        <div className="code-card">
          <div className="code-label">Share this code with the receiver</div>
          <div className="code-value">{code}</div>
          <div className="code-filename">
            {filename} ({formatSize(fileSize)})
          </div>
          <div className="encryption-note">
            AES-256-GCM encrypted - key is embedded in the code above
          </div>
          <button className="copy-btn" onClick={copyCode}>
            {copyText}
          </button>
          <br />
          <button className="reset-btn" onClick={reset}>
            Send another file
          </button>
        </div>
      )}

      {error && <div className="status error">{error}</div>}
    </>
  );
}
