import { useCallback, useRef, useState } from "react";
import { importKey, decryptData } from "../lib/crypto";
import * as api from "../lib/api";
import { formatSize, parseCode } from "../lib/utils";
import { ProgressBar } from "./ProgressBar";

export function ReceivePanel() {
  const [codeInput, setCodeInput] = useState("");
  const [fileInfo, setFileInfo] = useState<api.FileInfo | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [status, setStatus] = useState("");
  const [percent, setPercent] = useState(0);
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const onCodeChange = useCallback((value: string) => {
    setCodeInput(value);
    setFileInfo(null);
    setError("");
    setSuccess("");

    const { serverCode } = parseCode(value);

    if (!serverCode || serverCode.length < 5) return;

    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(async () => {
      try {
        const info = await api.getFileInfo(serverCode);
        setFileInfo({
          ...info,
          size: info.size,
        });
      } catch {
        setFileInfo(null);
      }
    }, 300);
  }, []);

  const handleDownload = async () => {
    const { serverCode, encKey } = parseCode(codeInput);
    setDownloading(true);
    setError("");
    setSuccess("");
    setStatus("Downloading...");
    setPercent(0);

    try {
      const { data, filename } = await api.downloadFile(serverCode, (p) => {
        const mapped = encKey ? Math.round(p * 0.8) : p;
        setPercent(mapped);
      });

      let finalBlob: Blob;

      if (encKey) {
        setStatus("Decrypting...");
        setPercent(90);
        const key = await importKey(encKey);
        const decrypted = await decryptData(key, data);
        setPercent(100);
        finalBlob = new Blob([decrypted]);
      } else {
        finalBlob = new Blob([data.buffer as ArrayBuffer]);
      }

      const url = URL.createObjectURL(finalBlob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);

      setSuccess(
        `Downloaded ${filename} (${formatSize(finalBlob.size)})${encKey ? " - decrypted" : ""}`
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed");
    }

    setDownloading(false);
  };

  const { encKey } = parseCode(codeInput);

  return (
    <div className="receive-form">
      <div className="input-group">
        <label>Enter transfer code</label>
        <input
          type="text"
          placeholder="e.g. 7-amber-wolf#..."
          value={codeInput}
          onChange={(e) => onCodeChange(e.target.value)}
        />
      </div>

      {fileInfo && (
        <div className="file-preview show">
          <div className="file-preview-icon">&#128196;</div>
          <div className="file-preview-info">
            <div className="file-preview-name">{fileInfo.filename}</div>
            <div className="file-preview-size">
              {formatSize(fileInfo.size)}
              {encKey ? " (encrypted)" : ""}
            </div>
          </div>
        </div>
      )}

      <button
        className="download-btn"
        onClick={handleDownload}
        disabled={!fileInfo || downloading}
      >
        {downloading ? "Downloading..." : "Download & Decrypt"}
      </button>

      {downloading && <ProgressBar status={status} percent={percent} />}

      {success && <div className="status success">{success}</div>}
      {error && <div className="status error">{error}</div>}
    </div>
  );
}
