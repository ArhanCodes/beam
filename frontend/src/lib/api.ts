export interface UploadResponse {
  code: string;
  filename: string;
  size: number;
}

export interface FileInfo {
  filename: string;
  size: number;
}

export async function uploadFile(
  encryptedBlob: Blob,
  filename: string,
  onProgress: (percent: number) => void
): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append("file", encryptedBlob, filename);

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();

    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) {
        onProgress(Math.round((e.loaded / e.total) * 100));
      }
    });

    xhr.onload = () => {
      if (xhr.status === 200) {
        resolve(JSON.parse(xhr.responseText));
      } else {
        try {
          const err = JSON.parse(xhr.responseText);
          reject(new Error(err.error || "Upload failed"));
        } catch {
          reject(new Error("Upload failed"));
        }
      }
    };

    xhr.onerror = () => reject(new Error("Network error"));
    xhr.open("POST", "/api/upload");
    xhr.send(formData);
  });
}

export async function getFileInfo(code: string): Promise<FileInfo> {
  const res = await fetch(`/api/info/${encodeURIComponent(code)}`);
  if (!res.ok) throw new Error("Transfer not found");
  return res.json();
}

export async function downloadFile(
  code: string,
  onProgress: (percent: number) => void
): Promise<{ data: Uint8Array; filename: string }> {
  const res = await fetch(`/api/download/${encodeURIComponent(code)}`);
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Download failed");
  }

  const contentLength = res.headers.get("content-length");
  const total = contentLength ? parseInt(contentLength) : 0;
  const reader = res.body!.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    if (total > 0) {
      onProgress(Math.round((received / total) * 100));
    }
  }

  const data = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.length;
  }

  let filename = "download";
  const disposition = res.headers.get("content-disposition");
  if (disposition) {
    const match = disposition.match(/filename="(.+)"/);
    if (match) filename = match[1];
  }

  return { data, filename };
}
