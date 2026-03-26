interface ProgressBarProps {
  status: string;
  percent: number;
}

export function ProgressBar({ status, percent }: ProgressBarProps) {
  return (
    <div className="progress-container">
      <div className="progress-bar-bg">
        <div
          className="progress-bar-fill"
          style={{ width: `${percent}%` }}
        />
      </div>
      <div className="progress-text">
        <span>{status}</span>
        <span>{percent}%</span>
      </div>
    </div>
  );
}
