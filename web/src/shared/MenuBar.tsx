import type { ReactNode } from "react";

export interface MenuBarProps {
  brandTitle?: string;
  onBrandClick: () => void;
  menuItems?: ReactNode;
  statusBadge?: ReactNode;
  controlCenterOpen: boolean;
  onToggleControlCenter: () => void;
  theme: "dark" | "light";
  onToggleTheme: () => void;
  clock: string;
  onClockClick: () => void;
  onAccountClick: () => void;
}

export function MenuBar({
  brandTitle = "AcornFox",
  onBrandClick,
  menuItems,
  statusBadge,
  controlCenterOpen,
  onToggleControlCenter,
  theme,
  onToggleTheme,
  clock,
  onClockClick,
  onAccountClick,
}: MenuBarProps) {
  return (
    <header className="macos-menubar">
      <div className="menubar-left">
        <button
          className="brand-mark-btn"
          onClick={onBrandClick}
          title={brandTitle}
        >
          <div className="openai-spark-icon">
            <svg
              viewBox="0 0 24 24"
              width="18"
              height="18"
              stroke="currentColor"
              strokeWidth="2"
              fill="none"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 2v20M2 12h20M4.93 4.93l14.14 14.14M4.93 19.07l14.14-14.14" />
            </svg>
          </div>
          <span className="brand-title">{brandTitle}</span>
        </button>
        <div className="menubar-items">{menuItems}</div>
      </div>

      <div className="menubar-right">
        {statusBadge}
        <button
          className={`tray-icon-btn ${controlCenterOpen ? "is-active" : ""}`}
          id="btnControlCenter"
          title="控制中心"
          onClick={onToggleControlCenter}
        >
          <svg
            viewBox="0 0 24 24"
            width="16"
            height="16"
            stroke="currentColor"
            strokeWidth="1.8"
            fill="none"
          >
            <line x1="4" y1="21" x2="4" y2="14" />
            <line x1="4" y1="10" x2="4" y2="3" />
            <line x1="12" y1="21" x2="12" y2="12" />
            <line x1="12" y1="8" x2="12" y2="3" />
            <line x1="20" y1="21" x2="20" y2="16" />
            <line x1="20" y1="12" x2="20" y2="3" />
            <line x1="1" y1="14" x2="7" y2="14" />
            <line x1="9" y1="8" x2="15" y2="8" />
            <line x1="17" y1="16" x2="23" y2="16" />
          </svg>
        </button>
        <button
          className="tray-icon-btn"
          id="btnThemeToggle"
          title="切换浅色模式 / 深色模式"
          onClick={onToggleTheme}
        >
          {theme === "dark" ? (
            <svg
              viewBox="0 0 24 24"
              width="16"
              height="16"
              stroke="currentColor"
              strokeWidth="1.8"
              fill="none"
            >
              <circle cx="12" cy="12" r="5" />
              <line x1="12" y1="1" x2="12" y2="3" />
              <line x1="12" y1="21" x2="12" y2="23" />
              <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
              <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
              <line x1="1" y1="12" x2="3" y2="12" />
              <line x1="21" y1="12" x2="23" y2="12" />
              <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
              <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
            </svg>
          ) : (
            <svg
              viewBox="0 0 24 24"
              width="16"
              height="16"
              stroke="currentColor"
              strokeWidth="1.8"
              fill="none"
            >
              <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
            </svg>
          )}
        </button>
        <div
          className="tray-clock-text"
          id="menubarClock"
          onClick={onClockClick}
        >
          {clock}
        </div>
        <div
          className="user-avatar-btn"
          title="管理员账户"
          onClick={onAccountClick}
        >
          管
        </div>
      </div>
    </header>
  );
}
