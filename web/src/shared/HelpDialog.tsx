import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import "../acornfox/ExternalAIHelp.css";

export interface HelpDialogProps {
  open: boolean;
  title: string;
  notice: ReactNode;
  fallbackText?: string | null;
  children: ReactNode;
  onClose: () => void;
}

export function useClipboardCopy(onToast?: (message: string) => void) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [fallbackText, setFallbackText] = useState<string | null>(null);
  const copyEpochRef = useRef(0);
  const copyTimerRef = useRef<number | null>(null);

  const copy = async (text: string, key: string, label: string) => {
    const epoch = ++copyEpochRef.current;
    let success = false;
    if (
      typeof navigator !== "undefined" &&
      navigator.clipboard &&
      typeof navigator.clipboard.writeText === "function"
    ) {
      try {
        await navigator.clipboard.writeText(text);
        success = true;
      } catch {
        success = false;
      }
    }

    if (epoch !== copyEpochRef.current) return;

    if (success) {
      setCopiedKey(key);
      setFallbackText(null);
      onToast?.(`已复制: ${label}`);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopiedKey((prev) => (prev === key ? null : prev));
        copyTimerRef.current = null;
      }, 2000);
    } else {
      setFallbackText(text);
      onToast?.("复制失败，请在文本框中手动全选复制");
    }
  };

  return { copiedKey, fallbackText, copy };
}

export function HelpDialog({
  open,
  title,
  notice,
  fallbackText,
  children,
  onClose,
}: HelpDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeBtnRef = useRef<HTMLButtonElement>(null);
  const fallbackRef = useRef<HTMLTextAreaElement>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);

  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  const isOpenRef = useRef(open);
  isOpenRef.current = open;

  const requestClose = () => {
    isOpenRef.current = false;
    onCloseRef.current();
  };

  useEffect(() => {
    if (open) {
      isOpenRef.current = true;
      previousActiveElement.current =
        (document.activeElement as HTMLElement) ?? null;

      const frame = window.requestAnimationFrame(() => {
        closeBtnRef.current?.focus();
      });

      const handleKeyDown = (event: KeyboardEvent) => {
        if (event.key === "Escape") {
          event.preventDefault();
          requestClose();
          return;
        }

        if (event.key === "Tab") {
          const container = dialogRef.current;
          if (!container) return;
          const focusable = container.querySelectorAll<HTMLElement>(
            'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
          );
          if (focusable.length === 0) return;

          const first = focusable[0];
          const last = focusable[focusable.length - 1];

          if (event.shiftKey) {
            if (document.activeElement === first) {
              event.preventDefault();
              last?.focus();
            }
          } else {
            if (document.activeElement === last) {
              event.preventDefault();
              first?.focus();
            }
          }
        }
      };

      window.addEventListener("keydown", handleKeyDown);
      return () => {
        window.cancelAnimationFrame(frame);
        isOpenRef.current = false;
        window.removeEventListener("keydown", handleKeyDown);
        if (
          previousActiveElement.current &&
          typeof previousActiveElement.current.focus === "function"
        ) {
          previousActiveElement.current.focus();
        }
        previousActiveElement.current = null;
      };
    }
  }, [open]);

  useEffect(() => {
    if (fallbackText && fallbackRef.current) {
      fallbackRef.current.focus();
      fallbackRef.current.select();
    }
  }, [fallbackText]);

  if (!open) return null;

  return (
    <div className="external-ai-help-overlay">
      <div className="external-ai-help-backdrop" onClick={requestClose} />
      <div
        ref={dialogRef}
        className="external-ai-help-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="help-dialog-title"
        aria-describedby="help-dialog-desc"
        tabIndex={-1}
      >
        <header className="external-ai-help-header">
          <div className="external-ai-help-header-content">
            <div className="external-ai-help-icon">
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
                <circle cx="12" cy="12" r="10" />
                <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
            </div>
            <h2 className="external-ai-help-title" id="help-dialog-title">
              {title}
            </h2>
          </div>
          <button
            ref={closeBtnRef}
            type="button"
            className="external-ai-help-close-btn"
            aria-label="关闭帮助对话框"
            onClick={requestClose}
          >
            <svg
              viewBox="0 0 24 24"
              width="18"
              height="18"
              stroke="currentColor"
              strokeWidth="2"
              fill="none"
            >
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </header>

        <div className="external-ai-help-body">
          <div className="external-ai-help-notice" id="help-dialog-desc">
            {notice}
          </div>

          {fallbackText && (
            <div className="external-ai-help-fallback-box" role="alert">
              <p>剪贴板自动写入未成功，请在下方文本框中手动全选复制：</p>
              <textarea
                ref={fallbackRef}
                className="external-ai-help-fallback-textarea"
                readOnly
                value={fallbackText}
                onFocus={(e) => e.target.select()}
              />
            </div>
          )}

          {children}
        </div>

        <footer className="external-ai-help-footer">
          <button type="button" className="btn-white" onClick={requestClose}>
            关闭
          </button>
        </footer>
      </div>
    </div>
  );
}
