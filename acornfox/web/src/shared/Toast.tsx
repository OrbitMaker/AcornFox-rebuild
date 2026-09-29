export function Toast({
  toast,
}: {
  toast: { text: string; visible: boolean };
}) {
  return (
    <div
      className={`toast-capsule ${toast.visible ? "is-active is-visible" : ""}`}
      id="toastCapsule"
    >
      <svg viewBox="0 0 24 24">
        <polyline points="20 6 9 17 4 12" />
      </svg>
      <span id="toastText">{toast.text}</span>
    </div>
  );
}
