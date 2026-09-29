import { useEffect, useState } from "react";

export function useDesktopPresentation() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [clock, setClock] = useState("14:45");
  const [toast, setToast] = useState<{ text: string; visible: boolean }>({
    text: "",
    visible: false,
  });

  // Sync theme
  useEffect(() => {
    let saved: "dark" | "light" = "dark";
    try {
      saved =
        localStorage.getItem("open_card_theme") === "light" ? "light" : "dark";
    } catch {
      /* ignore */
    }
    setTheme(saved);
    if (typeof document !== "undefined") {
      document.documentElement.setAttribute("data-theme", saved);
    }
  }, []);

  const toggleThemeMode = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    if (typeof document !== "undefined") {
      document.documentElement.setAttribute("data-theme", next);
    }
    try {
      localStorage.setItem("open_card_theme", next);
    } catch {
      /* ignore */
    }
  };

  // Clock ticker
  useEffect(() => {
    const update = () => {
      const d = new Date();
      setClock(
        d.toLocaleTimeString("zh-CN", {
          hour: "2-digit",
          minute: "2-digit",
        }),
      );
    };
    update();
    const interval = window.setInterval(update, 1000);
    return () => window.clearInterval(interval);
  }, []);

  const showToast = (text: string) => {
    setToast({ text, visible: true });
    window.setTimeout(() => setToast({ text: "", visible: false }), 2500);
  };

  return { theme, toggleThemeMode, clock, toast, showToast };
}
