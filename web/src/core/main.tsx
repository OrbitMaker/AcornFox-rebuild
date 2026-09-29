import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import CoreApp from "./CoreApp";
import "../shared/shell.css";
import "../acornfox/ExternalAIHelp.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <CoreApp />
  </StrictMode>,
);
