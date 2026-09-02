import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import AcornFoxApp from "./acornfox/App";
import "./acornfox/styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AcornFoxApp />
  </StrictMode>,
);
