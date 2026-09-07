import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/archivo";
import "@fontsource/barlow-condensed/latin-700.css";
import "@fontsource/barlow-condensed/latin-800.css";
import { App } from "./app/App";
import "./styles/index.css";

const root = document.getElementById("root");
if (!root) throw new Error("DOM X-Ray could not find its application root.");
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
