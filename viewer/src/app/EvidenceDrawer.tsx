import { Crosshair, Eye, EyeSlash, X } from "@phosphor-icons/react";
import { useEffect, useMemo, useRef } from "react";
import type { EvidenceDossier } from "../domain/types";

function evidenceSummary(dossier: EvidenceDossier) {
  const values = dossier.rows.map((row) => row.value);
  const record = values.find(
    (value): value is Record<string, unknown> =>
      typeof value === "object" && value !== null && !Array.isArray(value),
  );
  if (!record) return [];
  const candidates = [
    ["TAG", record.tag],
    ["SELECTOR", record.selector],
    ["RESOURCE", record.displayUrl],
    ["TRANSFERRED", record.transferredBytes],
    ["DOMAIN", record.registrableDomain],
    ["TYPE", record.type],
    ["PARTY", record.party],
    ["SCOPE", record.attributionScope],
  ] as const;
  return candidates.filter((item) => item[1] !== undefined && item[1] !== null);
}

export function EvidenceDrawer({
  dossier,
  isolated,
  onClose,
  onToggleIsolation,
}: {
  dossier: EvidenceDossier | null;
  isolated: boolean;
  onClose: () => void;
  onToggleIsolation: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const summary = useMemo(() => (dossier ? evidenceSummary(dossier) : []), [dossier]);

  useEffect(() => {
    if (dossier) closeRef.current?.focus({ preventScroll: true });
  }, [dossier]);

  if (!dossier) return null;

  return (
    <aside className="evidence-drawer" aria-label="Evidence for selected object">
      <header className="drawer-header">
        <div>
          <span className="measurement-label">EVIDENCE PATH</span>
          <h2>{dossier.selectable.label}</h2>
        </div>
        <button
          ref={closeRef}
          className="icon-button"
          type="button"
          onClick={onClose}
          aria-label="Close evidence"
        >
          <X size={20} weight="bold" aria-hidden="true" />
        </button>
      </header>

      <div className="drawer-selection-id">
        <Crosshair size={18} weight="regular" aria-hidden="true" />
        <code>{dossier.selectable.id}</code>
      </div>

      {summary.length > 0 && (
        <dl className="evidence-summary">
          {summary.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd>{String(value)}</dd>
            </div>
          ))}
        </dl>
      )}

      <button
        className="drawer-action"
        type="button"
        onClick={onToggleIsolation}
        disabled={!dossier.selectable.renderable}
      >
        {isolated ? <EyeSlash size={18} aria-hidden="true" /> : <Eye size={18} aria-hidden="true" />}
        {isolated ? "SHOW COMPLETE MODEL" : "ISOLATE IN MODEL"}
      </button>

      <div className="evidence-ledger">
        <h3>RAW SOURCES</h3>
        {dossier.rows.map((row, index) => (
          <details key={`${row.namespace}:${row.ref}:${index}`}>
            <summary>
              <span>{row.namespace}</span>
              <code>{row.ref}</code>
            </summary>
            <pre>{JSON.stringify(row.value, null, 2)}</pre>
          </details>
        ))}
      </div>
    </aside>
  );
}
