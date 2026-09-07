import { ListMagnifyingGlass } from "@phosphor-icons/react";
import type { ViewerBundle } from "../domain/types";

export function TextScene({
  bundle,
  selectedId,
  onSelect,
}: {
  bundle: ViewerBundle;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <section className="text-scene" aria-label="Text representation of the captured page">
      <header>
        <ListMagnifyingGlass size={24} aria-hidden="true" />
        <div>
          <h2>MODEL INDEX</h2>
          <p>Every object below opens the same evidence as the 3D model.</p>
        </div>
      </header>
      <ol>
        {bundle.runtime.selectables.map((item) => (
          <li key={item.id}>
            <button
              type="button"
              className={selectedId === item.id ? "is-selected" : ""}
              onClick={() => onSelect(item.id)}
            >
              <span>{item.label}</span>
              <code>{item.id}</code>
            </button>
          </li>
        ))}
      </ol>
    </section>
  );
}
