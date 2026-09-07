import type {
  EvidenceDossier,
  EvidenceRow,
  Selectable,
  ViewerBundle,
} from "./types";

export function resolvePointer(document: unknown, pointer: string): unknown {
  if (!pointer.startsWith("#/")) {
    throw new Error(`Invalid local JSON Pointer: ${pointer}`);
  }

  let current = document;
  for (const encoded of pointer.slice(2).split("/")) {
    const token = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (Array.isArray(current)) {
      if (!/^\d+$/.test(token)) {
        throw new Error(`Non-numeric array token: ${pointer}`);
      }
      const index = Number(token);
      if (!(index in current)) {
        throw new Error(`Pointer is out of range: ${pointer}`);
      }
      current = current[index];
      continue;
    }
    if (typeof current !== "object" || current === null || !(token in current)) {
      throw new Error(`Unresolved pointer: ${pointer}`);
    }
    current = (current as Record<string, unknown>)[token];
  }
  return current;
}

function pointerRows(
  namespace: EvidenceRow["namespace"],
  document: unknown,
  pointers: string[],
): EvidenceRow[] {
  return pointers.map((ref) => ({
    namespace,
    ref,
    value: resolvePointer(document, ref),
  }));
}

export function dossierFor(bundle: ViewerBundle, id: string): EvidenceDossier {
  const selectable = bundle.runtime.selectables.find((item) => item.id === id);
  if (!selectable) {
    throw new Error(`Unknown selectable: ${id}`);
  }
  return {
    selectable,
    rows: [
      ...pointerRows("scene", bundle.scene, selectable.sceneRefs),
      ...pointerRows("record", bundle.record, selectable.recordRefs),
      ...pointerRows("mapping", bundle.mapping, selectable.mappingRefs),
      ...pointerRows("result", bundle.result, selectable.resultRefs),
      ...pointerRows("limitation", bundle.record, selectable.limitationRefs),
    ],
  };
}

export function validateSelectablePointers(
  bundle: Omit<ViewerBundle, "name">,
  selectable: Selectable,
): void {
  for (const [document, refs] of [
    [bundle.scene, selectable.sceneRefs],
    [bundle.record, selectable.recordRefs],
    [bundle.mapping, selectable.mappingRefs],
    [bundle.result, selectable.resultRefs],
    [bundle.record, selectable.limitationRefs],
  ] as const) {
    refs.forEach((ref) => resolvePointer(document, ref));
  }
}
