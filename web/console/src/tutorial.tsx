// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import type { ReactNode } from "react";
import { api } from "./api";
import { useResource } from "./common";

/** Account-scoped, default-on. Every view that wraps its explanatory
 *  paragraph in [TutorialHint] shares one fetch of this setting rather than
 *  each re-requesting it, since `useResource` has no cross-component cache
 *  of its own. */
export function useTutorialMode() {
  const resource = useResource(() => api.tutorialMode().then((mode) => mode.enabled));
  return resource.value ?? false;
}

/** Wraps a page's "what is this, what does it talk to" explanation so the
 *  Settings toggle actually controls something instead of every view
 *  carrying its own always-on copy. Renders nothing while the setting is
 *  loading or off -- there is no flash of guidance text before it resolves,
 *  since `useTutorialMode` defaults to false until the fetch completes. */
export function TutorialHint({ children }: { children: ReactNode }) {
  const enabled = useTutorialMode();
  if (!enabled) return null;
  return <p className="lede">{children}</p>;
}
