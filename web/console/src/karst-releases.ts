// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

/** Recent karst-net/karst release tags, newest first — issue #560's
 * "Change version" dropdown stop-gap: a real admin-approved, per-connection
 * image/version registry (which would resolve a chosen entry to whatever a
 * given infrastructure connection's driver actually needs to launch it,
 * e.g. an AMI id) is tracked separately as issue #561. Until that lands,
 * this only offers a plausible-looking version string — picking one here
 * still does not guarantee `infraprovision.Driver.Create` can do anything
 * with it for a given connection.
 *
 * Fetched directly from GitHub's public Releases API: no backend
 * involvement, no auth needed for a public repo, and it is exactly the
 * same source the existing "Download Karst" link (Devices page,
 * machines.tsx) already points at.
 */
export async function recentKarstReleases(): Promise<string[]> {
  const response = await fetch("https://api.github.com/repos/karst-net/karst/releases?per_page=15");
  if (!response.ok) throw new Error(`GitHub releases: ${response.status} ${response.statusText}`);
  const releases = await response.json() as Array<{ tag_name: string; draft: boolean; published_at: string | null }>;
  return releases
    .filter(release => !release.draft)
    .sort((a, b) => (b.published_at ?? "").localeCompare(a.published_at ?? ""))
    .map(release => release.tag_name);
}
