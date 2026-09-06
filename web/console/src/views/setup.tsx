// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.
import { Enrollment } from "@karst-net/ui";
import { api } from "../api";

export function Setup({ go }: { go: (route: string) => void }) {
  return <section><h2>Set up your Karst network</h2>
    <p>Configure the coordination server and identity provider using the <a href="/docs/quickstart.html">installation guide</a>, then enroll your first device below.</p>
    <Enrollment metadata={api.enrollmentMetadata} issue={api.enroll} />
    <p>After enrollment, confirm the device in Machines. Bedrock approval and access policy determine which connections it can make.</p>
    <button onClick={() => go("machines")}>View machines</button>
  </section>;
}
