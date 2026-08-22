// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { execFileSync } from "node:child_process";
import { readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const generatedRoot = join(packageRoot, "src", "generated");
const openAPISpec = join(packageRoot, "../../../server/shared/management/http/api/karst-openapi.yml");
const spdx = "// SPDX-License-Identifier: AGPL-3.0-or-later\n// Copyright the Karst contributors.\n";

await rm(generatedRoot, { recursive: true, force: true });

execFileSync("openapi-ts", [
  "-i", openAPISpec,
  "-o", generatedRoot,
], { cwd: packageRoot, stdio: "inherit" });

async function addSpdx(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      await addSpdx(path);
    } else if (entry.isFile() && path.endsWith(".ts")) {
      const source = await readFile(path, "utf8");
		// The upstream generator emits two trailing newlines. Keep generated
		// files compatible with git diff --check while preserving one POSIX EOF.
		const body = source.startsWith("// SPDX-License-Identifier:")
			? source.slice(spdx.length)
			: source;
		await writeFile(path, `${spdx}${body.trimEnd()}\n`);
    }
  }
}

await addSpdx(generatedRoot);
