// SPDX-License-Identifier: AGPL-3.0-or-later
import { loadConfig, silentCallback } from "./auth";
void loadConfig().then(silentCallback).catch(() => { console.error("Karst session renewal failed"); });
