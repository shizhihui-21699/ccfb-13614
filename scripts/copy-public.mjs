// Build helper: assemble the static document root the relay server serves.
//   src/public/**        -> dist/public/**          (HTML, CSS)
//   dist/client/**/*.js  -> dist/public/client/**   (compiled browser bundle;
//                                                    Node-only crypto code is
//                                                    imported as ESM and lives
//                                                    in the same output tree)
import { cp, mkdir, rm } from "node:fs/promises";

await rm("dist/public", { recursive: true, force: true });
await mkdir("dist/public", { recursive: true });
await cp("src/public", "dist/public", { recursive: true });
await cp("dist/client", "dist/public/client", { recursive: true });
console.log("assembled dist/public (page assets + client bundle)");
