import { readdir, mkdir, copyFile } from 'node:fs/promises';
import { join } from 'node:path';

// Only the fixed corpus's public artifacts belong in the hosted evidence folder.
export async function copyCorpusEvidence(source, destination) {
  const entries = await readdir(source, { withFileTypes: true });
  await mkdir(destination, { recursive: true });
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (entry.name !== 'mechanical-baseline.json' &&
        !/^(?:[0-3][0-9]|4[0-4])\.(?:envelope|transaction|receipt|gate)\.json$/.test(entry.name)) continue;
    await copyFile(join(source, entry.name), join(destination, entry.name));
  }
}
