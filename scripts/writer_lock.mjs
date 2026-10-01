import {openSync,writeFileSync,closeSync,readFileSync,unlinkSync,lstatSync} from 'node:fs';
import {randomUUID} from 'node:crypto';

export function acquireWriterLock(path) {
  const owner = {pid:process.pid,id:randomUUID()};
  let descriptor;
  try {descriptor = openSync(path,'wx',0o600);}
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    if (lstatSync(path).isSymbolicLink()) throw new Error('writer lock is a symlink; refusing write');
    const bytes = readFileSync(path,'utf8');
    let existing;
    try {existing = JSON.parse(bytes);} catch {throw new Error('invalid writer lock; refusing write');}
    if (!Number.isSafeInteger(existing.pid) || existing.pid <= 0) throw new Error('invalid writer lock owner');
    try {process.kill(existing.pid,0);}
    catch (probeError) {
      if (probeError.code !== 'ESRCH') throw new Error('cannot verify writer lock owner; refusing write');
      // Reclaiming via read/unlink/open has a race between two contenders.
      // A human can clear a known dead lock while every writer is stopped.
      throw new Error('stale Bradbury writer lock; verify the owner is stopped and clear it explicitly');
    }
    if (descriptor === undefined) throw new Error('another Bradbury writer is active; refusing concurrent signing');
  }
  try {writeFileSync(descriptor,JSON.stringify(owner));} finally {closeSync(descriptor);}
  return () => {
    try {
      const current = JSON.parse(readFileSync(path,'utf8'));
      if (current.pid === owner.pid && current.id === owner.id) unlinkSync(path);
    } catch (error) {if (error.code !== 'ENOENT') throw error;}
  };
}
