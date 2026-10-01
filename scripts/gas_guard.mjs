// GenLayerJS catches estimation errors and falls back to 200k. A write bridge
// must fail closed instead of signing that fallback after a deterministic revert.
export function createGasGuard({estimate,readRpc}) {
  let failed = false;
  return {
    estimate: async (request) => {
      try {return await readRpc(() => estimate(request));}
      catch (error) {failed = true; throw error;}
    },
    assertCanSign: () => {
      if (failed) throw new Error('gas estimation failed; refusing SDK fallback broadcast');
    },
  };
}
