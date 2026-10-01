// Select the finalized consensus round explicitly; the debug RPC defaults to 0.
// The trace API exposes no leader signature or execution-hash preimage. This
// checks round/leader metadata and execution outcome, not a cryptographic proof.
const integer = (value, name) => {
  if (!/^(0|[1-9]\d*)$/.test(String(value))) throw new Error(`invalid ${name}`);
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw new Error(`invalid ${name}`);
  return number;
};
const sameHex = (left, right) => typeof left === 'string' && typeof right === 'string' && left.toLowerCase() === right.toLowerCase();
const leaderOf = (round) => {
  const index = integer(round?.leaderIndex, 'leader index');
  const leader = round?.roundValidators?.[index];
  if (!/^0x[0-9a-f]{40}$/i.test(leader || '')) throw new Error('round has no valid leader');
  return leader;
};

export function selectFinalizedRound({hash, receipt, roundNumber, lastRoundData}) {
  if (!sameHex(receipt?.txId, hash)) throw new Error('finalized receipt transaction identity mismatch');
  if (integer(receipt.status, 'receipt status') !== 7 || receipt.statusName !== 'FINALIZED') throw new Error('receipt is not finalized');
  if (integer(receipt.txExecutionResult, 'execution result') !== 1) throw new Error('finalized contract execution did not return successfully');
  if (integer(receipt.result, 'consensus result') !== 1) throw new Error('finalized consensus result is not AGREE');
  // The storage cursor and the round field inside RoundData differ after
  // rotations (observed cursor=4, RoundData.round=2). Trace RPC takes the cursor.
  const round = integer(roundNumber, 'on-chain round cursor');
  if (integer(receipt.numOfRounds, 'receipt round cursor') !== round) throw new Error('finalized round metadata mismatch');
  if (!Array.isArray(lastRoundData) || lastRoundData.length !== 2 || integer(lastRoundData[0], 'last round cursor') !== round) throw new Error('finalized last-round readback mismatch');
  const dataRound = integer(lastRoundData[1]?.round, 'round data');
  if (integer(receipt.lastRound?.round, 'receipt round data') !== dataRound) throw new Error('finalized round-data field mismatch');
  const leader = leaderOf(lastRoundData[1]);
  if (!sameHex(leader, leaderOf(receipt.lastRound)) || !sameHex(leader, receipt.lastLeader)) throw new Error('finalized round leader mismatch');
  if (integer(lastRoundData[1].result, 'round result') !== 1 || integer(receipt.lastRound.result, 'receipt round result') !== 1) throw new Error('finalized round is not AGREE');
  return {round,round_data_round:dataRound,leader,receipt_execution_hash:receipt.txExecutionHash,
    binding:'finalized-round-and-leader', cryptographic_trace_binding:false};
}

export function decodeFinalizedTrace({hash, trace, identity, decode}) {
  if (!sameHex(trace?.transaction_id, hash)) throw new Error('trace transaction identity mismatch');
  if (integer(trace.result_code, 'trace result code') !== 0) throw new Error(`contract execution failed (result_code ${trace.result_code}); see saved trace`);
  if (!identity || !Number.isSafeInteger(identity.round)) throw new Error('missing finalized trace round identity');
  if (!/^0x(?:[0-9a-f]{2})+$/i.test(trace.return_data || '')) throw new Error('trace contains invalid return data');
  let decoded;
  try {decoded = decode(Buffer.from(trace.return_data.slice(2), 'hex'));}
  catch {throw new Error('cannot decode finalized trace return data');}
  const value = (key) => decoded instanceof Map ? decoded.get(key) : decoded?.[key];
  const hasData = decoded instanceof Map ? decoded.has('data') : decoded && Object.hasOwn(decoded, 'data');
  if (value('kind') !== 'Return' || !hasData) throw new Error('finalized trace did not contain a successful Return');
  return value('data');
}
