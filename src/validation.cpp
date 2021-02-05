// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <checkqueue.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <cuckoocache.h>
#include <flatfile.h>
#include <hash.h>
#include <index/txindex.h>
#include <logging.h>
#include <logging/timer.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <pow.h>
#include <pos.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <reverse_iterator.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <shutdown.h>
#include <timedata.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <ui_interface.h>
#include <uint256.h>
#include <undo.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/translation.h>
#include <validationinterface.h>
#include <warnings.h>
#include <libethcore/ABI.h>
#include <util/signstr.h>
#include <net_processing.h>

#include <serialize.h>
#include <pubkey.h>
#include <key.h>
#include <wallet/wallet.h>
#include <util/convert.h>
#include <util/signstr.h>

#include <algorithm>
#include <string>

#include <boost/algorithm/string/replace.hpp>
#include <boost/thread.hpp>

#if defined(NDEBUG)
# error "Qtum cannot be compiled without assertions."
#endif

#define MICRO 0.000001
#define MILLI 0.001

 ////////////////////////////// qtum
#include <iostream>
#include <bitset>
#include "pubkey.h"
#include <univalue.h>

std::unique_ptr<QtumState> globalState;
std::shared_ptr<dev::eth::SealEngineFace> globalSealEngine;
bool fRecordLogOpcodes = false;
bool fIsVMlogFile = false;
bool fGettingValuesDGP = false;
 //////////////////////////////

bool CBlockIndexWorkComparator::operator()(const CBlockIndex *pa, const CBlockIndex *pb) const {
    // First sort by most total work, ...
    if (pa->nChainWork > pb->nChainWork) return false;
    if (pa->nChainWork < pb->nChainWork) return true;

    // ... then by earliest time received, ...
    if (pa->nSequenceId < pb->nSequenceId) return false;
    if (pa->nSequenceId > pb->nSequenceId) return true;

    // Use pointer address as tie breaker (should only happen with blocks
    // loaded from disk, as those all have id 0).
    if (pa < pb) return false;
    if (pa > pb) return true;

    // Identical blocks.
    return false;
}

namespace {
BlockManager g_blockman;
} // anon namespace

std::unique_ptr<CChainState> g_chainstate;

CChainState& ChainstateActive() {
    assert(g_chainstate);
    return *g_chainstate;
}

CChain& ChainActive() {
    assert(g_chainstate);
    return g_chainstate->m_chain;
}

/**
 * Mutex to guard access to validation specific variables, such as reading
 * or changing the chainstate.
 *
 * This may also need to be locked when updating the transaction pool, e.g. on
 * AcceptToMemoryPool. See CTxMemPool::cs comment for details.
 *
 * The transaction pool has a separate lock to allow reading from it and the
 * chainstate at the same time.
 */
RecursiveMutex cs_main;

CBlockIndex *pindexBestHeader = nullptr;
Mutex g_best_block_mutex;
std::condition_variable g_best_block_cv;
uint256 g_best_block;
bool g_parallel_script_checks{false};
std::atomic_bool fImporting(false);
std::atomic_bool fReindex(false);
bool fAddressIndex = false; // qtum
bool fLogEvents = false;
bool fHavePruned = false;
bool fPruneMode = false;
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;

uint256 hashAssumeValid;
arith_uint256 nMinimumChainWork;

CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);

CBlockPolicyEstimator feeEstimator;
CTxMemPool mempool(&feeEstimator);

// Internal stuff
namespace {
    CBlockIndex* pindexBestInvalid = nullptr;

    RecursiveMutex cs_LastBlockFile;
    std::vector<CBlockFileInfo> vinfoBlockFile;
    int nLastBlockFile = 0;
    /** Global flag to indicate we should check to see if there are
     *  block/undo files that should be deleted.  Set on startup
     *  or if we allocate more file space when we're in prune mode
     */
    bool fCheckForPruning = false;

    /** Dirty block index entries. */
    std::set<CBlockIndex*> setDirtyBlockIndex;

    /** Dirty block file entries. */
    std::set<int> setDirtyFileInfo;
} // anon namespace

CBlockIndex* LookupBlockIndex(const uint256& hash)
{
    AssertLockHeld(cs_main);
    BlockMap::const_iterator it = g_blockman.m_block_index.find(hash);
    return it == g_blockman.m_block_index.end() ? nullptr : it->second;
}

CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator)
{
    AssertLockHeld(cs_main);

    // Find the latest block common to locator and chain - we expect that
    // locator.vHave is sorted descending by height.
    for (const uint256& hash : locator.vHave) {
        CBlockIndex* pindex = LookupBlockIndex(hash);
        if (pindex) {
            if (chain.Contains(pindex))
                return pindex;
            if (pindex->GetAncestor(chain.Height()) == chain.Tip()) {
                return chain.Tip();
            }
        }
    }
    return chain.Genesis();
}

std::unique_ptr<CBlockTreeDB> pblocktree;
std::unique_ptr<StorageResults> pstorageresult;

// See definition for documentation
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight);
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight);
bool CheckInputScripts(const CTransaction& tx, TxValidationState &state, const CCoinsViewCache &inputs, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks = nullptr);
static FILE* OpenUndoFile(const FlatFilePos &pos, bool fReadOnly = false);
static FlatFileSeq BlockFileSeq();
static FlatFileSeq UndoFileSeq();

bool CheckFinalTx(const CTransaction &tx, int flags)
{
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses ::ChainActive().Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than ::ChainActive().Height().
    const int nBlockHeight = ::ChainActive().Height() + 1;

    // BIP113 requires that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST)
                             ? ::ChainActive().Tip()->GetMedianTimePast()
                             : GetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

bool TestLockPointValidity(const LockPoints* lp)
{
    AssertLockHeld(cs_main);
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) {
        // Check whether ::ChainActive() is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!::ChainActive().Contains(lp->maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTxMemPool& pool, const CTransaction& tx, int flags, LockPoints* lp, bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    CBlockIndex* tip = ::ChainActive().Tip();
    assert(tip != nullptr);

    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses ::ChainActive().Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than ::ChainActive().Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        // CoinsTip() contains the UTXO set for ::ChainActive().Tip()
        CCoinsViewMemPool viewMemPool(&::ChainstateActive().CoinsTip(), pool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            Coin coin;
            if (!viewMemPool.GetCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (const int height : prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

// Returns the script flags which should be checked for a given block
static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& chainparams);

static void LimitMempoolSize(CTxMemPool& pool, size_t limit, std::chrono::seconds age)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs, ::cs_main)
{
    int expired = pool.Expire(GetTime<std::chrono::seconds>() - age);
    if (expired != 0) {
        LogPrint(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint& removed : vNoSpendsRemaining)
        ::ChainstateActive().CoinsTip().Uncache(removed);
}

static bool IsCurrentForFeeEstimation() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    if (::ChainstateActive().IsInitialBlockDownload())
        return false;
    if (::ChainActive().Tip()->GetBlockTime() < (GetTime() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (::ChainActive().Height() < pindexBestHeader->nHeight - 1)
        return false;
    return true;
}

/* Make mempool consistent after a reorg, by re-adding or recursively erasing
 * disconnected block transactions from the mempool, and also removing any
 * other transactions from the mempool that are no longer valid given the new
 * tip/height.
 *
 * Note: we assume that disconnectpool only contains transactions that are NOT
 * confirmed in the current chain nor already in the mempool (otherwise,
 * in-mempool descendants of such transactions would be removed).
 *
 * Passing fAddToMempool=false will skip trying to add the transactions back,
 * and instead just erase from the mempool as needed.
 */

static void UpdateMempoolForReorg(DisconnectedBlockTransactions& disconnectpool, bool fAddToMempool) EXCLUSIVE_LOCKS_REQUIRED(cs_main, ::mempool.cs)
{
    AssertLockHeld(cs_main);
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        // ignore validation errors in resurrected transactions
        TxValidationState stateDummy;
        if (!fAddToMempool || (*it)->IsCoinBase() || (*it)->IsCoinStake() ||
            !AcceptToMemoryPool(mempool, stateDummy, *it,
                                nullptr /* plTxnReplaced */, true /* bypass_limits */, 0 /* nAbsurdFee */)) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
        } else if (mempool.exists((*it)->GetHash())) {
            vHashUpdate.push_back((*it)->GetHash());
        }
        ++it;
    }
    disconnectpool.queuedTx.clear();
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);

    // We also need to remove any now-immature transactions
    mempool.removeForReorg(&::ChainstateActive().CoinsTip(), ::ChainActive().Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(mempool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, std::chrono::hours{gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY)});
}

// Used to avoid mempool polluting consensus critical paths if CCoinsViewMempool
// were somehow broken and returning the wrong scriptPubKeys
static bool CheckInputsFromMempoolAndCache(const CTransaction& tx, TxValidationState& state, const CCoinsViewCache& view, const CTxMemPool& pool,
                 unsigned int flags, PrecomputedTransactionData& txdata) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);

    // pool.cs should be locked already, but go ahead and re-take the lock here
    // to enforce that mempool doesn't change between when we check the view
    // and when we actually call through to CheckInputScripts
    LOCK(pool.cs);

    assert(!tx.IsCoinBase());
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = view.AccessCoin(txin.prevout);

        // AcceptToMemoryPoolWorker has already checked that the coins are
        // available, so this shouldn't fail. If the inputs are not available
        // here then return false.
        if (coin.IsSpent()) return false;

        // Check equivalence for available inputs.
        const CTransactionRef& txFrom = pool.get(txin.prevout.hash);
        if (txFrom) {
            assert(txFrom->GetHash() == txin.prevout.hash);
            assert(txFrom->vout.size() > txin.prevout.n);
            assert(txFrom->vout[txin.prevout.n] == coin.out);
        } else {
            const Coin& coinFromDisk = ::ChainstateActive().CoinsTip().AccessCoin(txin.prevout);
            assert(!coinFromDisk.IsSpent());
            assert(coinFromDisk.out == coin.out);
        }
    }

    // Call CheckInputScripts() to cache signature and script validity against current tip consensus rules.
    return CheckInputScripts(tx, state, view, flags, /* cacheSigStore = */ true, /* cacheFullSciptStore = */ true, txdata);
}

namespace {

class MemPoolAccept
{
public:
    MemPoolAccept(CTxMemPool& mempool) : m_pool(mempool), m_view(&m_dummy), m_viewmempool(&::ChainstateActive().CoinsTip(), m_pool),
        m_limit_ancestors(gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT)),
        m_limit_ancestor_size(gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000),
        m_limit_descendants(gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT)),
        m_limit_descendant_size(gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000) {}

    // We put the arguments we're handed into a struct, so we can pass them
    // around easier.
    struct ATMPArgs {
        const CChainParams& m_chainparams;
        TxValidationState &m_state;
        const int64_t m_accept_time;
        std::list<CTransactionRef>* m_replaced_transactions;
        const bool m_bypass_limits;
        const CAmount& m_absurd_fee;
        /*
         * Return any outpoints which were not previously present in the coins
         * cache, but were added as a result of validating the tx for mempool
         * acceptance. This allows the caller to optionally remove the cache
         * additions if the associated transaction ends up being rejected by
         * the mempool.
         */
        std::vector<COutPoint>& m_coins_to_uncache;
        const bool m_test_accept;
        bool m_raw_tx;
    };

    // Single transaction acceptance
    bool AcceptSingleTransaction(const CTransactionRef& ptx, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    // All the intermediate state that gets passed between the various levels
    // of checking a given transaction.
    struct Workspace {
        Workspace(const CTransactionRef& ptx) : m_ptx(ptx), m_hash(ptx->GetHash()) {}
        std::set<uint256> m_conflicts;
        CTxMemPool::setEntries m_all_conflicting;
        CTxMemPool::setEntries m_ancestors;
        std::unique_ptr<CTxMemPoolEntry> m_entry;

        bool m_replacement_transaction;
        CAmount m_modified_fees;
        CAmount m_conflicting_fees;
        size_t m_conflicting_size;

        const CTransactionRef& m_ptx;
        const uint256& m_hash;
    };

    // Run the policy checks on a given transaction, excluding any script checks.
    // Looks up inputs, calculates feerate, considers replacement, evaluates
    // package limits, etc. As this function can be invoked for "free" by a peer,
    // only tests that are fast should be done here (to avoid CPU DoS).
    bool PreChecks(ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Run the script checks using our policy flags. As this can be slow, we should
    // only invoke this on transactions that have otherwise passed policy checks.
    bool PolicyScriptChecks(ATMPArgs& args, Workspace& ws, PrecomputedTransactionData& txdata) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Re-run the script checks, using consensus flags, and try to cache the
    // result in the scriptcache. This should be done after
    // PolicyScriptChecks(). This requires that all inputs either be in our
    // utxo set or in the mempool.
    bool ConsensusScriptChecks(ATMPArgs& args, Workspace& ws, PrecomputedTransactionData &txdata) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Try to add the transaction to the mempool, removing any conflicts first.
    // Returns true if the transaction is in the mempool after any size
    // limiting is performed, false otherwise.
    bool Finalize(ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Compare a package's feerate against minimum allowed.
    bool CheckFeeRate(size_t package_size, CAmount package_fee, TxValidationState& state)
    {
        CAmount mempoolRejectFee = m_pool.GetMinFee(gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFee(package_size);
        if (mempoolRejectFee > 0 && package_fee < mempoolRejectFee) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool min fee not met", strprintf("%d < %d", package_fee, mempoolRejectFee));
        }

        if (package_fee < ::minRelayTxFee.GetFee(package_size)) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "min relay fee not met", strprintf("%d < %d", package_fee, ::minRelayTxFee.GetFee(package_size)));
        }
        return true;
    }

private:
    CTxMemPool& m_pool;
    CCoinsViewCache m_view;
    CCoinsViewMemPool m_viewmempool;
    CCoinsView m_dummy;

    // The package limits in effect at the time of invocation.
    const size_t m_limit_ancestors;
    const size_t m_limit_ancestor_size;
    // These may be modified while evaluating a transaction (eg to account for
    // in-mempool conflicts; see below).
    size_t m_limit_descendants;
    size_t m_limit_descendant_size;
};

bool MemPoolAccept::PreChecks(ATMPArgs& args, Workspace& ws)
{
    const CTransactionRef& ptx = ws.m_ptx;
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;

    // Copy/alias what we need out of args
    TxValidationState &state = args.m_state;
    const int64_t nAcceptTime = args.m_accept_time;
    const bool bypass_limits = args.m_bypass_limits;
    const CAmount& nAbsurdFee = args.m_absurd_fee;
    std::vector<COutPoint>& coins_to_uncache = args.m_coins_to_uncache;
    const CChainParams& chainparams = args.m_chainparams;
    bool rawTx = args.m_raw_tx;

    // Alias what we need out of ws
    std::set<uint256>& setConflicts = ws.m_conflicts;
    CTxMemPool::setEntries& allConflicting = ws.m_all_conflicting;
    CTxMemPool::setEntries& setAncestors = ws.m_ancestors;
    std::unique_ptr<CTxMemPoolEntry>& entry = ws.m_entry;
    bool& fReplacementTransaction = ws.m_replacement_transaction;
    CAmount& nModifiedFees = ws.m_modified_fees;
    CAmount& nConflictingFees = ws.m_conflicting_fees;
    size_t& nConflictingSize = ws.m_conflicting_size;

    if (!CheckTransaction(tx, state))
        return false; // state filled in by CheckTransaction

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "coinbase");

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "coinstake");

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (fRequireStandard && !IsStandardTx(tx, reason))
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, reason);

    // Do not work on transactions that are too small.
    // A transaction with 1 segwit input and 1 P2WPHK output has non-witness size of 82 bytes.
    // Transactions smaller than this are not relayed to mitigate CVE-2017-12842 by not relaying
    // 64-byte transactions.
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) < MIN_STANDARD_TX_NONWITNESS_SIZE)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "tx-size-small");

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-final");

    // is it already in the memory pool?
    if (m_pool.exists(hash)) {
        return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-in-mempool");
    }

    // Check for conflicts with in-memory transactions
    for (const CTxIn &txin : tx.vin)
    {
        const CTransaction* ptxConflicting = m_pool.GetConflictTx(txin.prevout);
        if (ptxConflicting) {
            if (!setConflicts.count(ptxConflicting->GetHash()))
            {
                // Allow opt-out of transaction replacement by setting
                // nSequence > MAX_BIP125_RBF_SEQUENCE (SEQUENCE_FINAL-2) on all inputs.
                //
                // SEQUENCE_FINAL-1 is picked to still allow use of nLockTime by
                // non-replaceable transactions. All inputs rather than just one
                // is for the sake of multi-party protocols, where we don't
                // want a single party to be able to disable replacement.
                //
                // The opt-out ignores descendants as anyone relying on
                // first-seen mempool behavior should be checking all
                // unconfirmed ancestors anyway; doing otherwise is hopelessly
                // insecure.
                bool fReplacementOptOut = true;
                for (const CTxIn &_txin : ptxConflicting->vin)
                {
                    if (_txin.nSequence <= MAX_BIP125_RBF_SEQUENCE)
                    {
                        fReplacementOptOut = false;
                        break;
                    }
                }
                if (fReplacementOptOut) {
                    return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "txn-mempool-conflict");
                }

                setConflicts.insert(ptxConflicting->GetHash());
            }
        }
    }

    LockPoints lp;
    m_view.SetBackend(m_viewmempool);

    CCoinsViewCache& coins_cache = ::ChainstateActive().CoinsTip();

    // do we already have it?
    for (size_t out = 0; out < tx.vout.size(); out++) {
        COutPoint outpoint(hash, out);
        bool had_coin_in_cache = coins_cache.HaveCoinInCache(outpoint);
        if (m_view.HaveCoin(outpoint)) {
            if (!had_coin_in_cache) {
                coins_to_uncache.push_back(outpoint);
            }
            return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-known");
        }
    }

    // do all inputs exist?
    for (const CTxIn& txin : tx.vin) {
        if (!coins_cache.HaveCoinInCache(txin.prevout)) {
            coins_to_uncache.push_back(txin.prevout);
        }

        // Note: this call may add txin.prevout to the coins cache
        // (coins_cache.cacheCoins) by way of FetchCoin(). It should be removed
        // later (via coins_to_uncache) if this tx turns out to be invalid.
        if (!m_view.HaveCoin(txin.prevout)) {
            // Are inputs missing because we already have the tx?
            for (size_t out = 0; out < tx.vout.size(); out++) {
                // Optimistically just do efficient check of cache for outputs
                if (coins_cache.HaveCoinInCache(COutPoint(hash, out))) {
                    return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-known");
                }
            }
            // Otherwise assume this might be an orphan tx for which we just haven't seen parents yet
            return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
        }
    }

    // Bring the best block into scope
    m_view.GetBestBlock();

    // we have all inputs cached now, so switch back to dummy (to protect
    // against bugs where we pull more inputs from disk that miss being added
    // to coins_to_uncache)
    m_view.SetBackend(m_dummy);

    // Only accept BIP68 sequence locked transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
    // CoinsViewCache instead of create its own
    if (!CheckSequenceLocks(m_pool, tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-BIP68-final");

    CAmount nFees = 0;
    if (!Consensus::CheckTxInputs(tx, state, m_view, GetSpendHeight(m_view), nFees)) {
        return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), state.ToString());
    }

    // Check for non-standard pay-to-script-hash in inputs
    if (fRequireStandard && !AreInputsStandard(tx, m_view)) {
        return state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs");
    }

    // Check for non-standard witness in P2WSH
    if (tx.HasWitness() && fRequireStandard && !IsWitnessStandard(tx, m_view))
        return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-witness-nonstandard");

    int64_t nSigOpsCost = GetTransactionSigOpCost(tx, m_view, STANDARD_SCRIPT_VERIFY_FLAGS);

    dev::u256 txMinGasPrice = 0;

    //////////////////////////////////////////////////////////// // qtum
    if(!CheckOpSender(tx, chainparams, GetSpendHeight(m_view))){
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-invalid-sender");
    }
    if(tx.HasCreateOrCall()){

        if(!CheckSenderScript(m_view, tx)){
            return state.Invalid(TxValidationResult::TX_INVALID_SENDER_SCRIPT, "bad-txns-invalid-sender-script");
        }

        QtumDGP qtumDGP(globalState.get(), fGettingValuesDGP);
        uint64_t minGasPrice = qtumDGP.getMinGasPrice(::ChainActive().Tip()->nHeight + 1);
        uint64_t blockGasLimit = qtumDGP.getBlockGasLimit(::ChainActive().Tip()->nHeight + 1);
        size_t count = 0;
        for(const CTxOut& o : tx.vout)
            count += o.scriptPubKey.HasOpCreate() || o.scriptPubKey.HasOpCall() ? 1 : 0;
        unsigned int contractflags = GetContractScriptFlags(GetSpendHeight(m_view), chainparams.GetConsensus());
        QtumTxConverter converter(tx, NULL, NULL, contractflags);
        ExtractQtumTX resultConverter;
        if(!converter.extractionQtumTransactions(resultConverter)){
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-bad-contract-format", "AcceptToMempool(): Contract transaction of the wrong format");
        }
        std::vector<QtumTransaction> qtumTransactions = resultConverter.first;
        std::vector<EthTransactionParams> qtumETP = resultConverter.second;

        dev::u256 sumGas = dev::u256(0);
        dev::u256 gasAllTxs = dev::u256(0);
        for(QtumTransaction qtumTransaction : qtumTransactions){
            sumGas += qtumTransaction.gas() * qtumTransaction.gasPrice();

            if(sumGas > dev::u256(INT64_MAX)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-gas-stipend-overflow", "AcceptToMempool(): Transaction's gas stipend overflows");
            }

            if(sumGas > dev::u256(nFees)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-fee-notenough", "AcceptToMempool(): Transaction fee does not cover the gas stipend");
            }

            if(txMinGasPrice != 0) {
                txMinGasPrice = std::min(txMinGasPrice, qtumTransaction.gasPrice());
            } else {
                txMinGasPrice = qtumTransaction.gasPrice();
            }
            VersionVM v = qtumTransaction.getVersion();
            if(v.format!=0)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-version-format", "AcceptToMempool(): Contract execution uses unknown version format");
            if(v.rootVM != 1)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-version-rootvm", "AcceptToMempool(): Contract execution uses unknown root VM");
            if(v.vmVersion != 0)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-version-vmversion", "AcceptToMempool(): Contract execution uses unknown VM version");
            if(v.flagOptions != 0)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-version-flags", "AcceptToMempool(): Contract execution uses unknown flag options");

            //check gas limit is not less than minimum mempool gas limit
            if(qtumTransaction.gas() < gArgs.GetArg("-minmempoolgaslimit", MEMPOOL_MIN_GAS_LIMIT))
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-too-little-mempool-gas", "AcceptToMempool(): Contract execution has lower gas limit than allowed to accept into mempool");

            //check gas limit is not less than minimum gas limit (unless it is a no-exec tx)
            if(qtumTransaction.gas() < MINIMUM_GAS_LIMIT && v.rootVM != 0)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-too-little-gas", "AcceptToMempool(): Contract execution has lower gas limit than allowed");

            if(qtumTransaction.gas() > UINT32_MAX)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-too-much-gas", "AcceptToMempool(): Contract execution can not specify greater gas limit than can fit in 32-bits");

            gasAllTxs += qtumTransaction.gas();
            if(gasAllTxs > dev::u256(blockGasLimit))
                return state.Invalid(TxValidationResult::TX_GAS_EXCEEDS_LIMIT, "bad-txns-gas-exceeds-blockgaslimit");

            //don't allow less than DGP set minimum gas price to prevent MPoS greedy mining/spammers
            if(v.rootVM!=0 && (uint64_t)qtumTransaction.gasPrice() < minGasPrice)
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-tx-low-gas-price", "AcceptToMempool(): Contract execution has lower gas price than allowed");
        }

        if(!CheckMinGasPrice(qtumETP, minGasPrice))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-small-gasprice");

        if(count > qtumTransactions.size())
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-incorrect-format");

        if (rawTx && nAbsurdFee && dev::u256(nFees) > dev::u256(nAbsurdFee) + sumGas)
            return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "absurdly-high-fee",
                strprintf("%d > %d", nFees, nAbsurdFee));
    }
    ////////////////////////////////////////////////////////////


    // nModifiedFees includes any fee deltas from PrioritiseTransaction
    nModifiedFees = nFees;
    m_pool.ApplyDelta(hash, nModifiedFees);

    // Keep track of transactions that spend a coinbase, which we re-scan
    // during reorgs to ensure COINBASE_MATURITY is still met.
    bool fSpendsCoinbase = false;
    for (const CTxIn &txin : tx.vin) {
        const Coin &coin = m_view.AccessCoin(txin.prevout);
        if (coin.IsCoinBase() || coin.IsCoinStake()) {
            fSpendsCoinbase = true;
            break;
        }
    }

    entry.reset(new CTxMemPoolEntry(ptx, nFees, nAcceptTime, ::ChainActive().Height(),
            fSpendsCoinbase, nSigOpsCost, lp, CAmount(txMinGasPrice)));
    unsigned int nSize = entry->GetTxSize();

    if (nSigOpsCost > dgpMaxTxSigOps)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "bad-txns-too-many-sigops",
                strprintf("%d", nSigOpsCost));

    // No transactions are allowed below minRelayTxFee except from disconnected
    // blocks
    if (!bypass_limits && !CheckFeeRate(nSize, nModifiedFees, state)) return false;

    if (!tx.HasCreateOrCall() && nAbsurdFee && nFees > nAbsurdFee)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD,
                "absurdly-high-fee", strprintf("%d > %d", nFees, nAbsurdFee));

    const CTxMemPool::setEntries setIterConflicting = m_pool.GetIterSet(setConflicts);
    // Calculate in-mempool ancestors, up to a limit.
    if (setConflicts.size() == 1) {
        // In general, when we receive an RBF transaction with mempool conflicts, we want to know whether we
        // would meet the chain limits after the conflicts have been removed. However, there isn't a practical
        // way to do this short of calculating the ancestor and descendant sets with an overlay cache of
        // changed mempool entries. Due to both implementation and runtime complexity concerns, this isn't
        // very realistic, thus we only ensure a limited set of transactions are RBF'able despite mempool
        // conflicts here. Importantly, we need to ensure that some transactions which were accepted using
        // the below carve-out are able to be RBF'ed, without impacting the security the carve-out provides
        // for off-chain contract systems (see link in the comment below).
        //
        // Specifically, the subset of RBF transactions which we allow despite chain limits are those which
        // conflict directly with exactly one other transaction (but may evict children of said transaction),
        // and which are not adding any new mempool dependencies. Note that the "no new mempool dependencies"
        // check is accomplished later, so we don't bother doing anything about it here, but if BIP 125 is
        // amended, we may need to move that check to here instead of removing it wholesale.
        //
        // Such transactions are clearly not merging any existing packages, so we are only concerned with
        // ensuring that (a) no package is growing past the package size (not count) limits and (b) we are
        // not allowing something to effectively use the (below) carve-out spot when it shouldn't be allowed
        // to.
        //
        // To check these we first check if we meet the RBF criteria, above, and increment the descendant
        // limits by the direct conflict and its descendants (as these are recalculated in
        // CalculateMempoolAncestors by assuming the new transaction being added is a new descendant, with no
        // removals, of each parent's existing dependent set). The ancestor count limits are unmodified (as
        // the ancestor limits should be the same for both our new transaction and any conflicts).
        // We don't bother incrementing m_limit_descendants by the full removal count as that limit never comes
        // into force here (as we're only adding a single transaction).
        assert(setIterConflicting.size() == 1);
        CTxMemPool::txiter conflict = *setIterConflicting.begin();

        m_limit_descendants += 1;
        m_limit_descendant_size += conflict->GetSizeWithDescendants();
    }

    std::string errString;
    if (!m_pool.CalculateMemPoolAncestors(*entry, setAncestors, m_limit_ancestors, m_limit_ancestor_size, m_limit_descendants, m_limit_descendant_size, errString)) {
        setAncestors.clear();
        // If CalculateMemPoolAncestors fails second time, we want the original error string.
        std::string dummy_err_string;
        // Contracting/payment channels CPFP carve-out:
        // If the new transaction is relatively small (up to 40k weight)
        // and has at most one ancestor (ie ancestor limit of 2, including
        // the new transaction), allow it if its parent has exactly the
        // descendant limit descendants.
        //
        // This allows protocols which rely on distrusting counterparties
        // being able to broadcast descendants of an unconfirmed transaction
        // to be secure by simply only having two immediately-spendable
        // outputs - one for each counterparty. For more info on the uses for
        // this, see https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-November/016518.html
        if (nSize >  EXTRA_DESCENDANT_TX_SIZE_LIMIT ||
                !m_pool.CalculateMemPoolAncestors(*entry, setAncestors, 2, m_limit_ancestor_size, m_limit_descendants + 1, m_limit_descendant_size + EXTRA_DESCENDANT_TX_SIZE_LIMIT, dummy_err_string)) {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "too-long-mempool-chain", errString);
        }
    }

    // A transaction that spends outputs that would be replaced by it is invalid. Now
    // that we have the set of all ancestors we can detect this
    // pathological case by making sure setConflicts and setAncestors don't
    // intersect.
    for (CTxMemPool::txiter ancestorIt : setAncestors)
    {
        const uint256 &hashAncestor = ancestorIt->GetTx().GetHash();
        if (setConflicts.count(hashAncestor))
        {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-spends-conflicting-tx",
                    strprintf("%s spends conflicting transaction %s",
                        hash.ToString(),
                        hashAncestor.ToString()));
        }
    }

    // Check if it's economically rational to mine this transaction rather
    // than the ones it replaces.
    nConflictingFees = 0;
    nConflictingSize = 0;
    uint64_t nConflictingCount = 0;

    // If we don't hold the lock allConflicting might be incomplete; the
    // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
    // mempool consistency for us.
    fReplacementTransaction = setConflicts.size();
    if (fReplacementTransaction)
    {
        CFeeRate newFeeRate(nModifiedFees, nSize);
        std::set<uint256> setConflictsParents;
        const int maxDescendantsToVisit = 100;
        for (const auto& mi : setIterConflicting) {
            // Don't allow the replacement to reduce the feerate of the
            // mempool.
            //
            // We usually don't want to accept replacements with lower
            // feerates than what they replaced as that would lower the
            // feerate of the next block. Requiring that the feerate always
            // be increased is also an easy-to-reason about way to prevent
            // DoS attacks via replacements.
            //
            // We only consider the feerates of transactions being directly
            // replaced, not their indirect descendants. While that does
            // mean high feerate children are ignored when deciding whether
            // or not to replace, we do require the replacement to pay more
            // overall fees too, mitigating most cases.
            CFeeRate oldFeeRate(mi->GetModifiedFee(), mi->GetTxSize());
            if (newFeeRate <= oldFeeRate)
            {
                return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee",
                        strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                            hash.ToString(),
                            newFeeRate.ToString(),
                            oldFeeRate.ToString()));
            }

            for (const CTxIn &txin : mi->GetTx().vin)
            {
                setConflictsParents.insert(txin.prevout.hash);
            }

            nConflictingCount += mi->GetCountWithDescendants();
        }
        // This potentially overestimates the number of actual descendants
        // but we just want to be conservative to avoid doing too much
        // work.
        if (nConflictingCount <= maxDescendantsToVisit) {
            // If not too many to replace, then calculate the set of
            // transactions that would have to be evicted
            for (CTxMemPool::txiter it : setIterConflicting) {
                m_pool.CalculateDescendants(it, allConflicting);
            }
            for (CTxMemPool::txiter it : allConflicting) {
                nConflictingFees += it->GetModifiedFee();
                nConflictingSize += it->GetTxSize();
            }
        } else {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "too many potential replacements",
                    strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                        hash.ToString(),
                        nConflictingCount,
                        maxDescendantsToVisit));
        }

        for (unsigned int j = 0; j < tx.vin.size(); j++)
        {
            // We don't want to accept replacements that require low
            // feerate junk to be mined first. Ideally we'd keep track of
            // the ancestor feerates and make the decision based on that,
            // but for now requiring all new inputs to be confirmed works.
            //
            // Note that if you relax this to make RBF a little more useful,
            // this may break the CalculateMempoolAncestors RBF relaxation,
            // above. See the comment above the first CalculateMempoolAncestors
            // call for more info.
            if (!setConflictsParents.count(tx.vin[j].prevout.hash))
            {
                // Rather than check the UTXO set - potentially expensive -
                // it's cheaper to just check if the new input refers to a
                // tx that's in the mempool.
                if (m_pool.exists(tx.vin[j].prevout.hash)) {
                    return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "replacement-adds-unconfirmed",
                            strprintf("replacement %s adds unconfirmed input, idx %d",
                                hash.ToString(), j));
                }
            }
        }

        // The replacement must pay greater fees than the transactions it
        // replaces - if we did the bandwidth used by those conflicting
        // transactions would not be paid for.
        if (nModifiedFees < nConflictingFees)
        {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee",
                    strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                        hash.ToString(), FormatMoney(nModifiedFees), FormatMoney(nConflictingFees)));
        }

        // Finally in addition to paying more fees than the conflicts the
        // new transaction must pay for its own bandwidth.
        CAmount nDeltaFees = nModifiedFees - nConflictingFees;
        if (nDeltaFees < ::incrementalRelayFee.GetFee(nSize))
        {
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "insufficient fee",
                    strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                        hash.ToString(),
                        FormatMoney(nDeltaFees),
                        FormatMoney(::incrementalRelayFee.GetFee(nSize))));
        }
    }
    return true;
}

bool MemPoolAccept::PolicyScriptChecks(ATMPArgs& args, Workspace& ws, PrecomputedTransactionData& txdata)
{
    const CTransaction& tx = *ws.m_ptx;

    TxValidationState &state = args.m_state;

    constexpr unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;

    // Check input scripts and signatures.
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.
    if (!CheckInputScripts(tx, state, m_view, scriptVerifyFlags, true, false, txdata)) {
        // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
        // need to turn both off, and compare against just turning off CLEANSTACK
        // to see if the failure is specifically due to witness validation.
        TxValidationState state_dummy; // Want reported failures to be from first CheckInputScripts
        if (!tx.HasWitness() && CheckInputScripts(tx, state_dummy, m_view, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, false, txdata) &&
                !CheckInputScripts(tx, state_dummy, m_view, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, false, txdata)) {
            // Only the witness is missing, so the transaction itself may be fine.
            state.Invalid(TxValidationResult::TX_WITNESS_MUTATED,
                    state.GetRejectReason(), state.GetDebugMessage());
        }
        return false; // state filled in by CheckInputScripts
    }

    return true;
}

bool MemPoolAccept::ConsensusScriptChecks(ATMPArgs& args, Workspace& ws, PrecomputedTransactionData& txdata)
{
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;

    TxValidationState &state = args.m_state;
    const CChainParams& chainparams = args.m_chainparams;

    // Check again against the current block tip's script verification
    // flags to cache our script execution flags. This is, of course,
    // useless if the next block has different script flags from the
    // previous one, but because the cache tracks script flags for us it
    // will auto-invalidate and we'll just have a few blocks of extra
    // misses on soft-fork activation.
    //
    // This is also useful in case of bugs in the standard flags that cause
    // transactions to pass as valid when they're actually invalid. For
    // instance the STRICTENC flag was incorrectly allowing certain
    // CHECKSIG NOT scripts to pass, even though they were invalid.
    //
    // There is a similar check in CreateNewBlock() to prevent creating
    // invalid blocks (using TestBlockValidity), however allowing such
    // transactions into the mempool can be exploited as a DoS attack.
    unsigned int currentBlockScriptVerifyFlags = GetBlockScriptFlags(::ChainActive().Tip(), chainparams.GetConsensus());
    if (!CheckInputsFromMempoolAndCache(tx, state, m_view, m_pool, currentBlockScriptVerifyFlags, txdata)) {
        return error("%s: BUG! PLEASE REPORT THIS! CheckInputScripts failed against latest-block but not STANDARD flags %s, %s",
                __func__, hash.ToString(), state.ToString());
    }

    return true;
}

bool MemPoolAccept::Finalize(ATMPArgs& args, Workspace& ws)
{
    const CTransaction& tx = *ws.m_ptx;
    const uint256& hash = ws.m_hash;
    TxValidationState &state = args.m_state;
    const bool bypass_limits = args.m_bypass_limits;

    CTxMemPool::setEntries& allConflicting = ws.m_all_conflicting;
    CTxMemPool::setEntries& setAncestors = ws.m_ancestors;
    const CAmount& nModifiedFees = ws.m_modified_fees;
    const CAmount& nConflictingFees = ws.m_conflicting_fees;
    const size_t& nConflictingSize = ws.m_conflicting_size;
    const bool fReplacementTransaction = ws.m_replacement_transaction;
    std::unique_ptr<CTxMemPoolEntry>& entry = ws.m_entry;

    // Remove conflicting transactions from the mempool
    for (CTxMemPool::txiter it : allConflicting)
    {
        LogPrint(BCLog::MEMPOOL, "replacing tx %s with %s for %s QTUM additional fees, %d delta bytes\n",
                it->GetTx().GetHash().ToString(),
                hash.ToString(),
                FormatMoney(nModifiedFees - nConflictingFees),
                (int)entry->GetTxSize() - (int)nConflictingSize);
        if (args.m_replaced_transactions)
            args.m_replaced_transactions->push_back(it->GetSharedTx());
    }
    m_pool.RemoveStaged(allConflicting, false, MemPoolRemovalReason::REPLACED);

    // This transaction should only count for fee estimation if:
    // - it isn't a BIP 125 replacement transaction (may not be widely supported)
    // - it's not being re-added during a reorg which bypasses typical mempool fee limits
    // - the node is not behind
    // - the transaction is not dependent on any other transactions in the mempool
    bool validForFeeEstimation = !fReplacementTransaction && !bypass_limits && IsCurrentForFeeEstimation() && m_pool.HasNoInputsOf(tx);

    //////////////////////////////////////////////////////////////// // qtum
    // Add memory address index
    if (fAddressIndex)
    {
        m_pool.addAddressIndex(*entry, m_view);
        m_pool.addSpentIndex(*entry, m_view);
    }
    ////////////////////////////////////////////////////////////////

    // Store transaction in memory
    m_pool.addUnchecked(*entry, setAncestors, validForFeeEstimation);

    // trim mempool and check if tx was trimmed
    if (!bypass_limits) {
        LimitMempoolSize(m_pool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, std::chrono::hours{gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY)});
        if (!m_pool.exists(hash))
            return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool full");
    }
    return true;
}

bool MemPoolAccept::AcceptSingleTransaction(const CTransactionRef& ptx, ATMPArgs& args)
{
    AssertLockHeld(cs_main);
    LOCK(m_pool.cs); // mempool "read lock" (held through GetMainSignals().TransactionAddedToMempool())

    Workspace workspace(ptx);

    if (!PreChecks(args, workspace)) return false;

    // Only compute the precomputed transaction data if we need to verify
    // scripts (ie, other policy checks pass). We perform the inexpensive
    // checks first and avoid hashing and signature verification unless those
    // checks pass, to mitigate CPU exhaustion denial-of-service attacks.
    PrecomputedTransactionData txdata(*ptx);

    if (!PolicyScriptChecks(args, workspace, txdata)) return false;

    if (!ConsensusScriptChecks(args, workspace, txdata)) return false;

    // Tx was accepted, but not added
    if (args.m_test_accept) return true;

    if (!Finalize(args, workspace)) return false;

    GetMainSignals().TransactionAddedToMempool(ptx);

    return true;
}

} // anon namespace

/** (try to) add transaction to memory pool with a specified acceptance time **/
static bool AcceptToMemoryPoolWithTime(const CChainParams& chainparams, CTxMemPool& pool, TxValidationState &state, const CTransactionRef &tx,
                        int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee, bool test_accept, bool rawTx = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    std::vector<COutPoint> coins_to_uncache;
    MemPoolAccept::ATMPArgs args { chainparams, state, nAcceptTime, plTxnReplaced, bypass_limits, nAbsurdFee, coins_to_uncache, test_accept, rawTx };
    bool res = MemPoolAccept(pool).AcceptSingleTransaction(tx, args);
    if (!res) {
        // Remove coins that were not present in the coins cache before calling ATMPW;
        // this is to prevent memory DoS in case we receive a large number of
        // invalid transactions that attempt to overrun the in-memory coins cache
        // (`CCoinsViewCache::cacheCoins`).

        for (const COutPoint& hashTx : coins_to_uncache)
            ::ChainstateActive().CoinsTip().Uncache(hashTx);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    BlockValidationState state_dummy;
    ::ChainstateActive().FlushStateToDisk(chainparams, state_dummy, FlushStateMode::PERIODIC);
    return res;
}

bool IsConfirmedInNPrevBlocks(const CDiskTxPos& txindex, const CBlockIndex* pindexFrom, int nMaxDepth, int& nActualDepth)
{
    for (const CBlockIndex* pindex = pindexFrom; pindex && pindexFrom->nHeight - pindex->nHeight < nMaxDepth; pindex = pindex->pprev)
    {
        if (pindex->nDataPos == txindex.nPos && pindex->nFile == txindex.nFile)
        {
            nActualDepth = pindexFrom->nHeight - pindex->nHeight;
            return true;
        }
    }
    return false;
}

bool AcceptToMemoryPool(CTxMemPool& pool, TxValidationState &state, const CTransactionRef &tx,
                        std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee, bool test_accept, bool rawTx)
{
    const CChainParams& chainparams = Params();
    return AcceptToMemoryPoolWithTime(chainparams, pool, state, tx, GetTime(), plTxnReplaced, bypass_limits, nAbsurdFee, test_accept, rawTx);
}

/**
 * Return transaction in txOut, and if it was found inside a block, its hash is placed in hashBlock.
 * If blockIndex is provided, the transaction is fetched from the corresponding block.
 */
bool GetTransaction(const uint256& hash, CTransactionRef& txOut, const Consensus::Params& consensusParams, uint256& hashBlock, const CBlockIndex* const block_index, bool fAllowSlow)
{
    CBlockIndex* pindexSlow = (CBlockIndex*)block_index;

    LOCK(cs_main);

    if (!block_index) {
        CTransactionRef ptx = mempool.get(hash);
        if (ptx) {
            txOut = ptx;
            return true;
        }

        if (g_txindex) {
            return g_txindex->FindTx(hash, hashBlock, txOut);
        }

        if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
            const Coin& coin = AccessByTxid(::ChainstateActive().CoinsTip(), hash);
            if (!coin.IsSpent()) pindexSlow = ::ChainActive()[coin.nHeight];
        }
    }

    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}

bool CheckHeaderPoW(const CBlockHeader& block, const Consensus::Params& consensusParams)
{
    // Check for proof of work block header
    return CheckProofOfWork(block.GetHash(), block.nBits, consensusParams);
}

bool CheckHeaderPoS(const CBlockHeader& block, const Consensus::Params& consensusParams)
{
    // Check for proof of stake block header
    // Get prev block index
    BlockMap::iterator mi = ::BlockIndex().find(block.hashPrevBlock);
    if (mi == ::BlockIndex().end())
        return false;

    // Check the kernel hash
    CBlockIndex* pindexPrev = (*mi).second;

    if(pindexPrev->nHeight >= consensusParams.nEnableHeaderSignatureHeight && !CheckRecoveredPubKeyFromBlockSignature(pindexPrev, block, ::ChainstateActive().CoinsTip())) {
        return error("Failed signature check");
    }

    return CheckKernel(pindexPrev, block.nBits, block.StakeTime(), block.prevoutStake, ::ChainstateActive().CoinsTip());
}

bool CheckHeaderProof(const CBlockHeader& block, const Consensus::Params& consensusParams){
    if(block.IsProofOfWork()){
        return CheckHeaderPoW(block, consensusParams);
    }
    if(block.IsProofOfStake()){
        return CheckHeaderPoS(block, consensusParams);
    }
    return false;
}

bool CheckIndexProof(const CBlockIndex& block, const Consensus::Params& consensusParams)
{
    // Get the hash of the proof
    // After validating the PoS block the computed hash proof is saved in the block index, which is used to check the index
    uint256 hashProof = block.IsProofOfWork() ? block.GetBlockHash() : block.hashProof;
    // Check for proof after the hash proof is computed
    if(block.IsProofOfStake()){
        //blocks are loaded out of order, so checking PoS kernels here is not practical
        return true; //CheckKernel(block.pprev, block.nBits, block.nTime, block.prevoutStake);
    }else{
        return CheckProofOfWork(hashProof, block.nBits, consensusParams, false);
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static bool WriteBlockToDisk(const CBlock& block, FlatFilePos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = GetSerializeSize(block, fileout.GetVersion());
    fileout << messageStart << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

template <typename Block>
bool ReadBlockFromDisk(Block& block, const FlatFilePos& pos, const Consensus::Params& consensusParams)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check the header
    if(!block.IsProofOfStake()) {
        //PoS blocks can be loaded out of order from disk, which makes PoS impossible to validate. So, do not validate their headers
        //they will be validated later in CheckBlock and ConnectBlock anyway
        if (!CheckHeaderProof(block, consensusParams))
            return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());
    }
    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    FlatFilePos blockPos;
    {
        LOCK(cs_main);
        blockPos = pindex->GetBlockPos();
    }

    if (!ReadBlockFromDisk(block, blockPos, consensusParams))
        return false;
    if (block.GetHash() != pindex->GetBlockHash())
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
                pindex->ToString(), pindex->GetBlockPos().ToString());
    return true;
}

bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const FlatFilePos& pos, const CMessageHeader::MessageStartChars& message_start)
{
    FlatFilePos hpos = pos;
    hpos.nPos -= 8; // Seek back 8 bytes for meta header
    CAutoFile filein(OpenBlockFile(hpos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        return error("%s: OpenBlockFile failed for %s", __func__, pos.ToString());
    }

    try {
        CMessageHeader::MessageStartChars blk_start;
        unsigned int blk_size;

        filein >> blk_start >> blk_size;

        if (memcmp(blk_start, message_start, CMessageHeader::MESSAGE_START_SIZE)) {
            return error("%s: Block magic mismatch for %s: %s versus expected %s", __func__, pos.ToString(),
                    HexStr(blk_start, blk_start + CMessageHeader::MESSAGE_START_SIZE),
                    HexStr(message_start, message_start + CMessageHeader::MESSAGE_START_SIZE));
        }

        if (blk_size > MAX_SIZE) {
            return error("%s: Block data is larger than maximum deserialization size for %s: %s versus %s", __func__, pos.ToString(),
                    blk_size, MAX_SIZE);
        }

        block.resize(blk_size); // Zeroing of memory is intentional here
        filein.read((char*)block.data(), blk_size);
    } catch(const std::exception& e) {
        return error("%s: Read from block file failed: %s for %s", __func__, e.what(), pos.ToString());
    }

    return true;
}

bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const CBlockIndex* pindex, const CMessageHeader::MessageStartChars& message_start)
{
    FlatFilePos block_pos;
    {
        LOCK(cs_main);
        block_pos = pindex->GetBlockPos();
    }

    return ReadRawBlockFromDisk(block, block_pos, message_start);
}

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    if(nHeight <= consensusParams.nLastBigReward)
        return 20000 * COIN;

    int halvings = (nHeight - consensusParams.nLastBigReward - 1) / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 7)
        return 0;

    CAmount nSubsidy = 4 * COIN;
    // Subsidy is cut in half every 985500 blocks which will occur approximately every 4 years.
    nSubsidy >>= halvings;
    return nSubsidy;
}

CoinsViews::CoinsViews(
    std::string ldb_name,
    size_t cache_size_bytes,
    bool in_memory,
    bool should_wipe) : m_dbview(
                            GetDataDir() / ldb_name, cache_size_bytes, in_memory, should_wipe),
                        m_catcherview(&m_dbview) {}

void CoinsViews::InitCache()
{
    m_cacheview = MakeUnique<CCoinsViewCache>(&m_catcherview);
}

// NOTE: for now m_blockman is set to a global, but this will be changed
// in a future commit.
CChainState::CChainState() : m_blockman(g_blockman) {}


void CChainState::InitCoinsDB(
    size_t cache_size_bytes,
    bool in_memory,
    bool should_wipe,
    std::string leveldb_name)
{
    m_coins_views = MakeUnique<CoinsViews>(
        leveldb_name, cache_size_bytes, in_memory, should_wipe);
}

void CChainState::InitCoinsCache()
{
    assert(m_coins_views != nullptr);
    m_coins_views->InitCache();
}

// Note that though this is marked const, we may end up modifying `m_cached_finished_ibd`, which
// is a performance-related implementation detail. This function must be marked
// `const` so that `CValidationInterface` clients (which are given a `const CChainState*`)
// can call it.
//
bool CChainState::IsInitialBlockDownload() const
{
    // Optimization: pre-test latch before taking the lock.
    if (m_cached_finished_ibd.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (m_cached_finished_ibd.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (m_chain.Tip() == nullptr)
        return true;
    if (m_chain.Tip()->nChainWork < nMinimumChainWork)
        return true;
    if (m_chain.Tip()->GetBlockTime() < (GetTime() - nMaxTipAge))
        return true;
    LogPrintf("Leaving InitialBlockDownload (latching to false)\n");
    m_cached_finished_ibd.store(true, std::memory_order_relaxed);
    return false;
}

static CBlockIndex *pindexBestForkTip = nullptr, *pindexBestForkBase = nullptr;

BlockMap& BlockIndex()
{
    return g_blockman.m_block_index;
}

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
#if HAVE_SYSTEM
    std::string strCmd = gArgs.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    std::thread t(runCommand, strCmd);
    t.detach(); // thread runs free
#endif
}

static void CheckForkWarningConditions() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (::ChainstateActive().IsInitialBlockDownload())
        return;

    // If our best fork is no longer within 72 blocks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && ::ChainActive().Height() - pindexBestForkTip->nHeight >= 72)
        pindexBestForkTip = nullptr;

    if (pindexBestForkTip || (pindexBestInvalid && pindexBestInvalid->nChainWork > ::ChainActive().Tip()->nChainWork + (GetBlockProof(*::ChainActive().Tip()) * 6)))
    {
        if (!GetfLargeWorkForkFound() && pindexBestForkBase)
        {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                pindexBestForkBase->phashBlock->ToString() + std::string("'");
            AlertNotify(warning);
        }
        if (pindexBestForkTip && pindexBestForkBase)
        {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n", __func__,
                   pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                   pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
            SetfLargeWorkForkFound(true);
        }
        else
        {
            LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
            SetfLargeWorkInvalidChainFound(true);
        }
    }
    else
    {
        SetfLargeWorkForkFound(false);
        SetfLargeWorkInvalidChainFound(false);
    }
}

static void CheckForkWarningConditionsOnNewFork(CBlockIndex* pindexNewForkTip) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex* pfork = pindexNewForkTip;
    CBlockIndex* plonger = ::ChainActive().Tip();
    while (pfork && pfork != plonger)
    {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 12 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pindexBestForkTip || pindexNewForkTip->nHeight > pindexBestForkTip->nHeight) &&
            pindexNewForkTip->nChainWork - pfork->nChainWork > (GetBlockProof(*pfork) * 7) &&
            ::ChainActive().Height() - pindexNewForkTip->nHeight < 72)
    {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

// Called both upon regular invalid block discovery *and* InvalidateBlock
void static InvalidChainFound(CBlockIndex* pindexNew) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!pindexBestInvalid || pindexNew->nChainWork > pindexBestInvalid->nChainWork)
        pindexBestInvalid = pindexNew;
    if (pindexBestHeader != nullptr && pindexBestHeader->GetAncestor(pindexNew->nHeight) == pindexNew) {
        pindexBestHeader = ::ChainActive().Tip();
    }

    LogPrintf("%s: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
      log(pindexNew->nChainWork.getdouble())/log(2.0), FormatISO8601DateTime(pindexNew->GetBlockTime()));
    CBlockIndex *tip = ::ChainActive().Tip();
    assert (tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      tip->GetBlockHash().ToString(), ::ChainActive().Height(), log(tip->nChainWork.getdouble())/log(2.0),
      FormatISO8601DateTime(tip->GetBlockTime()));
    CheckForkWarningConditions();
}

// Same as InvalidChainFound, above, except not called directly from InvalidateBlock,
// which does its own setBlockIndexCandidates manageent.
void CChainState::InvalidBlockFound(CBlockIndex *pindex, const BlockValidationState &state) {
    if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        m_blockman.m_failed_blocks.insert(pindex);
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn &txin : tx.vin) {
            txundo.vprevout.emplace_back();
            bool is_spent = inputs.SpendCoin(txin.prevout, &txundo.vprevout.back());
            assert(is_spent);
        }
    }
    // add outputs
    AddCoins(inputs, tx, nHeight);
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight)
{
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}

bool CScriptCheck::operator()() {
    if(checkOutput())
    {
        // Check the sender signature inside the output, used to identify VM sender
        CScript senderPubKey, senderSig;
        if(!ExtractSenderData(ptxTo->vout[nOut].scriptPubKey, &senderPubKey, &senderSig))
            return false;
        return VerifyScript(senderSig, senderPubKey, nullptr, nFlags, CachingTransactionSignatureOutputChecker(ptxTo, nOut, ptxTo->vout[nOut].nValue, cacheStore, *txdata), &error);
    }

    // Check the input signature
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness *witness = &ptxTo->vin[nIn].scriptWitness;
    return VerifyScript(scriptSig, m_tx_out.scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, m_tx_out.nValue, cacheStore, *txdata), &error);
}

int GetSpendHeight(const CCoinsViewCache& inputs)
{
    LOCK(cs_main);
    CBlockIndex* pindexPrev = LookupBlockIndex(inputs.GetBestBlock());
    return pindexPrev->nHeight + 1;
}


static CuckooCache::cache<uint256, SignatureCacheHasher> scriptExecutionCache;
static uint256 scriptExecutionCacheNonce(GetRandHash());

void InitScriptExecutionCache() {
    // nMaxCacheSize is unsigned. If -maxsigcachesize is set to zero,
    // setup_bytes creates the minimum possible cache (2 elements).
    size_t nMaxCacheSize = std::min(std::max((int64_t)0, gArgs.GetArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE) / 2), MAX_MAX_SIG_CACHE_SIZE) * ((size_t) 1 << 20);
    size_t nElems = scriptExecutionCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu/2 requested for script execution cache, able to store %zu elements\n",
            (nElems*sizeof(uint256)) >>20, (nMaxCacheSize*2)>>20, nElems);
}

/**
 * Check whether all of this transaction's input scripts succeed.
 *
 * This involves ECDSA signature checks so can be computationally intensive. This function should
 * only be called after the cheap sanity checks in CheckTxInputs passed.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being performed inline. Any
 * script checks which are not necessary (eg due to script execution cache hits) are, obviously,
 * not pushed onto pvChecks/run.
 *
 * Setting cacheSigStore/cacheFullScriptStore to false will remove elements from the corresponding cache
 * which are matched. This is useful for checking blocks where we will likely never need the cache
 * entry again.
 *
 * Note that we may set state.reason to NOT_STANDARD for extra soft-fork flags in flags, block-checking
 * callers should probably reset it to CONSENSUS in such cases.
 *
 * Non-static (and re-declared) in src/test/txvalidationcache_tests.cpp
 */
bool CheckInputScripts(const CTransaction& tx, TxValidationState &state, const CCoinsViewCache &inputs, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (tx.IsCoinBase()) return true;

    if (pvChecks) {
        pvChecks->reserve(tx.vin.size());
    }

    // First check if script executions have been cached with the same
    // flags. Note that this assumes that the inputs provided are
    // correct (ie that the transaction hash which is in tx's prevouts
    // properly commits to the scriptPubKey in the inputs view of that
    // transaction).
    uint256 hashCacheEntry;
    // We only use the first 19 bytes of nonce to avoid a second SHA
    // round - giving us 19 + 32 + 4 = 55 bytes (+ 8 + 1 = 64)
    static_assert(55 - sizeof(flags) - 32 >= 128/8, "Want at least 128 bits of nonce for script execution cache");
    CSHA256().Write(scriptExecutionCacheNonce.begin(), 55 - sizeof(flags) - 32).Write(tx.GetWitnessHash().begin(), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(hashCacheEntry.begin());
    AssertLockHeld(cs_main); //TODO: Remove this requirement by making CuckooCache not require external locks
    if (scriptExecutionCache.contains(hashCacheEntry, !cacheFullScriptStore)) {
        return true;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // We very carefully only pass in things to CScriptCheck which
        // are clearly committed to by tx' witness hash. This provides
        // a sanity check that our caching is not introducing consensus
        // failures through additional data in, eg, the coins being
        // spent being checked as a part of CScriptCheck.

        // Verify signature
        CScriptCheck check(coin.out, tx, i, flags, cacheSigStore, &txdata);
        if (pvChecks) {
            pvChecks->push_back(CScriptCheck());
            check.swap(pvChecks->back());
        } else if (!check()) {
            if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                // Check whether the failure was caused by a
                // non-mandatory script verification check, such as
                // non-standard DER encodings or non-null dummy
                // arguments; if so, ensure we return NOT_STANDARD
                // instead of CONSENSUS to avoid downstream users
                // splitting the network between upgraded and
                // non-upgraded nodes by banning CONSENSUS-failing
                // data providers.
                CScriptCheck check2(coin.out, tx, i,
                        flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheSigStore, &txdata);
                if (check2())
                    return state.Invalid(TxValidationResult::TX_NOT_STANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
            }
            // MANDATORY flag failures correspond to
            // TxValidationResult::TX_CONSENSUS. Because CONSENSUS
            // failures are the most serious case of validation
            // failures, we may need to consider using
            // RECENT_CONSENSUS_CHANGE for any script failure that
            // could be due to non-upgraded nodes which we may want to
            // support, to avoid splitting the network (but this
            // depends on the details of how net_processing handles
            // such errors).
            return state.Invalid(TxValidationResult::TX_CONSENSUS, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
        }
    }

    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        // Verify sender output signature
        if(tx.vout[i].scriptPubKey.HasOpSender())
        {
            CScriptCheck check(tx, i, 0, cacheSigStore, &txdata);
            if (pvChecks) {
                pvChecks->push_back(CScriptCheck());
                check.swap(pvChecks->back());
            } else if (!check()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, strprintf("sender-output-script-verify-failed (%s)", ScriptErrorString(check.GetScriptError())));
            }
        }
    }


    if (cacheFullScriptStore && !pvChecks) {
        // We executed all of the provided scripts, and were told to
        // cache the result. Do so now.
        scriptExecutionCache.insert(hashCacheEntry);
    }

    return true;
}

static bool UndoWriteToDisk(const CBlockUndo& blockundo, FlatFilePos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(blockundo, fileout.GetVersion());
    fileout << messageStart << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

bool UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex* pindex)
{
    FlatFilePos pos = pindex->GetUndoPos();
    if (pos.IsNull()) {
        return error("%s: no undo data available", __func__);
    }

    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein); // We need a CHashVerifier as reserializing may lose data
    try {
        verifier << pindex->pprev->GetBlockHash();
        verifier >> blockundo;
        filein >> hashChecksum;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

/** Abort with a message */
static bool AbortNode(const std::string& strMessage, const std::string& userMessage = "", unsigned int prefix = 0)
{
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    if (!userMessage.empty()) {
        uiInterface.ThreadSafeMessageBox(userMessage, "", CClientUIInterface::MSG_ERROR | prefix);
    } else {
        uiInterface.ThreadSafeMessageBox(_("Error: A fatal internal error occurred, see debug.log for details").translated, "", CClientUIInterface::MSG_ERROR | CClientUIInterface::MSG_NOPREFIX);
    }
    StartShutdown();
    return false;
}

static bool AbortNode(BlockValidationState& state, const std::string& strMessage, const std::string& userMessage = "", unsigned int prefix = 0)
{
    AbortNode(strMessage, userMessage, prefix);
    return state.Error(strMessage);
}

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    // The potential_overwrite parameter to AddCoin is only allowed to be false if we know for
    // sure that the coin did not already exist in the cache. As we have queried for that above
    // using HaveCoin, we don't need to guess. When fClean is false, a coin already existed and
    // it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */
DisconnectResult CChainState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view, bool* pfClean)
{
    assert(pindex->GetBlockHash() == view.GetBestBlock());
    if (pfClean)
        *pfClean = false;
    bool fClean = true;

    CBlockUndo blockUndo;
    if (!UndoReadFromDisk(blockUndo, pindex)) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("DisconnectBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }

    /////////////////////////////////////////////////////////// // qtum
    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > addressUnspentIndex;
    ///////////////////////////////////////////////////////////

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();
        bool is_coinbase = tx.IsCoinBase();
        bool is_coinstake = tx.IsCoinStake();

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                COutPoint out(hash, o);
                Coin coin;
                bool is_spent = view.SpendCoin(out, &coin);
                if (!is_spent || tx.vout[o] != coin.out || pindex->nHeight != coin.nHeight || is_coinbase != coin.fCoinBase || is_coinstake != coin.fCoinStake) {
                    fClean = false; // transaction output mismatch
                }
            }
        }

        /////////////////////////////////////////////////////////// // qtum
        if (pfClean == NULL && fAddressIndex) {

            for (unsigned int k = tx.vout.size(); k-- > 0;) {
                const CTxOut &out = tx.vout[k];

                CTxDestination dest;
                if (ExtractDestination({hash, k}, out.scriptPubKey, dest)) {
                    valtype bytesID(boost::apply_visitor(DataVisitor(), dest));
                    if(bytesID.empty()) {
                        continue;
                    }
                    valtype addressBytes(32);
                    std::copy(bytesID.begin(), bytesID.end(), addressBytes.begin());
                    // undo receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(dest.which(), uint256(addressBytes), pindex->nHeight, i, hash, k, false), out.nValue));
                    // undo unspent index
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(dest.which(), uint256(addressBytes), hash, k), CAddressUnspentValue()));
                }
            }
        }
        ///////////////////////////////////////////////////////////

        // restore inputs
        if (i > 0) { // not coinbases
            CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                error("DisconnectBlock(): transaction and undo data inconsistent");
                return DISCONNECT_FAILED;
            }
            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                fClean = fClean && res != DISCONNECT_UNCLEAN;

                if (pfClean == NULL && fAddressIndex) {
                    const auto &undo = txundo.vprevout[j];
                    const bool isTxCoinStake = tx.IsCoinStake();
                    const CTxIn input = tx.vin[j];
                    const CTxOut &prevout = view.GetOutputFor(input);

                    CTxDestination dest;
                    if (ExtractDestination(input.prevout, prevout.scriptPubKey, dest)) {
                        valtype bytesID(boost::apply_visitor(DataVisitor(), dest));
                        if(bytesID.empty()) {
                            continue;
                        }
                        valtype addressBytes(32);
                        std::copy(bytesID.begin(), bytesID.end(), addressBytes.begin());
                        // undo spending activity
                        addressIndex.push_back(std::make_pair(CAddressIndexKey(dest.which(), uint256(addressBytes), pindex->nHeight, i, hash, j, true), prevout.nValue * -1));
                        // restore unspent index
                        addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(dest.which(), uint256(addressBytes), input.prevout.hash, input.prevout.n), CAddressUnspentValue(prevout.nValue, prevout.scriptPubKey, undo.nHeight, isTxCoinStake)));
                    }
                }
            }
            // At this point, all of txundo.vprevout should have been moved out.
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    globalState->setRoot(uintToh256(pindex->pprev->hashStateRoot)); // qtum
    globalState->setRootUTXO(uintToh256(pindex->pprev->hashUTXORoot)); // qtum

    if(pfClean == NULL && fLogEvents){
        pstorageresult->deleteResults(block.vtx);
        pblocktree->EraseHeightIndex(pindex->nHeight);
    }

    // The stake and delegate index is needed for MPoS, update it while MPoS is active
    const CChainParams& chainparams = Params();
    if(pindex->nHeight <= chainparams.GetConsensus().nLastMPoSBlock)
    {
        pblocktree->EraseStakeIndex(pindex->nHeight);
        if(pindex->IsProofOfStake() && pindex->HasProofOfDelegation())
            pblocktree->EraseDelegateIndex(pindex->nHeight);
    }

    //////////////////////////////////////////////////// // qtum
    if (pfClean == NULL && fAddressIndex) {
        if (!pblocktree->EraseAddressIndex(addressIndex)) {
            error("Failed to delete address index");
            return DISCONNECT_FAILED;
        }
        if (!pblocktree->UpdateAddressUnspentIndex(addressUnspentIndex)) {
            error("Failed to write address unspent index");
            return DISCONNECT_FAILED;
        }
    }
    ////////////////////////////////////////////////////

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    FlatFilePos block_pos_old(nLastBlockFile, vinfoBlockFile[nLastBlockFile].nSize);
    FlatFilePos undo_pos_old(nLastBlockFile, vinfoBlockFile[nLastBlockFile].nUndoSize);

    bool status = true;
    status &= BlockFileSeq().Flush(block_pos_old, fFinalize);
    status &= UndoFileSeq().Flush(undo_pos_old, fFinalize);
    if (!status) {
        AbortNode("Flushing block file to disk failed. This is likely the result of an I/O error.");
    }
}

static bool FindUndoPos(BlockValidationState &state, int nFile, FlatFilePos &pos, unsigned int nAddSize);

static bool WriteUndoDataForBlock(const CBlockUndo& blockundo, BlockValidationState& state, CBlockIndex* pindex, const CChainParams& chainparams)
{
    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull()) {
        FlatFilePos _pos;
        if (!FindUndoPos(state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, CLIENT_VERSION) + 40))
            return error("ConnectBlock(): FindUndoPos failed");
        if (!UndoWriteToDisk(blockundo, _pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
            return AbortNode(state, "Failed to write undo data");

        // update nUndoPos in block index
        pindex->nUndoPos = _pos.nPos;
        pindex->nStatus |= BLOCK_HAVE_UNDO;
        setDirtyBlockIndex.insert(pindex);
    }

    return true;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck(int worker_num) {
    util::ThreadRename(strprintf("scriptch.%i", worker_num));
    scriptcheckqueue.Thread();
}

VersionBitsCache versionbitscache GUARDED_BY(cs_main);

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        ThresholdState state = VersionBitsState(pindexPrev, params, static_cast<Consensus::DeploymentPos>(i), versionbitscache);
        if (state == ThresholdState::LOCKED_IN || state == ThresholdState::STARTED) {
            nVersion |= VersionBitsMask(params, static_cast<Consensus::DeploymentPos>(i));
        }
    }

    return nVersion;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    explicit WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const override { return 0; }
    int64_t EndTime(const Consensus::Params& params) const override { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const override { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const override { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override
    {
        return pindex->nHeight >= params.MinBIP9WarningHeight &&
               ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((ComputeBlockVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS] GUARDED_BY(cs_main);

// 0.13.0 was shipped with a segwit deployment defined for testnet, but not for
// mainnet. We no longer need to support disabling the segwit deployment
// except for testing purposes, due to limitations of the functional test
// environment. See test/functional/p2p-segwit.py.
static bool IsScriptWitnessEnabled(const Consensus::Params& params)
{
    return params.SegwitHeight != std::numeric_limits<int>::max();
}

static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& consensusparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);

    unsigned int flags = SCRIPT_VERIFY_NONE;

    // BIP16 didn't become active until Apr 1 2012 (on mainnet, and
    // retroactively applied to testnet)
    // However, only one historical block violated the P2SH rules (on both
    // mainnet and testnet), so for simplicity, always leave P2SH
    // on except for the one violating block.
    if (consensusparams.BIP16Exception.IsNull() || // no bip16 exception on this chain
        pindex->phashBlock == nullptr || // this is a new candidate block, eg from TestBlockValidity()
        *pindex->phashBlock != consensusparams.BIP16Exception) // this block isn't the historical exception
    {
        flags |= SCRIPT_VERIFY_P2SH;
    }

    // Enforce WITNESS rules whenever P2SH is in effect (and the segwit
    // deployment is defined).
    if (flags & SCRIPT_VERIFY_P2SH && IsScriptWitnessEnabled(consensusparams)) {
        flags |= SCRIPT_VERIFY_WITNESS;
    }

    // Start enforcing the DERSIG (BIP66) rule
    if (pindex->nHeight >= consensusparams.BIP66Height) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY (BIP65) rule
    if (pindex->nHeight >= consensusparams.BIP65Height) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP112 (CHECKSEQUENCEVERIFY)
    if (pindex->nHeight >= consensusparams.CSVHeight) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    // Start enforcing BIP147 NULLDUMMY (activated simultaneously with segwit)
    if (IsWitnessEnabled(pindex->pprev, consensusparams)) {
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    // Start support sender address in contract output
    if (pindex->nHeight >= consensusparams.QIP5Height) {
        flags |= SCRIPT_OUTPUT_SENDER;
    }

    return flags;
}

unsigned int GetContractScriptFlags(int nHeight, const Consensus::Params& consensusparams) {
    unsigned int flags = SCRIPT_EXEC_BYTE_CODE;

    // Start support sender address in contract output
    if (nHeight >= consensusparams.QIP5Height) {
        flags |= SCRIPT_OUTPUT_SENDER;
    }

    return flags;
}


static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;
static int64_t nBlocksTotal = 0;

/////////////////////////////////////////////////////////////////////// qtum
bool GetSpentCoinFromBlock(const CBlockIndex* pindex, COutPoint prevout, Coin* coin) {
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
        return error("GetSpentCoinFromBlock(): Could not read block from disk");
    }

    for(size_t j = 1; j < block.vtx.size(); ++j) {
        CTransactionRef& tx = block.vtx[j];
        for(size_t k = 0; k < tx->vin.size(); ++k) {
            const COutPoint& tmpprevout = tx->vin[k].prevout;
            if(tmpprevout == prevout) {
                CBlockUndo undo;
                if(!UndoReadFromDisk(undo, pindex)) {
                    return error("GetSpentCoinFromBlock(): Could not read undo block from disk");
                }

                if(undo.vtxundo.size() != block.vtx.size() - 1) {
                    return error("GetSpentCoinFromBlock(): undo tx size not equal to block tx size");
                }

                CTxUndo &txundo = undo.vtxundo[j-1]; // no vtxundo for coinbase

                if(txundo.vprevout.size() != tx->vin.size()) {
                    return error("GetSpentCoinFromBlock(): undo tx vin size not equal to block tx vin size");
                }

                *coin = txundo.vprevout[k];
                return true;
            }

        }
    }
    return false;
}

bool GetSpentCoinFromMainChain(const CBlockIndex* pforkPrev, COutPoint prevoutStake, Coin* coin) {
    const CBlockIndex* pforkBase = ChainActive().FindFork(pforkPrev);

    // If the forkbase is more than COINBASE_MATURITY blocks in the past, do not attempt to scan the main chain.
    if(ChainActive().Tip()->nHeight - pforkBase->nHeight > COINBASE_MATURITY) {
        return error("The fork's base is behind by more than 500 blocks");
    }

    // First, we make sure that the prevout has not been spent in any of pforktip's ancestors as the prevoutStake.
    // This is done to prevent a single staker building a long chain based on only a single prevout.
    {
        const CBlockIndex* pindex = pforkPrev;
        while(pindex && pindex != pforkBase) {
            // The coinstake has already been spent in the fork.
            if(pindex->prevoutStake == prevoutStake) {
                return error("prevout already spent in the orphan chain");
            }
            pindex = pindex->pprev;
        }
    }

    // Scan through blocks until we reach the forkbase to check if the prevoutStake has been spent in one of those blocks
    // If it not in any of those blocks, and not in the utxo set, it can't be spendable in the orphan chain.
    {
        CBlockIndex* pindex = ChainActive().Tip();
        while(pindex && pindex != pforkBase) {
            if(GetSpentCoinFromBlock(pindex, prevoutStake, coin)) {
                return true;
            }
            pindex = pindex->pprev;
        }
    }

    return false;
}

bool CheckOpSender(const CTransaction& tx, const CChainParams& chainparams, int nHeight){
    if(!tx.HasOpSender())
        return true;

    if(!(nHeight >= chainparams.GetConsensus().QIP5Height))
        return false;

    // Check that the sender address inside the output is only valid for contract outputs
    for (const CTxOut& txout : tx.vout)
    {
        bool hashOpSender = txout.scriptPubKey.HasOpSender();
        if(hashOpSender &&
                !(txout.scriptPubKey.HasOpCreate() ||
                  txout.scriptPubKey.HasOpCall()))
        {
            return false;
        }

        // Solve the script that match the sender templates
        if(hashOpSender && !ExtractSenderData(txout.scriptPubKey, nullptr, nullptr))
            return false;
    }

    return true;
}

bool CheckSenderScript(const CCoinsViewCache& view, const CTransaction& tx){
    // Check for the sender that pays the coins
    CScript script = view.AccessCoin(tx.vin[0].prevout).out.scriptPubKey;
    if(!script.IsPayToPubkeyHash() && !script.IsPayToPubkey()){
        return false;
    }

    // Check for additional VM sender
    if(!tx.HasOpSender())
        return true;

    // Check for the VM sender that is encoded into the output
    for (const CTxOut& txout : tx.vout)
    {
        if(txout.scriptPubKey.HasOpSender())
        {
            // Extract the sender data
            CScript senderPubKey, senderSig;
            if(!ExtractSenderData(txout.scriptPubKey, &senderPubKey, &senderSig))
                return false;

            // Check that the pub key is valid sender that can be used in the VM
            if(!senderPubKey.IsPayToPubkeyHash() && !senderPubKey.IsPayToPubkey())
                return false;

            // Get the signature stack
            std::vector <std::vector<unsigned char> > stack;
            if (!EvalScript(stack, senderSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;

            // Check that the signature script contains only signature and public key (2 items)
            if(stack.size() != STANDARD_SENDER_STACK_ITEMS)
                return false;

            // Check that the items size is no more than 80 bytes
            for(size_t i=0; i < stack.size(); i++)
            {
                if(stack[i].size() > MAX_STANDARD_SENDER_STACK_ITEM_SIZE)
                    return false;
            }
        }
    }

    return true;
}

std::vector<ResultExecute> CallContract(const dev::Address& addrContract, std::vector<unsigned char> opcode, const dev::Address& sender, uint64_t gasLimit, CAmount nAmount){
    CBlock block;
    CMutableTransaction tx;

    CBlockIndex* pblockindex = ::BlockIndex()[::ChainActive().Tip()->GetBlockHash()];
    ReadBlockFromDisk(block, pblockindex, Params().GetConsensus());
    block.nTime = GetAdjustedTime();

    if(block.IsProofOfStake())
    	block.vtx.erase(block.vtx.begin()+2,block.vtx.end());
    else
    	block.vtx.erase(block.vtx.begin()+1,block.vtx.end());

    QtumDGP qtumDGP(globalState.get(), fGettingValuesDGP);
    uint64_t blockGasLimit = qtumDGP.getBlockGasLimit(::ChainActive().Tip()->nHeight + 1);

    if(gasLimit == 0){
        gasLimit = blockGasLimit - 1;
    }
    dev::Address senderAddress = sender == dev::Address() ? dev::Address("ffffffffffffffffffffffffffffffffffffffff") : sender;
    tx.vout.push_back(CTxOut(nAmount, CScript() << OP_DUP << OP_HASH160 << senderAddress.asBytes() << OP_EQUALVERIFY << OP_CHECKSIG));
    block.vtx.push_back(MakeTransactionRef(CTransaction(tx)));
 
    QtumTransaction callTransaction;
    if(addrContract == dev::Address())
    {
        callTransaction = QtumTransaction(nAmount, 1, dev::u256(gasLimit), opcode, dev::u256(0));
    }
    else
    {
        callTransaction = QtumTransaction(nAmount, 1, dev::u256(gasLimit), addrContract, opcode, dev::u256(0));
    }
    callTransaction.forceSender(senderAddress);
    callTransaction.setVersion(VersionVM::GetEVMDefault());

    
    ByteCodeExec exec(block, std::vector<QtumTransaction>(1, callTransaction), blockGasLimit, pblockindex);
    exec.performByteCode(dev::eth::Permanence::Reverted);
    return exec.getResult();
}

bool CheckMinGasPrice(std::vector<EthTransactionParams>& etps, const uint64_t& minGasPrice){
    for(EthTransactionParams& etp : etps){
        if(etp.gasPrice < dev::u256(minGasPrice))
            return false;
    }
    return true;
}

bool CheckReward(const CBlock& block, BlockValidationState& state, int nHeight, const Consensus::Params& consensusParams, CAmount nFees, CAmount gasRefunds, CAmount nActualStakeReward, const std::vector<CTxOut>& vouts, CAmount nValueCoinPrev, bool delegateOutputExist)
{
    size_t offset = block.IsProofOfStake() ? 1 : 0;
    std::vector<CTxOut> vTempVouts=block.vtx[offset]->vout;
    std::vector<CTxOut>::iterator it;
    for(size_t i = 0; i < vouts.size(); i++){
        it=std::find(vTempVouts.begin(), vTempVouts.end(), vouts[i]);
        if(it==vTempVouts.end()){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-gas-refund-missing", "CheckReward(): Gas refund missing");
        }else{
            vTempVouts.erase(it);
        }
    }

    // Check block reward
    if (block.IsProofOfWork())
    {
        // Check proof-of-work reward
        CAmount blockReward = nFees + GetBlockSubsidy(nHeight, consensusParams);
        if (block.vtx[offset]->GetValueOut() > blockReward)
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-amount", strprintf("CheckReward(): coinbase pays too much (actual=%d vs limit=%d)", block.vtx[offset]->GetValueOut(), blockReward));
    }
    else
    {
        // Check full reward
        CAmount blockReward = nFees + GetBlockSubsidy(nHeight, consensusParams);
        if (nActualStakeReward > blockReward)
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-amount", strprintf("CheckReward(): coinstake pays too much (actual=%d vs limit=%d)", nActualStakeReward, blockReward));

        // The first proof-of-stake blocks get full reward, the rest of them are split between recipients
        int rewardRecipients = 1;
        int nPrevHeight = nHeight -1;
        if(nPrevHeight >= consensusParams.nFirstMPoSBlock && nPrevHeight < consensusParams.nLastMPoSBlock)
            rewardRecipients = consensusParams.nMPoSRewardRecipients;

        // Check reward recipients number
        if(rewardRecipients < 1)
            return error("CheckReward(): invalid reward recipients");

        // Check reward can cover the gas refunds
        if(blockReward < gasRefunds){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-gas-greater-than-reward", "CheckReward(): Block Reward is less than total gas refunds");
        }

        CAmount splitReward = (blockReward - gasRefunds) / rewardRecipients;

        // Check that the reward is in the second output for the staker and the third output for the delegate
        // Delegation contract data like the fee is checked in CheckProofOfStake
        if(block.HasProofOfDelegation())
        {
            CAmount nReward = blockReward - gasRefunds - splitReward * (rewardRecipients -1);
            CAmount nValueStaker = block.vtx[offset]->vout[1].nValue;
            CAmount nValueDelegate = delegateOutputExist ? block.vtx[offset]->vout[2].nValue : 0;
            CAmount nMinedReward = nValueStaker + nValueDelegate - nValueCoinPrev;
            if(nReward != nMinedReward)
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-delegate-reward", "CheckReward(): The block reward is not split correctly between the staker and the delegate");
        }

        //if only 1 then no MPoS logic required
        if(rewardRecipients == 1){
            return true;
        }

        // Generate the list of mpos outputs including all of their parameters
        std::vector<CTxOut> mposOutputList;
        if(!GetMPoSOutputs(mposOutputList, splitReward, nPrevHeight, consensusParams))
            return error("CheckReward(): cannot create the list of MPoS outputs");
      
        for(size_t i = 0; i < mposOutputList.size(); i++){
            it=std::find(vTempVouts.begin(), vTempVouts.end(), mposOutputList[i]);
            if(it==vTempVouts.end()){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-mpos-missing", "CheckReward(): An MPoS participant was not properly paid");
            }else{
                vTempVouts.erase(it);
            }
        }

        vTempVouts.clear();
    }

    return true;
}

valtype GetSenderAddress(const CTransaction& tx, const CCoinsViewCache* coinsView, const std::vector<CTransactionRef>* blockTxs, int nOut = -1){
    CScript script;
    bool scriptFilled=false; //can't use script.empty() because an empty script is technically valid

    // Try get the sender script from the output script
    if(nOut > -1)
        scriptFilled = ExtractSenderData(tx.vout[nOut].scriptPubKey, &script, nullptr);

    // Check the current (or in-progress) block for zero-confirmation change spending that won't yet be in txindex
    if(!scriptFilled && blockTxs){
        for(auto btx : *blockTxs){
            if(btx->GetHash() == tx.vin[0].prevout.hash){
                script = btx->vout[tx.vin[0].prevout.n].scriptPubKey;
                scriptFilled=true;
                break;
            }
        }
    }
    if(!scriptFilled && coinsView){
        script = coinsView->AccessCoin(tx.vin[0].prevout).out.scriptPubKey;
        scriptFilled = true;
    }
    if(!scriptFilled)
    {
        CTransactionRef txPrevout;
        uint256 hashBlock;
        if(GetTransaction(tx.vin[0].prevout.hash, txPrevout, Params().GetConsensus(), hashBlock, nullptr, true)){
            script = txPrevout->vout[tx.vin[0].prevout.n].scriptPubKey;
        } else {
            LogPrintf("Error fetching transaction details of tx %s. This will probably cause more errors", tx.vin[0].prevout.hash.ToString());
            return valtype();
        }
    }

	CTxDestination addressBit;
    txnouttype txType=TX_NONSTANDARD;
	if(ExtractDestination(script, addressBit, &txType)){
		if ((txType == TX_PUBKEY || txType == TX_PUBKEYHASH) &&
                addressBit.type() == typeid(PKHash)){
			PKHash senderAddress(boost::get<PKHash>(addressBit));
			return valtype(senderAddress.begin(), senderAddress.end());
		}
	}
    //prevout is not a standard transaction format, so just return 0
    return valtype();
}

UniValue vmLogToJSON(const ResultExecute& execRes, const CTransaction& tx, const CBlock& block){
    UniValue result(UniValue::VOBJ);
    if(tx != CTransaction())
        result.pushKV("txid", tx.GetHash().GetHex());
    result.pushKV("address", execRes.execRes.newAddress.hex());
    if(block.GetHash() != CBlock().GetHash()){
        result.pushKV("time", block.GetBlockTime());
        result.pushKV("blockhash", block.GetHash().GetHex());
        result.pushKV("blockheight", ::ChainActive().Tip()->nHeight + 1);
    } else {
        result.pushKV("time", GetAdjustedTime());
        result.pushKV("blockheight", ::ChainActive().Tip()->nHeight);
    }
    UniValue logEntries(UniValue::VARR);
    dev::eth::LogEntries logs = execRes.txRec.log();
    for(dev::eth::LogEntry log : logs){
        UniValue logEntrie(UniValue::VOBJ);
        logEntrie.pushKV("address", log.address.hex());
        UniValue topics(UniValue::VARR);
        for(dev::h256 l : log.topics){
            UniValue topicPair(UniValue::VOBJ);
            topicPair.pushKV("raw", l.hex());
            topics.push_back(topicPair);
            //TODO add "pretty" field for human readable data
        }
        UniValue dataPair(UniValue::VOBJ);
        dataPair.pushKV("raw", HexStr(log.data));
        logEntrie.pushKV("data", dataPair);
        logEntrie.pushKV("topics", topics);
        logEntries.push_back(logEntrie);
    }
    result.pushKV("entries", logEntries);
    return result;
}

void writeVMlog(const std::vector<ResultExecute>& res, const CTransaction& tx, const CBlock& block){
    boost::filesystem::path qtumDir = GetDataDir() / "vmExecLogs.json";
    std::stringstream ss;
    if(fIsVMlogFile){
        ss << ",";
    } else {
        std::ofstream file(qtumDir.string(), std::ios::out | std::ios::app);
        file << "{\"logs\":[]}";
        file.close();
    }

    for(size_t i = 0; i < res.size(); i++){
        ss << vmLogToJSON(res[i], tx, block).write();
        if(i != res.size() - 1){
            ss << ",";
        } else {
            ss << "]}";
        }
    }
    
    std::ofstream file(qtumDir.string(), std::ios::in | std::ios::out);
    file.seekp(-2, std::ios::end);
    file << ss.str();
    file.close();
    fIsVMlogFile = true;
}

LastHashes::LastHashes()
{}

void LastHashes::set(const CBlockIndex *tip)
{
    clear();

    m_lastHashes.resize(256);
    for(int i=0;i<256;i++){
        if(!tip)
            break;
        m_lastHashes[i]= uintToh256(*tip->phashBlock);
        tip = tip->pprev;
    }
}

dev::h256s LastHashes::precedingHashes(const dev::h256 &) const
{
    return m_lastHashes;
}

void LastHashes::clear()
{
    m_lastHashes.clear();
}

bool ByteCodeExec::performByteCode(dev::eth::Permanence type){
    for(QtumTransaction& tx : txs){
        //validate VM version
        if(tx.getVersion().toRaw() != VersionVM::GetEVMDefault().toRaw()){
            return false;
        }
        dev::eth::EnvInfo envInfo(BuildEVMEnvironment());
        if(!tx.isCreation() && !globalState->addressInUse(tx.receiveAddress())){
            dev::eth::ExecutionResult execRes;
            execRes.excepted = dev::eth::TransactionException::Unknown;
            result.push_back(ResultExecute{execRes, QtumTransactionReceipt(dev::h256(), dev::h256(), dev::u256(), dev::eth::LogEntries()), CTransaction()});
            continue;
        }
        result.push_back(globalState->execute(envInfo, *globalSealEngine.get(), tx, type, OnOpFunc()));
    }
    globalState->db().commit();
    globalState->dbUtxo().commit();
    globalSealEngine.get()->deleteAddresses.clear();
    return true;
}

bool ByteCodeExec::processingResults(ByteCodeExecResult& resultBCE){
	const Consensus::Params& consensusParams = Params().GetConsensus();
    for(size_t i = 0; i < result.size(); i++){
        uint64_t gasUsed = (uint64_t) result[i].execRes.gasUsed;

        if(result[i].execRes.excepted != dev::eth::TransactionException::None){
        	// refund coins sent to the contract to the sender
        	if(txs[i].value() > 0){
        		CMutableTransaction tx;
        		tx.vin.push_back(CTxIn(h256Touint(txs[i].getHashWith()), txs[i].getNVout(), CScript() << OP_SPEND));
        		CScript script(CScript() << OP_DUP << OP_HASH160 << txs[i].sender().asBytes() << OP_EQUALVERIFY << OP_CHECKSIG);
        		tx.vout.push_back(CTxOut(CAmount(txs[i].value()), script));
        		resultBCE.valueTransfers.push_back(CTransaction(tx));
        	}
        	if(!(::ChainActive().Height() >= consensusParams.QIP7Height && result[i].execRes.excepted == dev::eth::TransactionException::RevertInstruction)){
        	resultBCE.usedGas += gasUsed;
        	}
        }

        if(result[i].execRes.excepted == dev::eth::TransactionException::None || (::ChainActive().Height() >= consensusParams.QIP7Height && result[i].execRes.excepted == dev::eth::TransactionException::RevertInstruction)){
        	if(txs[i].gas() > UINT64_MAX ||
        			result[i].execRes.gasUsed > UINT64_MAX ||
					txs[i].gasPrice() > UINT64_MAX){
        		return false;
        	}
        	uint64_t gas = (uint64_t) txs[i].gas();
        	uint64_t gasPrice = (uint64_t) txs[i].gasPrice();

        	resultBCE.usedGas += gasUsed;
        	int64_t amount = (gas - gasUsed) * gasPrice;
        	if(amount < 0){
        		return false;
        	}
        	if(amount > 0){
        		// Refund the rest of the amount to the sender that provide the coins for the contract
				CScript script(CScript() << OP_DUP << OP_HASH160 << txs[i].getRefundSender().asBytes() << OP_EQUALVERIFY << OP_CHECKSIG);
				resultBCE.refundOutputs.push_back(CTxOut(amount, script));
				resultBCE.refundSender += amount;
        	}
        }

        if(result[i].tx != CTransaction()){
            resultBCE.valueTransfers.push_back(result[i].tx);
        }
    }
    return true;
}

dev::eth::EnvInfo ByteCodeExec::BuildEVMEnvironment(){
    CBlockIndex* tip = pindex;
    dev::eth::BlockHeader header;
    header.setNumber(tip->nHeight + 1);
    header.setTimestamp(block.nTime);
    header.setDifficulty(dev::u256(block.nBits));
    header.setGasLimit(blockGasLimit);

    lastHashes.set(tip);

    if(block.IsProofOfStake()){
        header.setAuthor(EthAddrFromScript(block.vtx[1]->vout[1].scriptPubKey));
    }else {
        header.setAuthor(EthAddrFromScript(block.vtx[0]->vout[0].scriptPubKey));
    }
    dev::u256 gasUsed;
    dev::eth::EnvInfo env(header, lastHashes, gasUsed);
    return env;
}

dev::Address ByteCodeExec::EthAddrFromScript(const CScript& script){
    CTxDestination addressBit;
    txnouttype txType=TX_NONSTANDARD;
    if(ExtractDestination(script, addressBit, &txType)){
        if ((txType == TX_PUBKEY || txType == TX_PUBKEYHASH) &&
            addressBit.type() == typeid(PKHash)){
            PKHash addressKey(boost::get<PKHash>(addressBit));
            std::vector<unsigned char> addr(addressKey.begin(), addressKey.end());
            return dev::Address(addr);
        }
    }
    //if not standard or not a pubkey or pubkeyhash output, then return 0
    return dev::Address();
}

bool QtumTxConverter::extractionQtumTransactions(ExtractQtumTX& qtumtx){
    // Get the address of the sender that pay the coins for the contract transactions
    refundSender = dev::Address(GetSenderAddress(txBit, view, blockTransactions));

    // Extract contract transactions
    std::vector<QtumTransaction> resultTX;
    std::vector<EthTransactionParams> resultETP;
    for(size_t i = 0; i < txBit.vout.size(); i++){
        if(txBit.vout[i].scriptPubKey.HasOpCreate() || txBit.vout[i].scriptPubKey.HasOpCall()){
            if(receiveStack(txBit.vout[i].scriptPubKey)){
                EthTransactionParams params;
                if(parseEthTXParams(params)){
                    resultTX.push_back(createEthTX(params, i));
                    resultETP.push_back(params);
                }else{
                    return false;
                }
            }else{
                return false;
            }
        }
    }
    qtumtx = std::make_pair(resultTX, resultETP);
    return true;
}

bool QtumTxConverter::receiveStack(const CScript& scriptPubKey){
    sender = false;
    EvalScript(stack, scriptPubKey, nFlags, BaseSignatureChecker(), SigVersion::BASE, nullptr);
    if (stack.empty())
        return false;

    CScript scriptRest(stack.back().begin(), stack.back().end());
    stack.pop_back();
    sender = scriptPubKey.HasOpSender();

    opcode = (opcodetype)(*scriptRest.begin());
    if((opcode == OP_CREATE && stack.size() < correctedStackSize(4)) || (opcode == OP_CALL && stack.size() < correctedStackSize(5))){
        stack.clear();
        sender = false;
        return false;
    }

    return true;
}

bool QtumTxConverter::parseEthTXParams(EthTransactionParams& params){
    try{
        dev::Address receiveAddress;
        valtype vecAddr;
        if (opcode == OP_CALL)
        {
            vecAddr = stack.back();
            stack.pop_back();
            receiveAddress = dev::Address(vecAddr);
        }
        if(stack.size() < correctedStackSize(4))
            return false;

        if(stack.back().size() < 1){
            return false;
        }
        valtype code(stack.back());
        stack.pop_back();
        uint64_t gasPrice = CScriptNum::vch_to_uint64(stack.back());
        stack.pop_back();
        uint64_t gasLimit = CScriptNum::vch_to_uint64(stack.back());
        stack.pop_back();
        if(gasPrice > INT64_MAX || gasLimit > INT64_MAX){
            return false;
        }
        //we track this as CAmount in some places, which is an int64_t, so constrain to INT64_MAX
        if(gasPrice !=0 && gasLimit > INT64_MAX / gasPrice){
            //overflows past 64bits, reject this tx
            return false;
        }
        if(stack.back().size() > 4){
            return false;
        }
        VersionVM version = VersionVM::fromRaw((uint32_t)CScriptNum::vch_to_uint64(stack.back()));
        stack.pop_back();
        params.version = version;
        params.gasPrice = dev::u256(gasPrice);
        params.receiveAddress = receiveAddress;
        params.code = code;
        params.gasLimit = dev::u256(gasLimit);
        return true;
    }
    catch(const scriptnum_error& err){
        LogPrintf("Incorrect parameters to VM.");
        return false;
    }
}

QtumTransaction QtumTxConverter::createEthTX(const EthTransactionParams& etp, uint32_t nOut){
    QtumTransaction txEth;
    if (etp.receiveAddress == dev::Address() && opcode != OP_CALL){
        txEth = QtumTransaction(txBit.vout[nOut].nValue, etp.gasPrice, etp.gasLimit, etp.code, dev::u256(0));
    }
    else{
        txEth = QtumTransaction(txBit.vout[nOut].nValue, etp.gasPrice, etp.gasLimit, etp.receiveAddress, etp.code, dev::u256(0));
    }
    dev::Address sender(GetSenderAddress(txBit, view, blockTransactions, (int)nOut));
    txEth.forceSender(sender);
    txEth.setHashWith(uintToh256(txBit.GetHash()));
    txEth.setNVout(nOut);
    txEth.setVersion(etp.version);
    txEth.setRefundSender(refundSender);

    return txEth;
}

size_t QtumTxConverter::correctedStackSize(size_t size){
    // OP_SENDER add 3 more parameters in stack besides those for OP_CREATE or OP_CALL
    return sender ? size + 3 : size;
}
///////////////////////////////////////////////////////////////////////

bool CheckDelegationOutput(const CBlock& block, bool& delegateOutputExist, CCoinsViewCache& view)
{
    if(block.IsProofOfStake() && block.HasProofOfDelegation())
    {
        uint160 staker;
        std::vector<unsigned char> vchPubKey;
        if(GetBlockPublicKey(block, vchPubKey))
        {
            staker = uint160(ToByteVector(CPubKey(vchPubKey).GetID()));
            uint160 address;
            uint8_t fee = 0;
            if(GetBlockDelegation(block, staker, address, fee, view))
            {
                delegateOutputExist = IsDelegateOutputExist(fee);
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }

    return true;
}

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool CChainState::ConnectBlock(const CBlock& block, BlockValidationState& state, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck)
{
    AssertLockHeld(cs_main);
    assert(pindex);
    assert(*pindex->phashBlock == block.GetHash());
    int64_t nTimeStart = GetTimeMicros();

    ///////////////////////////////////////////////// // qtum
    QtumDGP qtumDGP(globalState.get(), fGettingValuesDGP);
    globalSealEngine->setQtumSchedule(qtumDGP.getGasSchedule(pindex->nHeight + (pindex->nHeight+1 >= chainparams.GetConsensus().QIP7Height ? 0 : 1) ));
    uint32_t sizeBlockDGP = qtumDGP.getBlockSize(pindex->nHeight + (pindex->nHeight+1 >= chainparams.GetConsensus().QIP7Height ? 0 : 1));
    uint64_t minGasPrice = qtumDGP.getMinGasPrice(pindex->nHeight + (pindex->nHeight+1 >= chainparams.GetConsensus().QIP7Height ? 0 : 1));
    uint64_t blockGasLimit = qtumDGP.getBlockGasLimit(pindex->nHeight + (pindex->nHeight+1 >= chainparams.GetConsensus().QIP7Height ? 0 : 1));
    dgpMaxBlockSize = sizeBlockDGP ? sizeBlockDGP : dgpMaxBlockSize;
    updateBlockSizeParams(dgpMaxBlockSize);
    CBlock checkBlock(block.GetBlockHeader());
    std::vector<CTxOut> checkVouts;

    /////////////////////////////////////////////////
    // We recheck the hardened checkpoints here since ContextualCheckBlock(Header) is not called in ConnectBlock.
    if(fCheckpointsEnabled && !Checkpoints::CheckHardened(pindex->nHeight, block.GetHash(), chainparams.Checkpoints())) {
        return state.Invalid(BlockValidationResult::BLOCK_CHECKPOINT, "bad-fork-hardened-checkpoint", strprintf("%s: expected hardened checkpoint at height %d", __func__, pindex->nHeight));
    }


    // Move this check from CheckBlock to ConnectBlock as it depends on DGP values
    if (block.vtx.empty() || block.vtx.size() > dgpMaxBlockSize || ::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) > dgpMaxBlockSize) // qtum
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");

    // Move this check from ContextualCheckBlock to ConnectBlock as it depends on DGP values
    if (GetBlockWeight(block) > dgpMaxBlockWeight) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-weight", strprintf("%s : weight limit failed", __func__));
    }

    bool delegateOutputExist = false;
    if (!CheckDelegationOutput(block, delegateOutputExist, view)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-delegate-output", strprintf("%s : delegation output check failed", __func__));
    }

    if (block.IsProofOfStake() && pindex->nHeight > chainparams.GetConsensus().nEnableHeaderSignatureHeight && !CheckBlockInputPubKeyMatchesOutputPubKey(block, view, delegateOutputExist)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-coinstake-input-output-mismatch");
    }

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific (see RewindBlockIndex()
    // for one general approach that was used for BIP 141 deployment).
    // Also, currently the rule against blocks more than 2 hours in the future
    // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
    // re-enforce that rule here (at least until we make it impossible for
    // GetAdjustedTime() to go backward).
    if (!CheckBlock(block, state, chainparams.GetConsensus(), !fJustCheck, !fJustCheck)) {
        if (state.GetResult() == BlockValidationResult::BLOCK_MUTATED) {
            // We don't write down blocks to disk if they may have been
            // corrupted, so this should be impossible unless we're having hardware
            // problems.
            return AbortNode(state, "Corrupt block found indicating potential hardware failure; shutting down");
        }
        return error("%s: Consensus::CheckBlock: %s", __func__, state.ToString());
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    nBlocksTotal++;

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.GetHash() == chainparams.GetConsensus().hashGenesisBlock) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    // State is filled in by UpdateHashProof
    if (!UpdateHashProof(block, state, chainparams.GetConsensus(), pindex, view)) {
        return error("%s: ConnectBlock(): %s", __func__, state.GetRejectReason().c_str());
    }

    bool fScriptChecks = true;
    if (!hashAssumeValid.IsNull()) {
        // We've been configured with the hash of a block which has been externally verified to have a valid history.
        // A suitable default value is included with the software and updated from time to time.  Because validity
        //  relative to a piece of software is an objective fact these defaults can be easily reviewed.
        // This setting doesn't force the selection of any particular chain but makes validating some faster by
        //  effectively caching the result of part of the verification.
        BlockMap::const_iterator  it = m_blockman.m_block_index.find(hashAssumeValid);
        if (it != m_blockman.m_block_index.end()) {
            if (it->second->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->nChainWork >= nMinimumChainWork) {
                // This block is a member of the assumed verified chain and an ancestor of the best header.
                // Script verification is skipped when connecting blocks under the
                // assumevalid block. Assuming the assumevalid block is valid this
                // is safe because block merkle hashes are still computed and checked,
                // Of course, if an assumed valid block is invalid due to false scriptSigs
                // this optimization would allow an invalid chain to be accepted.
                // The equivalent time check discourages hash power from extorting the network via DOS attack
                //  into accepting an invalid block through telling users they must manually set assumevalid.
                //  Requiring a software change or burying the invalid block, regardless of the setting, makes
                //  it hard to hide the implication of the demand.  This also avoids having release candidates
                //  that are hardly doing any signature verification at all in testing without having to
                //  artificially set the default assumed verified block further back.
                // The test against nMinimumChainWork prevents the skipping when denied access to any chain at
                //  least as good as the expected chain.
                fScriptChecks = (GetBlockProofEquivalentTime(*pindexBestHeader, *pindex, *pindexBestHeader, chainparams.GetConsensus()) <= 60 * 60 * 24 * 7 * 2);
            }
        }
    }

    int64_t nTime1 = GetTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    LogPrint(BCLog::BENCH, "    - Sanity checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime1 - nTimeStart), nTimeCheck * MICRO, nTimeCheck * MILLI / nBlocksTotal);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30, CVE-2012-1909, and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = (!pindex->phashBlock);
    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried it's no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.

    // BIP34 requires that a block at height X (block X) has its coinbase
    // scriptSig start with a CScriptNum of X (indicated height X).  The above
    // logic of no longer requiring BIP30 once BIP34 activates is flawed in the
    // case that there is a block X before the BIP34 height of 227,931 which has
    // an indicated height Y where Y is greater than X.  The coinbase for block
    // X would also be a valid coinbase for block Y, which could be a BIP30
    // violation.  An exhaustive search of all mainnet coinbases before the
    // BIP34 height which have an indicated height greater than the block height
    // reveals many occurrences. The 3 lowest indicated heights found are
    // 209,921, 490,897, and 1,983,702 and thus coinbases for blocks at these 3
    // heights would be the first opportunity for BIP30 to be violated.

    // The search reveals a great many blocks which have an indicated height
    // greater than 1,983,702, so we simply remove the optimization to skip
    // BIP30 checking for blocks at height 1,983,702 or higher.  Before we reach
    // that block in another 25 years or so, we should take advantage of a
    // future consensus change to do a new and improved version of BIP34 that
    // will actually prevent ever creating any duplicate coinbases in the
    // future.
    static constexpr int BIP34_IMPLIES_BIP30_LIMIT = 1983702;

    // There is no potential to create a duplicate coinbase at block 209,921
    // because this is still before the BIP34 height and so explicit BIP30
    // checking is still active.

    // The final case is block 176,684 which has an indicated height of
    // 490,897. Unfortunately, this issue was not discovered until about 2 weeks
    // before block 490,897 so there was not much opportunity to address this
    // case other than to carefully analyze it and determine it would not be a
    // problem. Block 490,897 was, in fact, mined with a different coinbase than
    // block 176,684, but it is important to note that even if it hadn't been or
    // is remined on an alternate fork with a duplicate coinbase, we would still
    // not run into a BIP30 violation.  This is because the coinbase for 176,684
    // is spent in block 185,956 in transaction
    // d4f7fbbf92f4a3014a230b2dc70b8058d02eb36ac06b4a0736d9d60eaa9e8781.  This
    // spending transaction can't be duplicated because it also spends coinbase
    // 0328dd85c331237f18e781d692c92de57649529bd5edf1d01036daea32ffde29.  This
    // coinbase has an indicated height of over 4.2 billion, and wouldn't be
    // duplicatable until that height, and it's currently impossible to create a
    // chain that long. Nevertheless we may wish to consider a future soft fork
    // which retroactively prevents block 490,897 from creating a duplicate
    // coinbase. The two historical BIP30 violations often provide a confusing
    // edge case when manipulating the UTXO and it would be simpler not to have
    // another edge case to deal with.

    // testnet3 has no blocks before the BIP34 height with indicated heights
    // post BIP34 before approximately height 486,000,000 and presumably will
    // be reset before it reaches block 1,983,702 and starts doing unnecessary
    // BIP30 checking again.
    assert(pindex->pprev);
    CBlockIndex *pindexBIP34height = pindex->pprev->GetAncestor(chainparams.GetConsensus().BIP34Height);
    //Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == chainparams.GetConsensus().BIP34Hash));

    // TODO: Remove BIP30 checking from block height 1,983,702 on, once we have a
    // consensus change that ensures coinbases at those heights can not
    // duplicate earlier coinbases.
    if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT) {
        for (const auto& tx : block.vtx) {
            for (size_t o = 0; o < tx->vout.size(); o++) {
                if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                    LogPrintf("ERROR: ConnectBlock(): tried to overwrite transaction\n");
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-BIP30");
                }
            }
        }
    }

    // Start enforcing BIP68 (sequence locks)
    int nLockTimeFlags = 0;
    if (pindex->nHeight >= chainparams.GetConsensus().CSVHeight) {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Get the script flags for this block
    unsigned int flags = GetBlockScriptFlags(pindex, chainparams.GetConsensus());
    unsigned int contractflags = GetContractScriptFlags(pindex->nHeight, chainparams.GetConsensus());

    int64_t nTime2 = GetTimeMicros(); nTimeForks += nTime2 - nTime1;
    LogPrint(BCLog::BENCH, "    - Fork checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime2 - nTime1), nTimeForks * MICRO, nTimeForks * MILLI / nBlocksTotal);

    CBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && g_parallel_script_checks ? &scriptcheckqueue : nullptr);

    std::vector<int> prevheights;
    CAmount nFees = 0;
    CAmount nActualStakeReward = 0;
    CAmount nValueCoinPrev = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    blockundo.vtxundo.reserve(block.vtx.size() - 1);

    ///////////////////////////////////////////////////////// // qtum
    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > addressUnspentIndex;
    std::vector<std::pair<CSpentIndexKey, CSpentIndexValue> > spentIndex;
    std::map<dev::Address, std::pair<CHeightTxIndexKey, std::vector<uint256>>> heightIndexes;
    /////////////////////////////////////////////////////////

    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(block.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated
    uint64_t blockGasUsed = 0;
    CAmount gasRefunds=0;

    uint64_t nValueOut=0;
    uint64_t nValueIn=0;

    if(block.IsProofOfStake())
    {
        Coin coin;
        if(!view.GetCoin(block.vtx[1]->vin[0].prevout, coin)){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "stake-prevout-not-exist", strprintf("ConnectBlock() : Stake prevout does not exist %s", block.vtx[1]->vin[0].prevout.hash.ToString()));
        }
        nValueCoinPrev = coin.out.nValue;
    }

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);

        nInputs += tx.vin.size();

        if (!tx.IsCoinBase())
        {
            CAmount txfee = 0;
            TxValidationState tx_state;
            if (!Consensus::CheckTxInputs(tx, tx_state, view, pindex->nHeight, txfee)) {
                // Any transaction validation failure in ConnectBlock is a block consensus failure
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                            tx_state.GetRejectReason(), tx_state.GetDebugMessage());
                return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), state.ToString());
            }
            nFees += txfee;
            if (!MoneyRange(nFees)) {
                LogPrintf("ERROR: %s: accumulated fee in the block out of range.\n", __func__);
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-accumulated-fee-outofrange");
            }

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex)) {
                LogPrintf("ERROR: %s: contains a non-BIP68-final transaction\n", __func__);
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal");
            }

            ////////////////////////////////////////////////////////////////// // qtum
            if (fAddressIndex)
            {
                for (size_t j = 0; j < tx.vin.size(); j++) {
                    const CTxIn input = tx.vin[j];
                    const CTxOut &prevout = view.GetOutputFor(tx.vin[j]);

                    CTxDestination dest;
                    if (ExtractDestination(input.prevout, prevout.scriptPubKey, dest)) {
                        valtype bytesID(boost::apply_visitor(DataVisitor(), dest));
                        if(bytesID.empty()) {
                            continue;
                        }
                        valtype addressBytes(32);
                        std::copy(bytesID.begin(), bytesID.end(), addressBytes.begin());
                        addressIndex.push_back(std::make_pair(CAddressIndexKey(dest.which(), uint256(addressBytes), pindex->nHeight, i, tx.GetHash(), j, true), prevout.nValue * -1));

                        // remove address from unspent index
                        addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(dest.which(), uint256(addressBytes), input.prevout.hash, input.prevout.n), CAddressUnspentValue()));
                        spentIndex.push_back(std::make_pair(CSpentIndexKey(input.prevout.hash, input.prevout.n), CSpentIndexValue(tx.GetHash(), j, pindex->nHeight, prevout.nValue, dest.which(), uint256(addressBytes))));
                    }
                }
            }
            //////////////////////////////////////////////////////////////////
        }

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > dgpMaxBlockSigOps) {
            LogPrintf("ERROR: ConnectBlock(): too many sigops\n");
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops");
        }

        txdata.emplace_back(tx);

        bool hasOpSpend = tx.HasOpSpend();

        if (!tx.IsCoinBase())
        {
            if (tx.IsCoinStake())
                nActualStakeReward = tx.GetValueOut()-view.GetValueIn(tx);
                    
            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            TxValidationState tx_state;
            if (fScriptChecks && !CheckInputScripts(tx, tx_state, view, flags, fCacheResults, fCacheResults, txdata[i], (hasOpSpend || tx.HasCreateOrCall()) ? nullptr : (g_parallel_script_checks ? &vChecks : nullptr))) {
                // Any transaction validation failure in ConnectBlock is a block consensus failure
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                              tx_state.GetRejectReason(), tx_state.GetDebugMessage());
                return error("ConnectBlock(): CheckInputScripts on %s failed with %s",
                    tx.GetHash().ToString(), state.ToString());
            }
            control.Add(vChecks);

            for(const CTxIn& j : tx.vin){
                if(!j.scriptSig.HasOpSpend()){
                    const CTxOut& prevout = view.AccessCoin(j.prevout).out;
                    if((prevout.scriptPubKey.HasOpCreate() || prevout.scriptPubKey.HasOpCall())){
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-invalid-contract-spend", "ConnectBlock(): Contract spend without OP_SPEND in scriptSig");
                    }
                }
            }
        }

        if(tx.IsCoinBase()){
            nValueOut += tx.GetValueOut();
        }else{
            int64_t nTxValueIn = view.GetValueIn(tx);
            int64_t nTxValueOut = tx.GetValueOut();
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
        }

///////////////////////////////////////////////////////////////////////////////////////// qtum
        if(!CheckOpSender(tx, chainparams, pindex->nHeight)){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-invalid-sender");
        }
        if(!tx.HasOpSpend()){
            checkBlock.vtx.push_back(block.vtx[i]);
        }
        if(tx.HasCreateOrCall() && !hasOpSpend){

            if(!CheckSenderScript(view, tx)){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-invalid-sender-script");
            }

            QtumTxConverter convert(tx, &view, &block.vtx, contractflags);

            ExtractQtumTX resultConvertQtumTX;
            if(!convert.extractionQtumTransactions(resultConvertQtumTX)){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-bad-contract-format", "ConnectBlock(): Contract transaction of the wrong format");
            }
            if(!CheckMinGasPrice(resultConvertQtumTX.second, minGasPrice))
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-low-gas-price", "ConnectBlock(): Contract execution has lower gas price than allowed");


            dev::u256 gasAllTxs = dev::u256(0);
            ByteCodeExec exec(block, resultConvertQtumTX.first, blockGasLimit, pindex->pprev);
            //validate VM version and other ETH params before execution
            //Reject anything unknown (could be changed later by DGP)
            //TODO evaluate if this should be relaxed for soft-fork purposes
            bool nonZeroVersion=false;
            dev::u256 sumGas = dev::u256(0);
            CAmount nTxFee = view.GetValueIn(tx)-tx.GetValueOut();
            for(QtumTransaction& qtx : resultConvertQtumTX.first){
                sumGas += qtx.gas() * qtx.gasPrice();

                if(sumGas > dev::u256(INT64_MAX)) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-gas-stipend-overflow", "ConnectBlock(): Transaction's gas stipend overflows");
                }

                if(sumGas > dev::u256(nTxFee)) {
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-fee-notenough", "ConnectBlock(): Transaction fee does not cover the gas stipend");
                }

                VersionVM v = qtx.getVersion();
                if(v.format!=0)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-version-format", "ConnectBlock(): Contract execution uses unknown version format");
                if(v.rootVM != 0){
                    nonZeroVersion=true;
                }else{
                    if(nonZeroVersion){
                        //If an output is version 0, then do not allow any other versions in the same tx
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-mixed-zero-versions", "ConnectBlock(): Contract tx has mixed version 0 and non-0 VM executions");
                    }
                }
                if(!(v.rootVM == 0 || v.rootVM == 1))
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-version-rootvm", "ConnectBlock(): Contract execution uses unknown root VM");
                if(v.vmVersion != 0)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-version-vmversion", "ConnectBlock(): Contract execution uses unknown VM version");
                if(v.flagOptions != 0)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-version-flags", "ConnectBlock(): Contract execution uses unknown flag options");

                //check gas limit is not less than minimum gas limit (unless it is a no-exec tx)
                if(qtx.gas() < MINIMUM_GAS_LIMIT && v.rootVM != 0)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-too-little-gas", "ConnectBlock(): Contract execution has lower gas limit than allowed");

                if(qtx.gas() > UINT32_MAX)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-too-much-gas", "ConnectBlock(): Contract execution can not specify greater gas limit than can fit in 32-bits");

                gasAllTxs += qtx.gas();
                if(gasAllTxs > dev::u256(blockGasLimit))
                    return state.Invalid(BlockValidationResult::BLOCK_GAS_EXCEEDS_LIMIT, "bad-txns-gas-exceeds-blockgaslimit");

                //don't allow less than DGP set minimum gas price to prevent MPoS greedy mining/spammers
                if(v.rootVM!=0 && (uint64_t)qtx.gasPrice() < minGasPrice)
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-low-gas-price", "ConnectBlock(): Contract execution has lower gas price than allowed");
            }

            if(!nonZeroVersion){
                //if tx is 0 version, then the tx must already have been added by a previous contract execution
                if(!tx.HasOpSpend()){
                    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-improper-version-0", "ConnectBlock(): Version 0 contract executions are not allowed unless created by the AAL");
                }
            }

            if(!exec.performByteCode()){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-tx-unknown-error", "ConnectBlock(): Unknown error during contract execution");
            }

            std::vector<ResultExecute> resultExec(exec.getResult());
            ByteCodeExecResult bcer;
            if(!exec.processingResults(bcer)){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-vm-exec-processing", "ConnectBlock(): Error processing VM execution results");
            }

            std::vector<TransactionReceiptInfo> tri;
            if (fLogEvents && !fJustCheck)
            {
                uint64_t countCumulativeGasUsed = blockGasUsed;
                for(size_t k = 0; k < resultConvertQtumTX.first.size(); k ++){
                    for(auto& log : resultExec[k].txRec.log()) {
                        if(!heightIndexes.count(log.address)){
                            heightIndexes[log.address].first = CHeightTxIndexKey(pindex->nHeight, log.address);
                        }
                        heightIndexes[log.address].second.push_back(tx.GetHash());
                    }
                    uint64_t gasUsed = uint64_t(resultExec[k].execRes.gasUsed);
                    countCumulativeGasUsed += gasUsed;
                    tri.push_back(TransactionReceiptInfo{
                        block.GetHash(),
                        uint32_t(pindex->nHeight),
                        tx.GetHash(),
                        uint32_t(i),
                        resultConvertQtumTX.first[k].from(),
                        resultConvertQtumTX.first[k].to(),
                        countCumulativeGasUsed,
                        gasUsed,
                        resultExec[k].execRes.newAddress,
                        resultExec[k].txRec.log(),
                        resultExec[k].execRes.excepted,
                        exceptedMessage(resultExec[k].execRes.excepted, resultExec[k].execRes.output),
                        resultConvertQtumTX.first[k].getNVout(),
                        resultExec[k].txRec.bloom()
                    });
                }

                pstorageresult->addResult(uintToh256(tx.GetHash()), tri);
            }

            blockGasUsed += bcer.usedGas;
            if(blockGasUsed > blockGasLimit){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-gaslimit", "ConnectBlock(): Block exceeds gas limit");
            }
            for(CTxOut refundVout : bcer.refundOutputs){
                gasRefunds += refundVout.nValue;
            }
            checkVouts.insert(checkVouts.end(), bcer.refundOutputs.begin(), bcer.refundOutputs.end());
            for(CTransaction& t : bcer.valueTransfers){
                checkBlock.vtx.push_back(MakeTransactionRef(std::move(t)));
            }
            if(fRecordLogOpcodes && !fJustCheck){
                writeVMlog(resultExec, tx, block);
            }

            for(ResultExecute& re: resultExec){
                if(re.execRes.newAddress != dev::Address() && !fJustCheck)
                    dev::g_logPost(std::string("Address : " + re.execRes.newAddress.hex()), NULL);
            }
        }
/////////////////////////////////////////////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////////////////////// // qtum
        if (fAddressIndex) {

            for (unsigned int k = 0; k < tx.vout.size(); k++) {
                const CTxOut &out = tx.vout[k];
                const bool isTxCoinStake = tx.IsCoinStake();

                CTxDestination dest;
                if (ExtractDestination({tx.GetHash(), k}, out.scriptPubKey, dest)) {
                    valtype bytesID(boost::apply_visitor(DataVisitor(), dest));
                    if(bytesID.empty()) {
                        continue;
                    }
                    valtype addressBytes(32);
                    std::copy(bytesID.begin(), bytesID.end(), addressBytes.begin());
                    // record receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(dest.which(), uint256(addressBytes), pindex->nHeight, i, tx.GetHash(), k, false), out.nValue));
                    // record unspent output
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(dest.which(), uint256(addressBytes), tx.GetHash(), k), CAddressUnspentValue(out.nValue, out.scriptPubKey, pindex->nHeight, isTxCoinStake)));
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////////////

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);
    }
    int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
    LogPrint(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs (%.2fms/blk)]\n", (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2), MILLI * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);

    if(nFees < gasRefunds) { //make sure it won't overflow
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-fees-greater-gasrefund", "ConnectBlock(): Less total fees than gas refund fees");
    }
    if(!CheckReward(block, state, pindex->nHeight, chainparams.GetConsensus(), nFees, gasRefunds, nActualStakeReward, checkVouts, nValueCoinPrev, delegateOutputExist))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "block-reward-invalid", "ConnectBlock(): Reward check failed");

    if (!control.Wait()) {
        LogPrintf("ERROR: %s: CheckQueue failed\n", __func__);
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "block-validation-failed");
    }
    int64_t nTime4 = GetTimeMicros(); nTimeVerify += nTime4 - nTime2;
    LogPrint(BCLog::BENCH, "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs (%.2fms/blk)]\n", nInputs - 1, MILLI * (nTime4 - nTime2), nInputs <= 1 ? 0 : MILLI * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * MICRO, nTimeVerify * MILLI / nBlocksTotal);

////////////////////////////////////////////////////////////////// // qtum
    if(pindex->nHeight == chainparams.GetConsensus().nOfflineStakeHeight){
        globalState->deployDelegationsContract();
    }
    checkBlock.hashMerkleRoot = BlockMerkleRoot(checkBlock);
    checkBlock.hashStateRoot = h256Touint(globalState->rootHash());
    checkBlock.hashUTXORoot = h256Touint(globalState->rootHashUTXO());

    //If this error happens, it probably means that something with AAL created transactions didn't match up to what is expected
    if((checkBlock.GetHash() != block.GetHash()) && !fJustCheck)
    {
        LogPrintf("Actual block data does not match block expected by AAL\n");
        //Something went wrong with AAL, compare different elements and determine what the problem is
        if(checkBlock.hashMerkleRoot != block.hashMerkleRoot){
            //there is a mismatched tx, so go through and determine which txs
            if(block.vtx.size() > checkBlock.vtx.size()){
                LogPrintf("Unexpected AAL transactions in block. Actual txs: %i, expected txs: %i\n", block.vtx.size(), checkBlock.vtx.size());
                for(size_t i=0;i<block.vtx.size();i++){
                    if(i > checkBlock.vtx.size()-1){
                        LogPrintf("Unexpected transaction: %s\n", block.vtx[i]->ToString());
                    }else {
                        if (block.vtx[i]->GetHash() != checkBlock.vtx[i]->GetHash()) {
                            LogPrintf("Mismatched transaction at entry %i\n", i);
                            LogPrintf("Actual: %s\n", block.vtx[i]->ToString());
                            LogPrintf("Expected: %s\n", checkBlock.vtx[i]->ToString());
                        }
                    }
                }
            }else if(block.vtx.size() < checkBlock.vtx.size()){
                LogPrintf("Actual block is missing AAL transactions. Actual txs: %i, expected txs: %i\n", block.vtx.size(), checkBlock.vtx.size());
                for(size_t i=0;i<checkBlock.vtx.size();i++){
                    if(i > block.vtx.size()-1){
                        LogPrintf("Missing transaction: %s\n", checkBlock.vtx[i]->ToString());
                    }else {
                        if (block.vtx[i]->GetHash() != checkBlock.vtx[i]->GetHash()) {
                            LogPrintf("Mismatched transaction at entry %i\n", i);
                            LogPrintf("Actual: %s\n", block.vtx[i]->ToString());
                            LogPrintf("Expected: %s\n", checkBlock.vtx[i]->ToString());
                        }
                    }
                }
            }else{
                //count is correct, but a tx is wrong
                for(size_t i=0;i<checkBlock.vtx.size();i++){
                    if (block.vtx[i]->GetHash() != checkBlock.vtx[i]->GetHash()) {
                        LogPrintf("Mismatched transaction at entry %i\n", i);
                        LogPrintf("Actual: %s\n", block.vtx[i]->ToString());
                        LogPrintf("Expected: %s\n", checkBlock.vtx[i]->ToString());
                    }
                }
            }
        }
        if(checkBlock.hashUTXORoot != block.hashUTXORoot){
            LogPrintf("Actual block data does not match hashUTXORoot expected by AAL block\n");
        }
        if(checkBlock.hashStateRoot != block.hashStateRoot){
            LogPrintf("Actual block data does not match hashStateRoot expected by AAL block\n");
        }

        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "incorrect-transactions-or-hashes-block", "ConnectBlock(): Incorrect AAL transactions or hashes (hashStateRoot, hashUTXORoot)");
    }

    if (fJustCheck)
    {
        dev::h256 prevHashStateRoot(dev::sha3(dev::rlp("")));
        dev::h256 prevHashUTXORoot(dev::sha3(dev::rlp("")));
        if(pindex->pprev->hashStateRoot != uint256() && pindex->pprev->hashUTXORoot != uint256()){
            prevHashStateRoot = uintToh256(pindex->pprev->hashStateRoot);
            prevHashUTXORoot = uintToh256(pindex->pprev->hashUTXORoot);
        }
        globalState->setRoot(prevHashStateRoot);
        globalState->setRootUTXO(prevHashUTXORoot);
        return true;
    }
//////////////////////////////////////////////////////////////////

    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    //only start checking this error after block 5000 and only on testnet and mainnet, not regtest
    if(pindex->nHeight > 5000 && !Params().MineBlocksOnDemand()) {
        //sanity check in case an exploit happens that allows new coins to be minted
        if(pindex->nMoneySupply > (uint64_t)(100000000 + ((pindex->nHeight - 5000) * 4)) * COIN){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "incorrect-money-supply", "ConnectBlock(): Unknown error caused actual money supply to exceed expected money supply");
        }
    }

    if (!WriteUndoDataForBlock(blockundo, state, pindex, chainparams))
        return false;

    if (!pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }
    if (fLogEvents)
    {
        for (const auto& e: heightIndexes)
        {
            if (!pblocktree->WriteHeightIndex(e.second.first, e.second.second))
                return AbortNode(state, "Failed to write height index");
        }
    }

    // The stake and delegate index is needed for MPoS, update it while MPoS is active
    if(pindex->nHeight <= chainparams.GetConsensus().nLastMPoSBlock)
    {
        if(block.IsProofOfStake()){
            // Read the public key from the second output
            std::vector<unsigned char> vchPubKey;
            uint160 pkh;
            if(GetBlockPublicKey(block, vchPubKey))
            {
                pkh = uint160(ToByteVector(CPubKey(vchPubKey).GetID()));
                pblocktree->WriteStakeIndex(pindex->nHeight, pkh);
            }else{
                pblocktree->WriteStakeIndex(pindex->nHeight, uint160());
            }

            if(block.HasProofOfDelegation())
            {
                uint160 address;
                uint8_t fee = 0;
                GetBlockDelegation(block, pkh, address, fee, view);
                pblocktree->WriteDelegateIndex(pindex->nHeight, address, fee);
            }
        }else{
            pblocktree->WriteStakeIndex(pindex->nHeight, uint160());
        }
    }

    assert(pindex->phashBlock);
    ///////////////////////////////////////////////////////////// // qtum
    if (fAddressIndex) {
        if (!pblocktree->WriteAddressIndex(addressIndex)) {
            return AbortNode(state, "Failed to write address index");
        }
        if (!pblocktree->UpdateAddressUnspentIndex(addressUnspentIndex)) {
            return AbortNode(state, "Failed to write address unspent index");
        }

        if (!pblocktree->UpdateSpentIndex(spentIndex))
            return AbortNode(state, "Failed to write transaction index");

        unsigned int logicalTS = pindex->nTime;
        unsigned int prevLogicalTS = 0;

        // retrieve logical timestamp of the previous block
        if (pindex->pprev)
            if (!pblocktree->ReadTimestampBlockIndex(pindex->pprev->GetBlockHash(), prevLogicalTS))
                LogPrintf("%s: Failed to read previous block's logical timestamp\n", __func__);

        if (logicalTS <= prevLogicalTS) {
            logicalTS = prevLogicalTS + 1;
            LogPrintf("%s: Previous logical timestamp is newer Actual[%d] prevLogical[%d] Logical[%d]\n", __func__, pindex->nTime, prevLogicalTS, logicalTS);
        }

        if (!pblocktree->WriteTimestampIndex(CTimestampIndexKey(logicalTS, pindex->GetBlockHash())))
            return AbortNode(state, "Failed to write timestamp index");

        if (!pblocktree->WriteTimestampBlockIndex(CTimestampBlockIndexKey(pindex->GetBlockHash()), CTimestampBlockIndexValue(logicalTS)))
            return AbortNode(state, "Failed to write blockhash index");
    }
    /////////////////////////////////////////////////////////////

    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime5 = GetTimeMicros(); nTimeIndex += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "    - Index writing: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime5 - nTime4), nTimeIndex * MICRO, nTimeIndex * MILLI / nBlocksTotal);

    int64_t nTime6 = GetTimeMicros(); nTimeCallbacks += nTime6 - nTime5;
    LogPrint(BCLog::BENCH, "    - Callbacks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime6 - nTime5), nTimeCallbacks * MICRO, nTimeCallbacks * MILLI / nBlocksTotal);

    if (fLogEvents)
        pstorageresult->commitResults();

    return true;
}

CoinsCacheSizeState CChainState::GetCoinsCacheSizeState(const CTxMemPool& tx_pool)
{
    return this->GetCoinsCacheSizeState(
        tx_pool,
        nCoinCacheUsage,
        gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000);
}

CoinsCacheSizeState CChainState::GetCoinsCacheSizeState(
    const CTxMemPool& tx_pool,
    size_t max_coins_cache_size_bytes,
    size_t max_mempool_size_bytes)
{
    int64_t nMempoolUsage = tx_pool.DynamicMemoryUsage();
    int64_t cacheSize = CoinsTip().DynamicMemoryUsage() * DB_PEAK_USAGE_FACTOR;
    int64_t nTotalSpace =
        max_coins_cache_size_bytes + std::max<int64_t>(max_mempool_size_bytes - nMempoolUsage, 0);

    //! No need to periodic flush if at least this much space still available.
    static constexpr int64_t MAX_BLOCK_COINSDB_USAGE_BYTES = 10 * 1024 * 1024;  // 10MB
    int64_t large_threshold =
        std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE_BYTES);

    if (cacheSize > nTotalSpace) {
        LogPrintf("Cache size (%s) exceeds total space (%s)\n", cacheSize, nTotalSpace);
        return CoinsCacheSizeState::CRITICAL;
    } else if (cacheSize > large_threshold) {
        return CoinsCacheSizeState::LARGE;
    }
    return CoinsCacheSizeState::OK;
}

bool CChainState::FlushStateToDisk(
    const CChainParams& chainparams,
    BlockValidationState &state,
    FlushStateMode mode,
    int nManualPruneHeight)
{
    LOCK(cs_main);
    assert(this->CanFlushToDisk());
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    std::set<int> setFilesToPrune;
    bool full_flush_completed = false;

    const size_t coins_count = CoinsTip().GetCacheSize();
    const size_t coins_mem_usage = CoinsTip().DynamicMemoryUsage();

    try {
    {
        bool fFlushForPrune = false;
        bool fDoFullFlush = false;
        CoinsCacheSizeState cache_state = GetCoinsCacheSizeState(::mempool);
        LOCK(cs_LastBlockFile);
        if (fPruneMode && (fCheckForPruning || nManualPruneHeight > 0) && !fReindex) {
            if (nManualPruneHeight > 0) {
                LOG_TIME_MILLIS("find files to prune (manual)", BCLog::BENCH);

                FindFilesToPruneManual(setFilesToPrune, nManualPruneHeight);
            } else {
                LOG_TIME_MILLIS("find files to prune", BCLog::BENCH);

                FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
                fCheckForPruning = false;
            }
            if (!setFilesToPrune.empty()) {
                fFlushForPrune = true;
                if (!fHavePruned) {
                    pblocktree->WriteFlag("prunedblockfiles", true);
                    fHavePruned = true;
                }
            }
        }
        int64_t nNow = GetTimeMicros();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite == 0) {
            nLastWrite = nNow;
        }
        if (nLastFlush == 0) {
            nLastFlush = nNow;
        }
        // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
        bool fCacheLarge = mode == FlushStateMode::PERIODIC && cache_state >= CoinsCacheSizeState::LARGE;
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FlushStateMode::IF_NEEDED && cache_state >= CoinsCacheSizeState::CRITICAL;
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FlushStateMode::PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FlushStateMode::PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
        // Combine all conditions that result in a full cache flush.
        fDoFullFlush = (mode == FlushStateMode::ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite) {
            // Depend on nMinDiskSpace to ensure we can write block index
            if (!CheckDiskSpace(GetBlocksDir())) {
                return AbortNode(state, "Disk space is too low!", _("Error: Disk space is too low!").translated, CClientUIInterface::MSG_NOPREFIX);
            }
            {
                LOG_TIME_MILLIS("write block and undo data to disk", BCLog::BENCH);

                // First make sure all block and undo data is flushed to disk.
                FlushBlockFile();
            }

            // Then update all block file information (which may refer to block and undo files).
            {
                LOG_TIME_MILLIS("write block index to disk", BCLog::BENCH);

                std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
                vFiles.reserve(setDirtyFileInfo.size());
                for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) {
                    vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                    setDirtyFileInfo.erase(it++);
                }
                std::vector<const CBlockIndex*> vBlocks;
                vBlocks.reserve(setDirtyBlockIndex.size());
                for (std::set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end(); ) {
                    vBlocks.push_back(*it);
                    setDirtyBlockIndex.erase(it++);
                }
                if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                    return AbortNode(state, "Failed to write to block index database");
                }
            }
            // Finally remove any pruned files
            if (fFlushForPrune) {
                LOG_TIME_MILLIS("unlink pruned files", BCLog::BENCH);

                UnlinkPrunedFiles(setFilesToPrune);
            }
            nLastWrite = nNow;
        }
        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush && !CoinsTip().GetBestBlock().IsNull()) {
            LOG_TIME_SECONDS(strprintf("write coins cache to disk (%d coins, %.2fkB)",
                coins_count, coins_mem_usage / 1000));

            // Typical Coin structures on disk are around 48 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(GetDataDir(), 48 * 2 * 2 * CoinsTip().GetCacheSize())) {
                return AbortNode(state, "Disk space is too low!", _("Error: Disk space is too low!").translated, CClientUIInterface::MSG_NOPREFIX);
            }
            // Flush the chainstate (which may refer to block index entries).
            if (!CoinsTip().Flush())
                return AbortNode(state, "Failed to write to coin database");
            nLastFlush = nNow;
            full_flush_completed = true;
        }
    }
    if (full_flush_completed) {
        // Update best block in wallet (so we can detect restored wallets).
        GetMainSignals().ChainStateFlushed(m_chain.GetLocator());
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void CChainState::ForceFlushStateToDisk() {
    BlockValidationState state;
    const CChainParams& chainparams = Params();
    if (!this->FlushStateToDisk(chainparams, state, FlushStateMode::ALWAYS)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, state.ToString());
    }
}

void CChainState::PruneAndFlush() {
    BlockValidationState state;
    fCheckForPruning = true;
    const CChainParams& chainparams = Params();

    if (!this->FlushStateToDisk(chainparams, state, FlushStateMode::NONE)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, state.ToString());
    }
}

static void DoWarning(const std::string& strWarning)
{
    static bool fWarned = false;
    SetMiscWarning(strWarning);
    if (!fWarned) {
        AlertNotify(strWarning);
        fWarned = true;
    }
}

/** Private helper function that concatenates warning messages. */
static void AppendWarning(std::string& res, const std::string& warn)
{
    if (!res.empty()) res += ", ";
    res += warn;
}

/** Check warning conditions and do some notifications on new chain tip set. */
void static UpdateTip(const CBlockIndex* pindexNew, const CChainParams& chainParams)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    // New best block
    mempool.AddTransactionsUpdated(1);

    {
        LOCK(g_best_block_mutex);
        g_best_block = pindexNew->GetBlockHash();
        g_best_block_cv.notify_all();
    }

    std::string warningMessages;
    if (!::ChainstateActive().IsInitialBlockDownload())
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexNew;
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.GetStateFor(pindex, chainParams.GetConsensus(), warningcache[bit]);
            if (state == ThresholdState::ACTIVE || state == ThresholdState::LOCKED_IN) {
                const std::string strWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)").translated, bit);
                if (state == ThresholdState::ACTIVE) {
                    DoWarning(strWarning);
                } else {
                    AppendWarning(warningMessages, strWarning);
                }
            }
        }
        // Check the version of the last 100 blocks to see if we need to upgrade:
        for (int i = 0; i < 100 && pindex != nullptr; i++)
        {
            int32_t nExpectedVersion = ComputeBlockVersion(pindex->pprev, chainParams.GetConsensus());
            if (pindex->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pindex->nVersion & ~nExpectedVersion) != 0)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            AppendWarning(warningMessages, strprintf(_("%d of last 100 blocks have unexpected version").translated, nUpgraded));
    }
    LogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight, pindexNew->nVersion,
      log(pindexNew->nChainWork.getdouble())/log(2.0), (unsigned long)pindexNew->nChainTx,
      FormatISO8601DateTime(pindexNew->GetBlockTime()),
      GuessVerificationProgress(chainParams.TxData(), pindexNew), ::ChainstateActive().CoinsTip().DynamicMemoryUsage() * (1.0 / (1<<20)), ::ChainstateActive().CoinsTip().GetCacheSize(),
      !warningMessages.empty() ? strprintf(" warning='%s'", warningMessages) : "");

}

/** Disconnect m_chain's tip.
  * After calling, the mempool will be in an inconsistent state, with
  * transactions from disconnected blocks being added to disconnectpool.  You
  * should make the mempool consistent again by calling UpdateMempoolForReorg.
  * with cs_main held.
  *
  * If disconnectpool is nullptr, then no disconnected transactions are added to
  * disconnectpool (note that the caller is responsible for mempool consistency
  * in any case).
  */
bool CChainState::DisconnectTip(BlockValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions *disconnectpool)
{
    CBlockIndex *pindexDelete = m_chain.Tip();
    assert(pindexDelete);
    // Read block from disk.
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()))
        return error("DisconnectTip(): Failed to read block");
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(&CoinsTip());
        assert(view.GetBestBlock() == pindexDelete->GetBlockHash());
        if (DisconnectBlock(block, pindexDelete, view, nullptr) != DISCONNECT_OK)
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        bool flushed = view.Flush();
        assert(flushed);
    }
    LogPrint(BCLog::BENCH, "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * MILLI);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::IF_NEEDED))
        return false;

    if (disconnectpool) {
        // Save transactions to re-add to mempool at end of reorg
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            disconnectpool->addTransaction(*it);
        }
        while (disconnectpool->DynamicMemoryUsage() > MAX_DISCONNECTED_TX_POOL_SIZE * 1000) {
            // Drop the earliest entry, and remove its children from the mempool.
            auto it = disconnectpool->queuedTx.get<insertion_order>().begin();
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
            disconnectpool->removeEntry(it);
        }
    }

    m_chain.SetTip(pindexDelete->pprev);

    UpdateTip(pindexDelete->pprev, chainparams);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    GetMainSignals().BlockDisconnected(pblock, pindexDelete);
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

struct PerBlockConnectTrace {
    CBlockIndex* pindex = nullptr;
    std::shared_ptr<const CBlock> pblock;
    PerBlockConnectTrace() {}
};
/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 *
 * This class is single-use, once you call GetBlocksConnected() you have to throw
 * it away and make a new one.
 */
class ConnectTrace {
private:
    std::vector<PerBlockConnectTrace> blocksConnected;

public:
    explicit ConnectTrace() : blocksConnected(1) {}

    void BlockConnected(CBlockIndex* pindex, std::shared_ptr<const CBlock> pblock) {
        assert(!blocksConnected.back().pindex);
        assert(pindex);
        assert(pblock);
        blocksConnected.back().pindex = pindex;
        blocksConnected.back().pblock = std::move(pblock);
        blocksConnected.emplace_back();
    }

    std::vector<PerBlockConnectTrace>& GetBlocksConnected() {
        // We always keep one extra block at the end of our list because
        // blocks are added after all the conflicted transactions have
        // been filled in. Thus, the last entry should always be an empty
        // one waiting for the transactions from the next block. We pop
        // the last entry here to make sure the list we return is sane.
        assert(!blocksConnected.back().pindex);
        blocksConnected.pop_back();
        return blocksConnected;
    }
};

/**
 * Connect a new block to m_chain. pblock is either nullptr or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 *
 * The block is added to connectTrace if connection succeeds.
 */
bool CChainState::ConnectTip(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool)
{
    assert(pindexNew->pprev == m_chain.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    std::shared_ptr<const CBlock> pthisBlock;
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        if (!ReadBlockFromDisk(*pblockNew, pindexNew, chainparams.GetConsensus()))
            return AbortNode(state, "Failed to read block");
        pthisBlock = pblockNew;
    } else {
        pthisBlock = pblock;
    }
    const CBlock& blockConnecting = *pthisBlock;
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint(BCLog::BENCH, "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * MILLI, nTimeReadFromDisk * MICRO);
    {
        CCoinsViewCache view(&CoinsTip());

        dev::h256 oldHashStateRoot(globalState->rootHash()); // qtum
        dev::h256 oldHashUTXORoot(globalState->rootHashUTXO()); // qtum

        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view, chainparams);
        GetMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);

            globalState->setRoot(oldHashStateRoot); // qtum
            globalState->setRootUTXO(oldHashUTXORoot); // qtum
            pstorageresult->clearCacheResult();
            return error("%s: ConnectBlock %s failed, %s", __func__, pindexNew->GetBlockHash().ToString(), state.ToString());
        }
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        assert(nBlocksTotal > 0);
        LogPrint(BCLog::BENCH, "  - Connect total: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime3 - nTime2) * MILLI, nTimeConnectTotal * MICRO, nTimeConnectTotal * MILLI / nBlocksTotal);
        bool flushed = view.Flush();
        assert(flushed);
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint(BCLog::BENCH, "  - Flush: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime4 - nTime3) * MILLI, nTimeFlush * MICRO, nTimeFlush * MILLI / nBlocksTotal);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros(); nTimeChainState += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "  - Writing chainstate: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime5 - nTime4) * MILLI, nTimeChainState * MICRO, nTimeChainState * MILLI / nBlocksTotal);
    // Remove conflicting transactions from the mempool.;
    mempool.removeForBlock(blockConnecting.vtx, pindexNew->nHeight);
    disconnectpool.removeForBlock(blockConnecting.vtx);
    // Update m_chain & related variables.
    m_chain.SetTip(pindexNew);
    UpdateTip(pindexNew, chainparams);

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint(BCLog::BENCH, "  - Connect postprocess: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime5) * MILLI, nTimePostConnect * MICRO, nTimePostConnect * MILLI / nBlocksTotal);
    LogPrint(BCLog::BENCH, "- Connect block: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime1) * MILLI, nTimeTotal * MICRO, nTimeTotal * MILLI / nBlocksTotal);

    connectTrace.BlockConnected(pindexNew, std::move(pthisBlock));
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
CBlockIndex* CChainState::FindMostWorkChain() {
    do {
        CBlockIndex *pindexNew = nullptr;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return nullptr;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !m_chain.Contains(pindexTest)) {
            assert(pindexTest->HaveTxsDownloaded() || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pindexBestInvalid == nullptr || pindexNew->nChainWork > pindexBestInvalid->nChainWork))
                    pindexBestInvalid = pindexNew;
                CBlockIndex *pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to m_blocks_unlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        m_blockman.m_blocks_unlinked.insert(
                            std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
void CChainState::PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, m_chain.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either nullptr or a pointer to a CBlock corresponding to pindexMostWork.
 *
 * @returns true unless a system error occurred
 */
bool CChainState::ActivateBestChainStep(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace)
{
    AssertLockHeld(cs_main);

    const CBlockIndex *pindexOldTip = m_chain.Tip();
    const CBlockIndex *pindexFork = m_chain.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (m_chain.Tip() && m_chain.Tip() != pindexFork) {
        if (!DisconnectTip(state, chainparams, &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            UpdateMempoolForReorg(disconnectpool, false);

            // If we're unable to disconnect a block during normal operation,
            // then that is a failure of our local system -- we should abort
            // rather than stay on a less work chain.
            AbortNode(state, "Failed to disconnect block; see debug.log for details");
            return false;
        }
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        for (CBlockIndex *pindexConnect : reverse_iterate(vpindexToConnect)) {
            if (!ConnectTip(state, chainparams, pindexConnect, pindexConnect == pindexMostWork ? pblock : std::shared_ptr<const CBlock>(), connectTrace, disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
                        InvalidChainFound(vpindexToConnect.front());
                    }
                    state = BlockValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    UpdateMempoolForReorg(disconnectpool, false);
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || m_chain.Tip()->nChainWork > pindexOldTip->nChainWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        UpdateMempoolForReorg(disconnectpool, true);
    }
    mempool.check(&CoinsTip());

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();

    return true;
}

static bool NotifyHeaderTip() LOCKS_EXCLUDED(cs_main) {
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = nullptr;
    CBlockIndex* pindexHeader = nullptr;
    {
        LOCK(cs_main);
        pindexHeader = pindexBestHeader;

        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = ::ChainstateActive().IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(fInitialBlockDownload, pindexHeader);
    }
    return fNotify;
}

static void LimitValidationInterfaceQueue() LOCKS_EXCLUDED(cs_main) {
    AssertLockNotHeld(cs_main);

    if (GetMainSignals().CallbacksPending() > 10) {
        SyncWithValidationInterfaceQueue();
    }
}

bool CChainState::ActivateBestChain(BlockValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!
    AssertLockNotHeld(cs_main);

    // ABC maintains a fair degree of expensive-to-calculate internal state
    // because this function periodically releases cs_main so that it does not lock up other threads for too long
    // during large connects - and to allow for e.g. the callback queue to drain
    // we use m_cs_chainstate to enforce mutual exclusion so that only one caller may execute this function at a time
    LOCK(m_cs_chainstate);

    CBlockIndex *pindexMostWork = nullptr;
    CBlockIndex *pindexNewTip = nullptr;
    int nStopAtHeight = gArgs.GetArg("-stopatheight", DEFAULT_STOPATHEIGHT);
    do {
        boost::this_thread::interruption_point();

        // Block until the validation queue drains. This should largely
        // never happen in normal operation, however may happen during
        // reindex, causing memory blowup if we run too far ahead.
        // Note that if a validationinterface callback ends up calling
        // ActivateBestChain this may lead to a deadlock! We should
        // probably have a DEBUG_LOCKORDER test for this in the future.
        LimitValidationInterfaceQueue();

        {
            LOCK2(cs_main, ::mempool.cs); // Lock transaction pool for at least as long as it takes for connectTrace to be consumed
            CBlockIndex* starting_tip = m_chain.Tip();
            bool blocks_connected = false;
            do {
                // We absolutely may not unlock cs_main until we've made forward progress
                // (with the exception of shutdown due to hardware issues, low disk space, etc).
                ConnectTrace connectTrace; // Destructed before cs_main is unlocked

                if (pindexMostWork == nullptr) {
                    pindexMostWork = FindMostWorkChain();
                }

                // Whether we have anything to do at all.
                if (pindexMostWork == nullptr || pindexMostWork == m_chain.Tip()) {
                    break;
                }

                bool fInvalidFound = false;
                std::shared_ptr<const CBlock> nullBlockPtr;
                if (!ActivateBestChainStep(state, chainparams, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace)) {
                    // A system error occurred
                    return false;
                }
                blocks_connected = true;

                if (fInvalidFound) {
                    // Wipe cache, we may need another branch now.
                    pindexMostWork = nullptr;
                }
                pindexNewTip = m_chain.Tip();

                for (const PerBlockConnectTrace& trace : connectTrace.GetBlocksConnected()) {
                    assert(trace.pblock && trace.pindex);
                    GetMainSignals().BlockConnected(trace.pblock, trace.pindex);
                }
            } while (!m_chain.Tip() || (starting_tip && CBlockIndexWorkComparator()(m_chain.Tip(), starting_tip)));
            if (!blocks_connected) return true;

            const CBlockIndex* pindexFork = m_chain.FindFork(starting_tip);
            bool fInitialDownload = IsInitialBlockDownload();

            // Notify external listeners about the new tip.
            // Enqueue while holding cs_main to ensure that UpdatedBlockTip is called in the order in which blocks are connected
            if (pindexFork != pindexNewTip) {
                // Notify ValidationInterface subscribers
                GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);

                // Always notify the UI if a new block tip was connected
                uiInterface.NotifyBlockTip(fInitialDownload, pindexNewTip);
            }
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        if (nStopAtHeight && pindexNewTip && pindexNewTip->nHeight >= nStopAtHeight) StartShutdown();

        // We check shutdown only after giving ActivateBestChainStep a chance to run once so that we
        // never shutdown before connecting the genesis block during LoadChainTip(). Previously this
        // caused an assert() failure during shutdown in such cases as the UTXO DB flushing checks
        // that the best block hash is non-null.
        if (ShutdownRequested())
            break;
    } while (pindexNewTip != pindexMostWork);
    CheckBlockIndex(chainparams.GetConsensus());

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::PERIODIC)) {
        return false;
    }

    return true;
}

bool ActivateBestChain(BlockValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    return ::ChainstateActive().ActivateBestChain(state, chainparams, std::move(pblock));
}

bool CChainState::PreciousBlock(BlockValidationState& state, const CChainParams& params, CBlockIndex *pindex)
{
    {
        LOCK(cs_main);
        if (pindex->nChainWork < m_chain.Tip()->nChainWork) {
            // Nothing to do, this block is not at the tip.
            return true;
        }
        if (m_chain.Tip()->nChainWork > nLastPreciousChainwork) {
            // The chain has been extended since the last call, reset the counter.
            nBlockReverseSequenceId = -1;
        }
        nLastPreciousChainwork = m_chain.Tip()->nChainWork;
        setBlockIndexCandidates.erase(pindex);
        pindex->nSequenceId = nBlockReverseSequenceId;
        if (nBlockReverseSequenceId > std::numeric_limits<int32_t>::min()) {
            // We can't keep reducing the counter if somebody really wants to
            // call preciousblock 2**31-1 times on the same set of tips...
            nBlockReverseSequenceId--;
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && pindex->HaveTxsDownloaded()) {
            setBlockIndexCandidates.insert(pindex);
            PruneBlockIndexCandidates();
        }
    }

    return ActivateBestChain(state, params, std::shared_ptr<const CBlock>());
}
bool PreciousBlock(BlockValidationState& state, const CChainParams& params, CBlockIndex *pindex) {
    return ::ChainstateActive().PreciousBlock(state, params, pindex);
}

bool CChainState::InvalidateBlock(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex)
{
    CBlockIndex* to_mark_failed = pindex;
    bool pindex_was_in_chain = false;
    int disconnected = 0;

    // We do not allow ActivateBestChain() to run while InvalidateBlock() is
    // running, as that could cause the tip to change while we disconnect
    // blocks.
    LOCK(m_cs_chainstate);

    // We'll be acquiring and releasing cs_main below, to allow the validation
    // callbacks to run. However, we should keep the block index in a
    // consistent state as we disconnect blocks -- in particular we need to
    // add equal-work blocks to setBlockIndexCandidates as we disconnect.
    // To avoid walking the block index repeatedly in search of candidates,
    // build a map once so that we can look up candidate blocks by chain
    // work as we go.
    std::multimap<const arith_uint256, CBlockIndex *> candidate_blocks_by_work;

    {
        LOCK(cs_main);
        for (const auto& entry : m_blockman.m_block_index) {
            CBlockIndex *candidate = entry.second;
            // We don't need to put anything in our active chain into the
            // multimap, because those candidates will be found and considered
            // as we disconnect.
            // Instead, consider only non-active-chain blocks that have at
            // least as much work as where we expect the new tip to end up.
            if (!m_chain.Contains(candidate) &&
                    !CBlockIndexWorkComparator()(candidate, pindex->pprev) &&
                    candidate->IsValid(BLOCK_VALID_TRANSACTIONS) &&
                    candidate->HaveTxsDownloaded()) {
                candidate_blocks_by_work.insert(std::make_pair(candidate->nChainWork, candidate));
            }
        }
    }

    // Disconnect (descendants of) pindex, and mark them invalid.
    while (true) {
        if (ShutdownRequested()) break;

        // Make sure the queue of validation callbacks doesn't grow unboundedly.
        LimitValidationInterfaceQueue();

        LOCK(cs_main);
        LOCK(::mempool.cs); // Lock for as long as disconnectpool is in scope to make sure UpdateMempoolForReorg is called after DisconnectTip without unlocking in between
        if (!m_chain.Contains(pindex)) break;
        pindex_was_in_chain = true;
        CBlockIndex *invalid_walk_tip = m_chain.Tip();

        // ActivateBestChain considers blocks already in m_chain
        // unconditionally valid already, so force disconnect away from it.
        DisconnectedBlockTransactions disconnectpool;
        bool ret = DisconnectTip(state, chainparams, &disconnectpool);
        // DisconnectTip will add transactions to disconnectpool.
        // Adjust the mempool to be consistent with the new tip, adding
        // transactions back to the mempool if disconnecting was successful,
        // and we're not doing a very deep invalidation (in which case
        // keeping the mempool up to date is probably futile anyway).
        UpdateMempoolForReorg(disconnectpool, /* fAddToMempool = */ (++disconnected <= 10) && ret);
        if (!ret) return false;
        assert(invalid_walk_tip->pprev == m_chain.Tip());

        // We immediately mark the disconnected blocks as invalid.
        // This prevents a case where pruned nodes may fail to invalidateblock
        // and be left unable to start as they have no tip candidates (as there
        // are no blocks that meet the "have data and are not invalid per
        // nStatus" criteria for inclusion in setBlockIndexCandidates).
        invalid_walk_tip->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(invalid_walk_tip);
        setBlockIndexCandidates.erase(invalid_walk_tip);
        setBlockIndexCandidates.insert(invalid_walk_tip->pprev);
        if (invalid_walk_tip->pprev == to_mark_failed && (to_mark_failed->nStatus & BLOCK_FAILED_VALID)) {
            // We only want to mark the last disconnected block as BLOCK_FAILED_VALID; its children
            // need to be BLOCK_FAILED_CHILD instead.
            to_mark_failed->nStatus = (to_mark_failed->nStatus ^ BLOCK_FAILED_VALID) | BLOCK_FAILED_CHILD;
            setDirtyBlockIndex.insert(to_mark_failed);
        }

        // Add any equal or more work headers to setBlockIndexCandidates
        auto candidate_it = candidate_blocks_by_work.lower_bound(invalid_walk_tip->pprev->nChainWork);
        while (candidate_it != candidate_blocks_by_work.end()) {
            if (!CBlockIndexWorkComparator()(candidate_it->second, invalid_walk_tip->pprev)) {
                setBlockIndexCandidates.insert(candidate_it->second);
                candidate_it = candidate_blocks_by_work.erase(candidate_it);
            } else {
                ++candidate_it;
            }
        }

        // Track the last disconnected block, so we can correct its BLOCK_FAILED_CHILD status in future
        // iterations, or, if it's the last one, call InvalidChainFound on it.
        to_mark_failed = invalid_walk_tip;
    }

    CheckBlockIndex(chainparams.GetConsensus());

    {
        LOCK(cs_main);
        if (m_chain.Contains(to_mark_failed)) {
            // If the to-be-marked invalid block is in the active chain, something is interfering and we can't proceed.
            return false;
        }

        // Mark pindex (or the last disconnected block) as invalid, even when it never was in the main chain
        to_mark_failed->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(to_mark_failed);
        setBlockIndexCandidates.erase(to_mark_failed);
        m_blockman.m_failed_blocks.insert(to_mark_failed);

        // If any new blocks somehow arrived while we were disconnecting
        // (above), then the pre-calculation of what should go into
        // setBlockIndexCandidates may have missed entries. This would
        // technically be an inconsistency in the block index, but if we clean
        // it up here, this should be an essentially unobservable error.
        // Loop back over all block index entries and add any missing entries
        // to setBlockIndexCandidates.
        BlockMap::iterator it = m_blockman.m_block_index.begin();
        while (it != m_blockman.m_block_index.end()) {
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->HaveTxsDownloaded() && !setBlockIndexCandidates.value_comp()(it->second, m_chain.Tip())) {
                setBlockIndexCandidates.insert(it->second);
            }
            it++;
        }

        InvalidChainFound(to_mark_failed);
    }

    // Only notify about a new block tip if the active chain was modified.
    if (pindex_was_in_chain) {
        uiInterface.NotifyBlockTip(IsInitialBlockDownload(), to_mark_failed->pprev);
    }
    return true;
}

bool InvalidateBlock(BlockValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex) {
    return ::ChainstateActive().InvalidateBlock(state, chainparams, pindex);
}

void CChainState::ResetBlockFailureFlags(CBlockIndex *pindex) {
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = m_blockman.m_block_index.begin();
    while (it != m_blockman.m_block_index.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->HaveTxsDownloaded() && setBlockIndexCandidates.value_comp()(m_chain.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) {
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = nullptr;
            }
            m_blockman.m_failed_blocks.erase(it->second);
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != nullptr) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
            m_blockman.m_failed_blocks.erase(pindex);
        }
        pindex = pindex->pprev;
    }
}

void ResetBlockFailureFlags(CBlockIndex *pindex) {
    return ::ChainstateActive().ResetBlockFailureFlags(pindex);
}

CBlockIndex* BlockManager::AddToBlockIndex(const CBlockHeader& block)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = m_block_index.find(hash);
    if (it != m_block_index.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(block);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = m_block_index.insert(std::make_pair(hash, pindexNew)).first;
    if (pindexNew->IsProofOfStake())
        ::ChainstateActive().setStakeSeen.insert(std::make_pair(pindexNew->prevoutStake, pindexNew->nTime));
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = m_block_index.find(block.hashPrevBlock);
    if (miPrev != m_block_index.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nTimeMax = (pindexNew->pprev ? std::max(pindexNew->pprev->nTimeMax, pindexNew->nTime) : pindexNew->nTime);
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);
    pindexNew->nStakeModifier = ComputeStakeModifier(pindexNew->pprev, block.IsProofOfWork() ? hash : block.prevoutStake.hash);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == nullptr || pindexBestHeader->nChainWork < pindexNew->nChainWork)
        pindexBestHeader = pindexNew;

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
void CChainState::ReceivedBlockTransactions(const CBlock& block, CBlockIndex* pindexNew, const FlatFilePos& pos, const Consensus::Params& consensusParams)
{
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    if (IsWitnessEnabled(pindexNew->pprev, consensusParams)) {
        pindexNew->nStatus |= BLOCK_OPT_WITNESS;
    }
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == nullptr || pindexNew->pprev->HaveTxsDownloaded()) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (m_chain.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pindex, m_chain.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = m_blockman.m_blocks_unlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                m_blockman.m_blocks_unlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            m_blockman.m_blocks_unlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }
}

static bool FindBlockPos(FlatFilePos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        bool out_of_space;
        size_t bytes_allocated = BlockFileSeq().Allocate(pos, nAddSize, out_of_space);
        if (out_of_space) {
            return AbortNode("Disk space is too low!", _("Error: Disk space is too low!").translated, CClientUIInterface::MSG_NOPREFIX);
        }
        if (bytes_allocated != 0 && fPruneMode) {
            fCheckForPruning = true;
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

static bool FindUndoPos(BlockValidationState &state, int nFile, FlatFilePos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    bool out_of_space;
    size_t bytes_allocated = UndoFileSeq().Allocate(pos, nAddSize, out_of_space);
    if (out_of_space) {
        return AbortNode(state, "Disk space is too low!", _("Error: Disk space is too low!").translated, CClientUIInterface::MSG_NOPREFIX);
    }
    if (bytes_allocated != 0 && fPruneMode) {
        fCheckForPruning = true;
    }

    return true;
}

bool CheckFirstCoinstakeOutput(const CBlock& block)
{
    // Coinbase output should be empty if proof-of-stake block
    int commitpos = GetWitnessCommitmentIndex(block);
    if(commitpos < 0)
    {
        if (block.vtx[0]->vout.size() != 1 || !block.vtx[0]->vout[0].IsEmpty())
            return false;
    }
    else
    {
        if (block.vtx[0]->vout.size() != 2 || !block.vtx[0]->vout[0].IsEmpty() || block.vtx[0]->vout[1].nValue)
            return false;
    }

    return true;
}

#ifdef ENABLE_WALLET
// novacoin: attempt to generate suitable proof-of-stake
bool SignBlock(std::shared_ptr<CBlock> pblock, CWallet& wallet, const CAmount& nTotalFees, uint32_t nTime, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoins, std::vector<COutPoint>& setDelegateCoins)
{
    // if we are trying to sign
    //    something except proof-of-stake block template
    if (!CheckFirstCoinstakeOutput(*pblock))
        return false;

    // if we are trying to sign
    //    a complete proof-of-stake block
    if (pblock->IsProofOfStake() && !pblock->vchBlockSigDlgt.empty())
        return true;

    CKey key;
    CMutableTransaction txCoinStake(*pblock->vtx[1]);
    uint32_t nTimeBlock = nTime;
    nTimeBlock &= ~STAKE_TIMESTAMP_MASK;
    std::vector<unsigned char> vchPoD;
    COutPoint headerPrevout;
    //original line:
    //int64_t nSearchInterval = IsProtocolV2(nBestHeight+1) ? 1 : nSearchTime - nLastCoinStakeSearchTime;
    //IsProtocolV2 mean POS 2 or higher, so the modified line is:
    if(wallet.IsStakeClosing()) return false;
    auto locked_chain = wallet.chain().lock();
    LOCK(wallet.cs_wallet);
    LegacyScriptPubKeyMan* spk_man = wallet.GetLegacyScriptPubKeyMan();
    if(!spk_man)
        return false;
    if (wallet.CreateCoinStake(*locked_chain, *spk_man, pblock->nBits, nTotalFees, nTimeBlock, txCoinStake, key, setCoins, setDelegateCoins, vchPoD, headerPrevout))
    {
        if (nTimeBlock >= ::ChainActive().Tip()->GetMedianTimePast()+1)
        {
            // make sure coinstake would meet timestamp protocol
            //    as it would be the same as the block timestamp
            pblock->nTime = nTimeBlock;
            pblock->vtx[1] = MakeTransactionRef(std::move(txCoinStake));
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
            pblock->prevoutStake = headerPrevout;

            // Check timestamp against prev
            if(pblock->GetBlockTime() <= ::ChainActive().Tip()->GetBlockTime() || FutureDrift(pblock->GetBlockTime()) < ::ChainActive().Tip()->GetBlockTime())
            {
                return false;
            }

            // Sign block
            if (::ChainActive().Height() + 1 >= Params().GetConsensus().nOfflineStakeHeight)
            {
                // append PoD to the end of the block header
                if(vchPoD.size() > 0)
                    pblock->SetProofOfDelegation(vchPoD);

                // append a signature to our block and ensure that is compact
                std::vector<unsigned char> vchSig;
                bool isSigned = key.SignCompact(pblock->GetHashWithoutSign(), vchSig);
                pblock->SetBlockSignature(vchSig);

                // check block header
                return isSigned && CheckHeaderPoS(*pblock, Params().GetConsensus());
            }
            else
            {
                // append a signature to our block and ensure that is LowS
                return key.Sign(pblock->GetHashWithoutSign(), pblock->vchBlockSigDlgt) &&
                           EnsureLowS(pblock->vchBlockSigDlgt) &&
                           CheckHeaderPoS(*pblock, Params().GetConsensus());
            }
        }
    }

    return false;
}
#endif

bool GetBlockPublicKey(const CBlock& block, std::vector<unsigned char>& vchPubKey)
{
    if (block.IsProofOfWork())
        return false;

    if (block.vchBlockSigDlgt.empty())
        return false;

    std::vector<valtype> vSolutions;
    const CTxOut& txout = block.vtx[1]->vout[1];
    txnouttype whichType = Solver(txout.scriptPubKey, vSolutions);

    if (whichType == TX_NONSTANDARD)
        return false;

    if (whichType == TX_PUBKEY)
    {
        vchPubKey = vSolutions[0];
        return true;
    }
    else
    {
        // Block signing key also can be encoded in the nonspendable output
        // This allows to not pollute UTXO set with useless outputs e.g. in case of multisig staking

        const CScript& script = txout.scriptPubKey;
        CScript::const_iterator pc = script.begin();
        opcodetype opcode;
        valtype vchPushValue;

        if (!script.GetOp(pc, opcode, vchPubKey))
            return false;
        if (opcode != OP_RETURN)
            return false;
        if (!script.GetOp(pc, opcode, vchPubKey))
            return false;
        if (!IsCompressedOrUncompressedPubKey(vchPubKey))
            return false;
        return true;
    }

    return false;
}

bool GetBlockDelegation(const CBlock& block, const uint160& staker, uint160& address, uint8_t& fee, CCoinsViewCache& view)
{
    // Check block parameters
    if (block.IsProofOfWork())
        return false;

    if (block.vchBlockSigDlgt.empty())
        return false;

    if (!block.HasProofOfDelegation())
        return false;

    if(block.vtx.size() < 1)
        return false;

    // Get the delegate
    std::string strMessage = staker.GetReverseHex();
    CKeyID keyid;
    if(!SignStr::GetKeyIdMessage(strMessage, block.GetProofOfDelegation(), keyid))
        return false;
    address = uint160(keyid);

    // Get the fee from the delegation contract
    uint8_t inFee = 0;
    if(!GetDelegationFeeFromContract(address, inFee))
        return false;

    bool delegateOutputExist = IsDelegateOutputExist(inFee);
    size_t minVoutSize = delegateOutputExist ? 3 : 2;
    if(block.vtx[1]->vin.size() < 1 ||
            block.vtx[1]->vout.size() < minVoutSize)
        return false;

    // Get the staker fee
    COutPoint prevout = block.vtx[1]->vin[0].prevout;
    CAmount nValueCoin = view.AccessCoin(prevout).out.nValue;
    if(nValueCoin <= 0)
        return false;

    CAmount nValueStaker = block.vtx[1]->vout[1].nValue - nValueCoin;
    CAmount nValueDelegate = delegateOutputExist ? block.vtx[1]->vout[2].nValue : 0;
    CAmount nReward = nValueStaker + nValueDelegate;
    if(nReward <= 0)
        return false;

    fee = (nValueStaker * 100 + nReward - 1) / nReward;
    if(inFee != fee)
        return false;

    return true;
}

bool CheckBlockSignature(const CBlock& block)
{
    std::vector<unsigned char> vchBlockSig = block.GetBlockSignature();
    if (block.IsProofOfWork())
        return vchBlockSig.empty();

    std::vector<unsigned char> vchPubKey;
    if(!GetBlockPublicKey(block, vchPubKey))
    {
        return false;
    }

    uint256 hash = block.GetHashWithoutSign();

    if(vchBlockSig.size() == CPubKey::COMPACT_SIGNATURE_SIZE)
    {
        CPubKey pubkey;
        if(pubkey.RecoverCompact(hash, vchBlockSig) && pubkey == CPubKey(vchPubKey))
            return true;
    }

    return CPubKey(vchPubKey).Verify(hash, vchBlockSig);
}

static bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true, bool fCheckPOS = true)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && block.IsProofOfWork() && !CheckHeaderPoW(block, consensusParams))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "high-hash", "proof of work failed");

    // Check proof of stake matches claimed amount
    if (fCheckPOS && !::ChainstateActive().IsInitialBlockDownload() && block.IsProofOfStake() && !CheckHeaderPoS(block, consensusParams))
        // May occur if behind on block chain sync
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-cb-header", "proof of stake failed");

    return true;
}

bool CheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW, false))
        return false;

    if (block.IsProofOfStake() &&  block.GetBlockTime() > FutureDrift(GetAdjustedTime()))
        return error("CheckBlock() : block timestamp too far in the future");

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-txnmrklroot", "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-txns-duplicate", "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-missing", "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-multiple", "more than one coinbase");

    //Don't allow contract opcodes in coinbase
    if(block.vtx[0]->HasOpSpend() || block.vtx[0]->HasCreateOrCall() || block.vtx[0]->HasOpSender()){
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-contract", "coinbase must not contain OP_SPEND, OP_CALL, OP_CREATE or OP_SENDER");
    }

    // Second transaction must be coinbase in case of PoS block, the rest must not be
    if (block.IsProofOfStake())
    {
        // Coinbase output should be empty if proof-of-stake block
        if (!CheckFirstCoinstakeOutput(block))
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-missing", "coinbase output not empty for proof-of-stake block");

        // Second transaction must be coinstake
        if (block.vtx.empty() || block.vtx.size() < 2 || !block.vtx[1]->IsCoinStake())
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-missing", "second tx is not coinstake");

        if(!block.HasProofOfDelegation())
        {
            //prevoutStake must exactly match the coinstake in the block body
            if(block.vtx[1]->vin.empty() || block.prevoutStake != block.vtx[1]->vin[0].prevout){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-invalid", "prevoutStake in block header does not match coinstake in block body");
            }
        }
        //the rest of the transactions must not be coinstake
        for (unsigned int i = 2; i < block.vtx.size(); i++)
            if (block.vtx[i]->IsCoinStake())
               return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-multiple", "more than one coinstake");

        //Don't allow contract opcodes in coinstake
        //We might allow this later, but it hasn't been tested enough to determine if safe
        if(block.vtx[1]->HasOpSpend() || block.vtx[1]->HasCreateOrCall() || block.vtx[1]->HasOpSender()){
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cs-contract", "coinstake must not contain OP_SPEND, OP_CALL, OP_CREATE or OP_SENDER");
        }
    }

    // Check proof-of-stake block signature
    if (fCheckSig && !CheckBlockSignature(block))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-signature", "bad proof-of-stake block signature");

    bool lastWasContract=false;
    // Check transactions
    // Must check for duplicate inputs (see CVE-2018-17144)
    for (const auto& tx : block.vtx) {
        TxValidationState tx_state;
        if (!CheckTransaction(*tx, tx_state)) {
            // CheckBlock() does context-free validation checks. The only
            // possible failures are consensus failures.
            assert(tx_state.GetResult() == TxValidationResult::TX_CONSENSUS);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, tx_state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), tx_state.GetDebugMessage()));
        }
        //OP_SPEND can only exist immediately after a contract tx in a block, or after another OP_SPEND
        //So, if the previous tx was not a contract tx, fail it.
        if(tx->HasOpSpend()){
            if(!lastWasContract){
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-opspend-tx", "OP_SPEND transaction without corresponding contract transaction");
            }
        }
        lastWasContract = tx->HasCreateOrCall() || tx->HasOpSpend();
    }

    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > dgpMaxBlockSigOps)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

bool IsWitnessEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    int height = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    return (height >= params.SegwitHeight);
}

int GetWitnessCommitmentIndex(const CBlock& block)
{
    int commitpos = -1;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            if (block.vtx[0]->vout[o].scriptPubKey.size() >= 38 && block.vtx[0]->vout[o].scriptPubKey[0] == OP_RETURN && block.vtx[0]->vout[o].scriptPubKey[1] == 0x24 && block.vtx[0]->vout[o].scriptPubKey[2] == 0xaa && block.vtx[0]->vout[o].scriptPubKey[3] == 0x21 && block.vtx[0]->vout[o].scriptPubKey[4] == 0xa9 && block.vtx[0]->vout[o].scriptPubKey[5] == 0xed) {
                commitpos = o;
            }
        }
    }
    return commitpos;
}

void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != -1 && IsWitnessEnabled(pindexPrev, consensusParams) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams, bool fProofOfStake)
{
    std::vector<unsigned char> commitment;
    int commitpos = GetWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (consensusParams.SegwitHeight != std::numeric_limits<int>::max()) {
        if (commitpos == -1) {
            uint256 witnessroot = BlockWitnessMerkleRoot(block, nullptr, &fProofOfStake);
            CHash256().Write(witnessroot.begin(), 32).Write(ret.data(), 32).Finalize(witnessroot.begin());
            CTxOut out;
            out.nValue = 0;
            out.scriptPubKey.resize(38);
            out.scriptPubKey[0] = OP_RETURN;
            out.scriptPubKey[1] = 0x24;
            out.scriptPubKey[2] = 0xaa;
            out.scriptPubKey[3] = 0x21;
            out.scriptPubKey[4] = 0xa9;
            out.scriptPubKey[5] = 0xed;
            memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
            commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            CMutableTransaction tx(*block.vtx[0]);
            tx.vout.push_back(out);
            block.vtx[0] = MakeTransactionRef(std::move(tx));
        }
    }
    UpdateUncommittedBlockStructures(block, pindexPrev, consensusParams);
    return commitment;
}

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock().
 *  NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const CChainParams& params, const CBlockIndex* pindexPrev, int64_t nAdjustedTime) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    assert(pindexPrev != nullptr);
    const int nHeight = pindexPrev->nHeight + 1;

    // Check proof of work
    const Consensus::Params& consensusParams = params.GetConsensus();
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams,block.IsProofOfStake()))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-diffbits", "incorrect difficulty value");

    // Check against checkpoints
    if (fCheckpointsEnabled) {
        // Don't accept any forks from the main chain prior to last checkpoint.
        // GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
        // g_blockman.m_block_index.
        CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(params.Checkpoints());
        if (pcheckpoint && nHeight < pcheckpoint->nHeight) {
            LogPrintf("ERROR: %s: forked chain older than last checkpoint (height %d)\n", __func__, nHeight);
            return state.Invalid(BlockValidationResult::BLOCK_CHECKPOINT, "bad-fork-prior-to-checkpoint");
        }
        if(!Checkpoints::CheckHardened(nHeight, block.GetHash(), params.Checkpoints())) {
            return state.Invalid(BlockValidationResult::BLOCK_CHECKPOINT, "bad-fork-hardened-checkpoint", strprintf("%s: expected hardened checkpoint at height %d", __func__, nHeight));
        }
    }

    // Check that the block satisfies synchronized checkpoint
    if (!Checkpoints::CheckSync(nHeight))
        return state.Invalid(BlockValidationResult::BLOCK_HEADER_SYNC, "bad-fork-prior-to-synch-checkpoint", strprintf("%s: forked chain older than synchronized checkpoint (height %d)", __func__, nHeight));

    // Check timestamp against prev
    if (pindexPrev && block.IsProofOfStake() && block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    if (block.IsProofOfStake() && block.GetBlockTime() > FutureDrift(nAdjustedTime))
        return state.Invalid(BlockValidationResult::BLOCK_TIME_FUTURE, "time-too-new", "block timestamp too far in the future");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    if((block.nVersion < 2 && nHeight >= consensusParams.BIP34Height) ||
       (block.nVersion < 3 && nHeight >= consensusParams.BIP66Height) ||
       (block.nVersion < 4 && nHeight >= consensusParams.BIP65Height))
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));

    return true;
}

/** NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    // Start enforcing BIP113 (Median Time Past).
    int nLockTimeFlags = 0;
    if (nHeight >= consensusParams.CSVHeight) {
        assert(pindexPrev != nullptr);
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                              ? pindexPrev->GetMedianTimePast()
                              : block.GetBlockTime();

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal", "non-final transaction");
        }
    }

    // Enforce rule that the coinbase starts with serialized block height
    if (nHeight >= consensusParams.BIP34Height)
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-height", "block height mismatch in coinbase");
        }
    }

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness reserved value (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness reserved value). In case there are
    //   multiple, the last one is used.
    bool fHaveWitness = false;
    if (nHeight >= consensusParams.SegwitHeight) {
        int commitpos = GetWitnessCommitmentIndex(block);
        if (commitpos != -1) {
            bool malleated = false;
            uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);
            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            if (block.vtx[0]->vin[0].scriptWitness.stack.size() != 1 || block.vtx[0]->vin[0].scriptWitness.stack[0].size() != 32) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-witness-nonce-size", strprintf("%s : invalid witness reserved value size", __func__));
            }
            CHash256().Write(hashWitness.begin(), 32).Write(&block.vtx[0]->vin[0].scriptWitness.stack[0][0], 32).Finalize(hashWitness.begin());
            if (memcmp(hashWitness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "bad-witness-merkle-match", strprintf("%s : witness merkle commitment mismatch", __func__));
            }
            fHaveWitness = true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    if (!fHaveWitness) {
      for (const auto& tx : block.vtx) {
            if (tx->HasWitness()) {
                return state.Invalid(BlockValidationResult::BLOCK_MUTATED, "unexpected-witness", strprintf("%s : unexpected witness data found", __func__));
            }
        }
    }

    return true;
}

bool CChainState::UpdateHashProof(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, CBlockIndex* pindex, CCoinsViewCache& view)
{
    int nHeight = pindex->nHeight;
    uint256 hash = block.GetHash();

    //reject proof of work at height consensusParams.nLastPOWBlock
    if (block.IsProofOfWork() && nHeight > consensusParams.nLastPOWBlock)
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "reject-pow", strprintf("UpdateHashProof() : reject proof-of-work at height %d", nHeight));
    
    // Check coinstake timestamp
    if (block.IsProofOfStake() && !CheckCoinStakeTimestamp(block.GetBlockTime()))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "timestamp-invalid", strprintf("UpdateHashProof() : coinstake timestamp violation nTimeBlock=%d", block.GetBlockTime()));

    // Check proof-of-work or proof-of-stake
    if (block.nBits != GetNextWorkRequired(pindex->pprev, &block, consensusParams,block.IsProofOfStake()))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-diffbits", strprintf("UpdateHashProof() : incorrect %s", block.IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));

    uint256 hashProof;
    // Verify hash target and signature of coinstake tx
    if (block.IsProofOfStake())
    {
        uint256 targetProofOfStake;
        if (!CheckProofOfStake(pindex->pprev, state, *block.vtx[1], block.nBits, block.nTime, block.GetProofOfDelegation(), block.prevoutStake, hashProof, targetProofOfStake, view))
        {
            return error("UpdateHashProof() : check proof-of-stake failed for block %s", hash.ToString());
        }
    }
    
    // PoW is checked in CheckBlock()
    if (block.IsProofOfWork())
    {
        hashProof = block.GetHash();
    }
    
    // Record proof hash value
    pindex->hashProof = hashProof;
    return true;
}

bool CheckPOS(const CBlockHeader& block, CBlockIndex* pindexPrev)
{
    // Determining if PoS is possible to be checked in the header
    int diff = pindexPrev->nHeight + 1 - ::ChainActive().Height();
    if(pindexPrev && block.IsProofOfStake() && !::ChainstateActive().IsInitialBlockDownload()
    // Additional check if not triggered initial block download, like when PoW blocks were initially created
    // CheckPOS is called after ContextualCheckBlockHeader where future block headers are not accepted
            && (diff < COINBASE_MATURITY))
    {
        // Old header not child of the Tip
        if(diff < -COINBASE_MATURITY)
            return true;

        // New header
        // Determining if the header is child of the Tip
        CBlockIndex* prev = pindexPrev;
        for(int i = 0; i < COINBASE_MATURITY; i++)
        {
            if(prev == ::ChainActive().Tip())
                return true;
            prev = prev->pprev;
        }
    }

    // PoS header proofs are not validated
    return false;
}

bool BlockManager::AcceptBlockHeader(const CBlockHeader& block, BlockValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf = m_block_index.find(hash);
    CBlockIndex *pindex = nullptr;
    if (hash != chainparams.GetConsensus().hashGenesisBlock) {
        if (miSelf != m_block_index.end()) {
            // Block header is already known.
            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                LogPrintf("ERROR: %s: block %s is marked invalid\n", __func__, hash.ToString());
                return state.Invalid(BlockValidationResult::BLOCK_CACHED_INVALID, "duplicate");
            }
            return true;
        }

        // Check for the checkpoint
        if (::ChainActive().Tip() && block.hashPrevBlock != ::ChainActive().Tip()->GetBlockHash())
        {
            // Extra checks to prevent "fill up memory by spamming with bogus blocks"
            const CBlockIndex* pcheckpoint = Checkpoints::AutoSelectSyncCheckpoint();
            int64_t deltaTime = block.GetBlockTime() - pcheckpoint->nTime;
            if (deltaTime < 0)
            {
                return state.Invalid(BlockValidationResult::BLOCK_HEADER_SYNC, "older-than-checkpoint", "AcceptBlockHeader(): Block with a timestamp before last checkpoint");
            }
        }

        // Check for the signiture encoding
        if (!CheckCanonicalBlockSignature(&block))
        {
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-signature-encoding", "AcceptBlockHeader(): bad block signature encoding");
        }

        // Get prev block index
        CBlockIndex* pindexPrev = nullptr;
        BlockMap::iterator mi = m_block_index.find(block.hashPrevBlock);
        if (mi == m_block_index.end()) {
            LogPrintf("ERROR: %s: prev block not found\n", __func__);
            return state.Invalid(BlockValidationResult::BLOCK_MISSING_PREV, "prev-blk-not-found");
        }
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK) {
            LogPrintf("ERROR: %s: prev block invalid\n", __func__);
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
        }
        if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
            return error("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString(), state.ToString());

        /* Determine if this block descends from any block which has been found
         * invalid (m_failed_blocks), then mark pindexPrev and any blocks between
         * them as failed. For example:
         *
         *                D3
         *              /
         *      B2 - C2
         *    /         \
         *  A             D2 - E2 - F2
         *    \
         *      B1 - C1 - D1 - E1
         *
         * In the case that we attempted to reorg from E1 to F2, only to find
         * C2 to be invalid, we would mark D2, E2, and F2 as BLOCK_FAILED_CHILD
         * but NOT D3 (it was not in any of our candidate sets at the time).
         *
         * In any case D3 will also be marked as BLOCK_FAILED_CHILD at restart
         * in LoadBlockIndex.
         */
        if (!pindexPrev->IsValid(BLOCK_VALID_SCRIPTS)) {
            // The above does not mean "invalid": it checks if the previous block
            // hasn't been validated up to BLOCK_VALID_SCRIPTS. This is a performance
            // optimization, in the common case of adding a new block to the tip,
            // we don't need to iterate over the failed blocks list.
            for (const CBlockIndex* failedit : m_failed_blocks) {
                if (pindexPrev->GetAncestor(failedit->nHeight) == failedit) {
                    assert(failedit->nStatus & BLOCK_FAILED_VALID);
                    CBlockIndex* invalid_walk = pindexPrev;
                    while (invalid_walk != failedit) {
                        invalid_walk->nStatus |= BLOCK_FAILED_CHILD;
                        setDirtyBlockIndex.insert(invalid_walk);
                        invalid_walk = invalid_walk->pprev;
                    }
                    LogPrintf("ERROR: %s: prev block invalid\n", __func__);
                    return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
                }
            }
        }

        // Reject proof of work at height consensusParams.nLastPOWBlock
        int nHeight = pindexPrev->nHeight + 1;
        if (block.IsProofOfWork() && nHeight > chainparams.GetConsensus().nLastPOWBlock)
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "reject-pow", strprintf("reject proof-of-work at height %d", nHeight));

        if(block.IsProofOfStake())
        {
            // Reject proof of stake before height COINBASE_MATURITY
            if (nHeight < COINBASE_MATURITY)
                return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "reject-pos", strprintf("reject proof-of-stake at height %d", nHeight));

            // Check coin stake timestamp
            if(!CheckCoinStakeTimestamp(block.nTime))
                return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "timestamp-invalid", "proof of stake failed due to invalid timestamp");
        }

        // Check block header
        // if (!CheckBlockHeader(block, state, chainparams.GetConsensus(), true, CheckPOS(block, pindexPrev)))
        if (!CheckBlockHeader(block, state, chainparams.GetConsensus()))
            return error("%s: Consensus::CheckBlockHeader: %s, %s", __func__, hash.ToString(), state.ToString());
    }
    if (pindex == nullptr)
        pindex = AddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& headers, BlockValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex,  const CBlockIndex** pindexFirst)
{
    if(!::ChainstateActive().IsInitialBlockDownload() && headers.size() > 1) {
        const CBlockHeader last_header = headers[headers.size()-1];
        if (last_header.IsProofOfStake() && last_header.GetBlockTime() > FutureDrift(GetAdjustedTime())) {
            return state.Invalid(BlockValidationResult::BLOCK_TIME_FUTURE, "time-too-new", "block timestamp too far in the future");
        }
    }

    {
        LOCK(cs_main);
        bool bFirst = true;
        bool fInstantBan = false;
        for (size_t i = 0; i < headers.size(); ++i) {
            const CBlockHeader& header = headers[i];

            // If the stake has been seen and the header has not yet been seen
            if (!fReindex && !fImporting && !::ChainstateActive().IsInitialBlockDownload() && header.IsProofOfStake() && ::ChainstateActive().setStakeSeen.count(std::make_pair(header.prevoutStake, header.nTime)) && !::BlockIndex().count(header.GetHash())) {
                // if it is the last header of the list
                if(i+1 == headers.size()) {
                    if(fInstantBan) {
                        // if we've seen a dupe stake header already in this list, then instaban
                        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "dupe-stake", strprintf("%s: duplicate proof-of-stake instant ban (%s, %d) for header %s", __func__, header.prevoutStake.ToString(), header.nTime, header.GetHash().ToString()));
                    } else {
                        // otherwise just reject the block until it is part of a longer list
                        return state.Invalid(BlockValidationResult::BLOCK_HEADER_REJECT, "dupe-stake", strprintf("%s: duplicate proof-of-stake (%s, %d) for header %s", __func__, header.prevoutStake.ToString(), header.nTime, header.GetHash().ToString()));
                    }
                } else {
                    // if it is not part of the longest chain, then any error on a subsequent header should result in an instant ban
                    fInstantBan = true;
                }
            }

            CBlockIndex *pindex = nullptr; // Use a temp pindex instead of ppindex to avoid a const_cast
            bool accepted = g_blockman.AcceptBlockHeader(header, state, chainparams, &pindex);
            ::ChainstateActive().CheckBlockIndex(chainparams.GetConsensus());

            if (!accepted) {
                // if we have seen a duplicate stake in this header list previously, then ban immediately.
                if(fInstantBan) {
                    state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, state.GetRejectReason(), "instant ban, due to duplicate header in the chain");
                }
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
                if(bFirst && pindexFirst)
                {
                    *pindexFirst = pindex;
                    bFirst = false;
                }
            }
        }
    }
    if (NotifyHeaderTip()) {
        if (::ChainstateActive().IsInitialBlockDownload() && ppindex && *ppindex) {
            LogPrintf("Synchronizing blockheaders, height: %d (~%.2f%%)\n", (*ppindex)->nHeight, 100.0/((*ppindex)->nHeight+(GetAdjustedTime() - (*ppindex)->GetBlockTime()) / Params().GetConsensus().nPowTargetSpacing) * (*ppindex)->nHeight);
        }
    }
    return true;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
static FlatFilePos SaveBlockToDisk(const CBlock& block, int nHeight, const CChainParams& chainparams, const FlatFilePos* dbp) {
    unsigned int nBlockSize = ::GetSerializeSize(block, CLIENT_VERSION);
    FlatFilePos blockPos;
    if (dbp != nullptr)
        blockPos = *dbp;
    if (!FindBlockPos(blockPos, nBlockSize+8, nHeight, block.GetBlockTime(), dbp != nullptr)) {
        error("%s: FindBlockPos failed", __func__);
        return FlatFilePos();
    }
    if (dbp == nullptr) {
        if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart())) {
            AbortNode("Failed to write block");
            return FlatFilePos();
        }
    }
    return blockPos;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
bool CChainState::AcceptBlock(const std::shared_ptr<const CBlock>& pblock, BlockValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const FlatFilePos* dbp, bool* fNewBlock)
{
    const CBlock& block = *pblock;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex *pindexDummy = nullptr;
    CBlockIndex *&pindex = ppindex ? *ppindex : pindexDummy;

    bool accepted_header = m_blockman.AcceptBlockHeader(block, state, chainparams, &pindex);
    CheckBlockIndex(chainparams.GetConsensus());

    if (!accepted_header)
        return false;

    if(block.IsProofOfWork()) {
        if (!UpdateHashProof(block, state, chainparams.GetConsensus(), pindex, CoinsTip()))
        {
            return error("%s: AcceptBlock(): %s", __func__, state.GetRejectReason().c_str());
        }
    }

    // Get prev block index
    CBlockIndex* pindexPrev = nullptr;
    if(pindex->nHeight > 0){
        BlockMap::iterator mi = g_blockman.m_block_index.find(block.hashPrevBlock);
        if (mi == g_blockman.m_block_index.end())
            return state.Invalid(BlockValidationResult::BLOCK_MISSING_PREV, "prev-blk-not-found", strprintf("%s: prev block not found", __func__));
        pindexPrev = (*mi).second;
    }

    // Get block height
    int nHeight = pindex->nHeight;

    // Check for the last proof of work block
    if (block.IsProofOfWork() && nHeight > chainparams.GetConsensus().nLastPOWBlock)
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "reject-pow", strprintf("%s: reject proof-of-work at height %d", __func__, nHeight));

    // Check that the block satisfies synchronized checkpoint
    if (!Checkpoints::CheckSync(nHeight))
        return error("AcceptBlock() : rejected by synchronized checkpoint");

    // Check timestamp against prev
    if (pindexPrev && block.IsProofOfStake() && (block.GetBlockTime() <= pindexPrev->GetBlockTime() || FutureDrift(block.GetBlockTime()) < pindexPrev->GetBlockTime()))
        return error("AcceptBlock() : block's timestamp is too early");

    // Check timestamp
    if (block.IsProofOfStake() &&  block.GetBlockTime() > FutureDrift(GetAdjustedTime()))
        return error("AcceptBlock() : block timestamp too far in the future");

    // Enforce rule that the coinbase starts with serialized block height
    if (nHeight >= chainparams.GetConsensus().BIP34Height)
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin()))
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-height", "block height mismatch in coinbase");
    }

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreWork = (m_chain.Tip() ? pindex->nChainWork > m_chain.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(m_chain.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain data structure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (pindex->nTx != 0) return true;    // This is a previously-processed block that was pruned
        if (!fHasMoreWork) return true; // Don't process less-work OR equal-work chains
        if (fTooFarAhead) return true;        // Block height is too high

        // Protect against DoS attacks from low-work chains.
        // If our tip is behind, a peer could try to send us
        // low-work blocks on a fake chain that we would never
        // request; don't process these.
        if (pindex->nChainWork < nMinimumChainWork) return true;
    }

    if (!CheckBlock(block, state, chainparams.GetConsensus()) ||
        !ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindex->pprev)) {
        if (state.IsInvalid() && state.GetResult() != BlockValidationResult::BLOCK_MUTATED) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return error("%s: %s", __func__, state.ToString());
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    //if (!IsInitialBlockDownload() && m_chain.Tip() == pindex->pprev)
    //    GetMainSignals().NewPoWValidBlock(pindex, pblock);

    // Write block to history file
    if (fNewBlock) *fNewBlock = true;
    try {
        FlatFilePos blockPos = SaveBlockToDisk(block, pindex->nHeight, chainparams, dbp);
        if (blockPos.IsNull()) {
            state.Error(strprintf("%s: Failed to find position to write new block to disk", __func__));
            return false;
        }
        ReceivedBlockTransactions(block, pindex, blockPos, chainparams.GetConsensus());
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    FlushStateToDisk(chainparams, state, FlushStateMode::NONE);

    CheckBlockIndex(chainparams.GetConsensus());

    return true;
}

bool IsCanonicalBlockSignature(const CBlockHeader* pblock, bool checkLowS)
{
    if (pblock->IsProofOfWork()) {
        return pblock->vchBlockSigDlgt.empty();
    }

    return checkLowS ? IsLowDERSignature(pblock->vchBlockSigDlgt, NULL, false) : IsDERSignature(pblock->vchBlockSigDlgt, NULL, false);
}

bool CheckCanonicalBlockSignature(const CBlockHeader* pblock)
{
    // Check compact signature size
    if(pblock->IsProofOfStake() && pblock->GetBlockSignature().size() == CPubKey::COMPACT_SIGNATURE_SIZE)
        return pblock->HasProofOfDelegation() ? pblock->GetProofOfDelegation().size() == CPubKey::COMPACT_SIGNATURE_SIZE : true;

    //block signature encoding
    bool ret = IsCanonicalBlockSignature(pblock, false);

    //block signature encoding (low-s)
    if(ret) ret = IsCanonicalBlockSignature(pblock, true);

    return ret;
}

bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool *fNewBlock)
{
    AssertLockNotHeld(cs_main);

    {
        CBlockIndex *pindex = nullptr;
        if (fNewBlock) *fNewBlock = false;
        BlockValidationState state;

        // CheckBlock() does not support multi-threaded block validation because CBlock::fChecked can cause data race.
        // Therefore, the following critical section must include the CheckBlock() call as well.
        LOCK(cs_main);

        // Ensure that CheckBlock() passes before calling AcceptBlock, as
        // belt-and-suspenders.
        bool ret = CheckBlock(*pblock, state, chainparams.GetConsensus());
        if (ret) {
            // Store to disk
            ret = ::ChainstateActive().AcceptBlock(pblock, state, chainparams, &pindex, fForceProcessing, nullptr, fNewBlock);
        }
        if (!ret) {
            GetMainSignals().BlockChecked(*pblock, state);
            return error("%s: AcceptBlock FAILED (%s)", __func__, state.ToString());
        }
    }

    NotifyHeaderTip();

    BlockValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!::ChainstateActive().ActivateBestChain(state, chainparams, pblock))
        return error("%s: ActivateBestChain failed (%s)", __func__, state.ToString());

    return true;
}

bool TestBlockValidity(BlockValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW, bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == ::ChainActive().Tip());
    CCoinsViewCache viewNew(&::ChainstateActive().CoinsTip());
    uint256 block_hash(block.GetHash());
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;
    indexDummy.phashBlock = &block_hash;

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
        return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, state.ToString());
    if (!CheckBlock(block, state, chainparams.GetConsensus(), fCheckPOW, fCheckMerkleRoot))
        return error("%s: Consensus::CheckBlock: %s", __func__, state.ToString());
    if (!ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindexPrev))
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__, state.ToString());

    dev::h256 oldHashStateRoot(globalState->rootHash()); // qtum
    dev::h256 oldHashUTXORoot(globalState->rootHashUTXO()); // qtum
    
    if (!::ChainstateActive().ConnectBlock(block, state, &indexDummy, viewNew, chainparams, true)){
        
        globalState->setRoot(oldHashStateRoot); // qtum
        globalState->setRootUTXO(oldHashUTXORoot); // qtum
        pstorageresult->clearCacheResult();
        return false;
    }
    assert(state.IsValid());

    return true;
}

/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    LOCK(cs_LastBlockFile);

    uint64_t retval = 0;
    for (const CBlockFileInfo &file : vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

/* Prune a block file (modify associated database entries)*/
void PruneOneBlockFile(const int fileNumber)
{
    LOCK(cs_LastBlockFile);

    for (const auto& entry : g_blockman.m_block_index) {
        CBlockIndex* pindex = entry.second;
        if (pindex->nFile == fileNumber) {
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex.insert(pindex);

            // Prune from m_blocks_unlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // m_blocks_unlinked or setBlockIndexCandidates.
            auto range = g_blockman.m_blocks_unlinked.equal_range(pindex->pprev);
            while (range.first != range.second) {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator _it = range.first;
                range.first++;
                if (_it->second == pindex) {
                    g_blockman.m_blocks_unlinked.erase(_it);
                }
            }
        }
    }

    vinfoBlockFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}


void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune)
{
    for (std::set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        FlatFilePos pos(*it, 0);
        fs::remove(BlockFileSeq().FileName(pos));
        fs::remove(UndoFileSeq().FileName(pos));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* Calculate the block/rev files to delete based on height specified by user with RPC command pruneblockchain */
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight)
{
    assert(fPruneMode && nManualPruneHeight > 0);

    LOCK2(cs_main, cs_LastBlockFile);
    if (::ChainActive().Tip() == nullptr)
        return;

    // last block to prune is the lesser of (user-specified height, MIN_BLOCKS_TO_KEEP from the tip)
    unsigned int nLastBlockWeCanPrune = std::min((unsigned)nManualPruneHeight, ::ChainActive().Tip()->nHeight - MIN_BLOCKS_TO_KEEP);
    int count=0;
    for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
        if (vinfoBlockFile[fileNumber].nSize == 0 || vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
            continue;
        PruneOneBlockFile(fileNumber);
        setFilesToPrune.insert(fileNumber);
        count++;
    }
    LogPrintf("Prune (Manual): prune_height=%d removed %d blk/rev pairs\n", nLastBlockWeCanPrune, count);
}

/* This function is called from the RPC code for pruneblockchain */
void PruneBlockFilesManual(int nManualPruneHeight)
{
    BlockValidationState state;
    const CChainParams& chainparams = Params();
    if (!::ChainstateActive().FlushStateToDisk(
            chainparams, state, FlushStateMode::NONE, nManualPruneHeight)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, state.ToString());
    }
}

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet, 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBlockFile);
    if (::ChainActive().Tip() == nullptr || nPruneTarget == 0) {
        return;
    }
    if ((uint64_t)::ChainActive().Tip()->nHeight <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBlockWeCanPrune = ::ChainActive().Tip()->nHeight - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count=0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        // On a prune event, the chainstate DB is flushed.
        // To avoid excessive prune events negating the benefit of high dbcache
        // values, we should not prune too rapidly.
        // So when pruning in IBD, increase the buffer a bit to avoid a re-prune too soon.
        if (::ChainstateActive().IsInitialBlockDownload()) {
            // Since this is only relevant during IBD, we use a fixed 10%
            nBuffer += nPruneTarget / 10;
        }

        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget)  // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            PruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint(BCLog::PRUNE, "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
           nPruneTarget/1024/1024, nCurrentUsage/1024/1024,
           ((int64_t)nPruneTarget - (int64_t)nCurrentUsage)/1024/1024,
           nLastBlockWeCanPrune, count);
}

static FlatFileSeq BlockFileSeq()
{
    return FlatFileSeq(GetBlocksDir(), "blk", BLOCKFILE_CHUNK_SIZE);
}

static FlatFileSeq UndoFileSeq()
{
    return FlatFileSeq(GetBlocksDir(), "rev", UNDOFILE_CHUNK_SIZE);
}

FILE* OpenBlockFile(const FlatFilePos &pos, bool fReadOnly) {
    return BlockFileSeq().Open(pos, fReadOnly);
}

/** Open an undo file (rev?????.dat) */
static FILE* OpenUndoFile(const FlatFilePos &pos, bool fReadOnly) {
    return UndoFileSeq().Open(pos, fReadOnly);
}

fs::path GetBlockPosFilename(const FlatFilePos &pos)
{
    return BlockFileSeq().FileName(pos);
}

CBlockIndex * BlockManager::InsertBlockIndex(const uint256& hash)
{
    AssertLockHeld(cs_main);

    if (hash.IsNull())
        return nullptr;

    // Return existing
    BlockMap::iterator mi = m_block_index.find(hash);
    if (mi != m_block_index.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    mi = m_block_index.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool BlockManager::LoadBlockIndex(
    const Consensus::Params& consensus_params,
    CBlockTreeDB& blocktree,
    std::set<CBlockIndex*, CBlockIndexWorkComparator>& block_index_candidates)
{
    if (!blocktree.LoadBlockIndexGuts(consensus_params, [this](const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return this->InsertBlockIndex(hash); }))
        return false;

    // Calculate nChainWork
    std::vector<std::pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(m_block_index.size());
    for (const std::pair<const uint256, CBlockIndex*>& item : m_block_index)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for (const std::pair<int, CBlockIndex*>& item : vSortedByHeight)
    {
        if (ShutdownRequested()) return false;
        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + GetBlockProof(*pindex);
        pindex->nTimeMax = (pindex->pprev ? std::max(pindex->pprev->nTimeMax, pindex->nTime) : pindex->nTime);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->pprev->HaveTxsDownloaded()) {
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                } else {
                    pindex->nChainTx = 0;
                    m_blocks_unlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            } else {
                pindex->nChainTx = pindex->nTx;
            }
        }
        if (!(pindex->nStatus & BLOCK_FAILED_MASK) && pindex->pprev && (pindex->pprev->nStatus & BLOCK_FAILED_MASK)) {
            pindex->nStatus |= BLOCK_FAILED_CHILD;
            setDirtyBlockIndex.insert(pindex);
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->HaveTxsDownloaded() || pindex->pprev == nullptr)) {
            block_index_candidates.insert(pindex);
        }
        if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->nChainWork > pindexBestInvalid->nChainWork))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == nullptr || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
            pindexBestHeader = pindex;
    }

    return true;
}

void BlockManager::Unload() {
    m_failed_blocks.clear();
    m_blocks_unlinked.clear();

    for (const BlockMap::value_type& entry : m_block_index) {
        delete entry.second;
    }

    m_block_index.clear();
}

bool static LoadBlockIndexDB(const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!g_blockman.LoadBlockIndex(
            chainparams.GetConsensus(), *pblocktree, ::ChainstateActive().setBlockIndexCandidates))
        return false;

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    for (const std::pair<const uint256, CBlockIndex*>& item : g_blockman.m_block_index)
    {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++)
    {
        FlatFilePos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
    pblocktree->ReadFlag("prunedblockfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    if(fReindexing) fReindex = true;

    ///////////////////////////////////////////////////////////// // qtum
    pblocktree->ReadFlag("addrindex", fAddressIndex);
    LogPrintf("LoadBlockIndexDB(): address index %s\n", fAddressIndex ? "enabled" : "disabled");
    /////////////////////////////////////////////////////////////
    // Check whether we have a transaction index
    pblocktree->ReadFlag("logevents", fLogEvents);
    LogPrintf("%s: log events index %s\n", __func__, fLogEvents ? "enabled" : "disabled");

    return true;
}

bool CChainState::LoadChainTip(const CChainParams& chainparams)
{
    AssertLockHeld(cs_main);
    const CCoinsViewCache& coins_cache = CoinsTip();
    assert(!coins_cache.GetBestBlock().IsNull()); // Never called when the coins view is empty
    const CBlockIndex* tip = m_chain.Tip();

    if (tip && tip->GetBlockHash() == coins_cache.GetBestBlock()) {
        return true;
    }

    // Load pointer to end of best chain
    CBlockIndex* pindex = LookupBlockIndex(coins_cache.GetBestBlock());
    if (!pindex) {
        return false;
    }
    m_chain.SetTip(pindex);
    PruneBlockIndexCandidates();

    tip = m_chain.Tip();
    LogPrintf("Loaded best chain: hashBestChain=%s height=%d date=%s progress=%f\n",
        tip->GetBlockHash().ToString(),
        m_chain.Height(),
        FormatISO8601DateTime(tip->GetBlockTime()),
        GuessVerificationProgress(chainparams.TxData(), tip));
    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying blocks...").translated, 0, false);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100, false);
}

bool CVerifyDB::VerifyDB(const CChainParams& chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth)
{
    LOCK(cs_main);
    if (::ChainActive().Tip() == nullptr || ::ChainActive().Tip()->pprev == nullptr)
        return true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > ::ChainActive().Height())
        nCheckDepth = ::ChainActive().Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBlockIndex* pindex;
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    BlockValidationState state;
    int reportDone = 0;

////////////////////////////////////////////////////////////////////////// // qtum
    dev::h256 oldHashStateRoot(globalState->rootHash());
    dev::h256 oldHashUTXORoot(globalState->rootHashUTXO());
    QtumDGP qtumDGP(globalState.get(), fGettingValuesDGP);
//////////////////////////////////////////////////////////////////////////

    LogPrintf("[0%%]..."); /* Continued */
    for (pindex = ::ChainActive().Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
        boost::this_thread::interruption_point();
        const int percentageDone = std::max(1, std::min(99, (int)(((double)(::ChainActive().Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone/10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone); /* Continued */
            reportDone = percentageDone/10;
        }
        uiInterface.ShowProgress(_("Verifying blocks...").translated, percentageDone, false);
        if (pindex->nHeight <= ::ChainActive().Height()-nCheckDepth)
            break;
        if (fPruneMode && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            LogPrintf("VerifyDB(): block verification stopping at height %d (pruning, no data)\n", pindex->nHeight);
            break;
        }

        ///////////////////////////////////////////////////////////////////// // qtum
        uint32_t sizeBlockDGP = qtumDGP.getBlockSize(pindex->nHeight);
        dgpMaxBlockSize = sizeBlockDGP ? sizeBlockDGP : dgpMaxBlockSize;
        updateBlockSizeParams(dgpMaxBlockSize);
        /////////////////////////////////////////////////////////////////////

        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
            return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, chainparams.GetConsensus(),false))
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__,
                         pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString());
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            if (!pindex->GetUndoPos().IsNull()) {
                if (!UndoReadFromDisk(undo, pindex)) {
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                }
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && (coins.DynamicMemoryUsage() + ::ChainstateActive().CoinsTip().DynamicMemoryUsage()) <= nCoinCacheUsage) {
            assert(coins.GetBestBlock() == pindex->GetBlockHash());
            bool fClean=true;
            DisconnectResult res = ::ChainstateActive().DisconnectBlock(block, pindex, coins, &fClean);
            if (res == DISCONNECT_FAILED) {
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", ::ChainActive().Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // store block count as we move pindex at check level >= 4
    int block_count = ::ChainActive().Height() - pindex->nHeight;

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        while (pindex != ::ChainActive().Tip()) {
            boost::this_thread::interruption_point();
            const int percentageDone = std::max(1, std::min(99, 100 - (int)(((double)(::ChainActive().Height() - pindex->nHeight)) / (double)nCheckDepth * 50)));
            if (reportDone < percentageDone/10) {
                // report every 10% step
                LogPrintf("[%d%%]...", percentageDone); /* Continued */
                reportDone = percentageDone/10;
            }
            uiInterface.ShowProgress(_("Verifying blocks...").translated, percentageDone, false);
            pindex = ::ChainActive().Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());

            dev::h256 oldHashStateRoot(globalState->rootHash()); // qtum
            dev::h256 oldHashUTXORoot(globalState->rootHashUTXO()); // qtum

            if (!::ChainstateActive().ConnectBlock(block, state, pindex, coins, chainparams)){

                globalState->setRoot(oldHashStateRoot); // qtum
                globalState->setRootUTXO(oldHashUTXORoot); // qtum
                pstorageresult->clearCacheResult();
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s (%s)", pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString());
            }
        }
    } else {
        globalState->setRoot(oldHashStateRoot); // qtum
        globalState->setRootUTXO(oldHashUTXORoot); // qtum
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", block_count, nGoodTransactions);

    return true;
}

/** Apply the effects of a block on the utxo cache, ignoring that it may already have been applied. */
bool CChainState::RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params)
{
    // TODO: merge with ConnectBlock
    CBlock block;
    if (!ReadBlockFromDisk(block, pindex, params.GetConsensus())) {
        return error("ReplayBlock(): ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
    }

    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn &txin : tx->vin) {
                inputs.SpendCoin(txin.prevout);
            }
        }
        // Pass check = true as every addition may be an overwrite.
        AddCoins(inputs, *tx, pindex->nHeight, true);
    }
    return true;
}

bool CChainState::ReplayBlocks(const CChainParams& params)
{
    LOCK(cs_main);

    CCoinsView& db = this->CoinsDB();
    CCoinsViewCache cache(&db);

    std::vector<uint256> hashHeads = db.GetHeadBlocks();
    if (hashHeads.empty()) return true; // We're already in a consistent state.
    if (hashHeads.size() != 2) return error("ReplayBlocks(): unknown inconsistent state");

    uiInterface.ShowProgress(_("Replaying blocks...").translated, 0, false);
    LogPrintf("Replaying blocks\n");

    const CBlockIndex* pindexOld = nullptr;  // Old tip during the interrupted flush.
    const CBlockIndex* pindexNew;            // New tip during the interrupted flush.
    const CBlockIndex* pindexFork = nullptr; // Latest block common to both the old and the new tip.

    if (m_blockman.m_block_index.count(hashHeads[0]) == 0) {
        return error("ReplayBlocks(): reorganization to unknown block requested");
    }
    pindexNew = m_blockman.m_block_index[hashHeads[0]];

    if (!hashHeads[1].IsNull()) { // The old tip is allowed to be 0, indicating it's the first flush.
        if (m_blockman.m_block_index.count(hashHeads[1]) == 0) {
            return error("ReplayBlocks(): reorganization from unknown block requested");
        }
        pindexOld = m_blockman.m_block_index[hashHeads[1]];
        pindexFork = LastCommonAncestor(pindexOld, pindexNew);
        assert(pindexFork != nullptr);
    }

    // Rollback along the old branch.
    while (pindexOld != pindexFork) {
        if (pindexOld->nHeight > 0) { // Never disconnect the genesis block.
            CBlock block;
            if (!ReadBlockFromDisk(block, pindexOld, params.GetConsensus())) {
                return error("RollbackBlock(): ReadBlockFromDisk() failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            LogPrintf("Rolling back %s (%i)\n", pindexOld->GetBlockHash().ToString(), pindexOld->nHeight);
            bool fClean=true;
            DisconnectResult res = DisconnectBlock(block, pindexOld, cache, &fClean);
            if (res == DISCONNECT_FAILED) {
                return error("RollbackBlock(): DisconnectBlock failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            // If DISCONNECT_UNCLEAN is returned, it means a non-existing UTXO was deleted, or an existing UTXO was
            // overwritten. It corresponds to cases where the block-to-be-disconnect never had all its operations
            // applied to the UTXO set. However, as both writing a UTXO and deleting a UTXO are idempotent operations,
            // the result is still a version of the UTXO set with the effects of that block undone.
        }
        pindexOld = pindexOld->pprev;
    }

    // Roll forward from the forking point to the new tip.
    int nForkHeight = pindexFork ? pindexFork->nHeight : 0;
    for (int nHeight = nForkHeight + 1; nHeight <= pindexNew->nHeight; ++nHeight) {
        const CBlockIndex* pindex = pindexNew->GetAncestor(nHeight);
        LogPrintf("Rolling forward %s (%i)\n", pindex->GetBlockHash().ToString(), nHeight);
        uiInterface.ShowProgress(_("Replaying blocks...").translated, (int) ((nHeight - nForkHeight) * 100.0 / (pindexNew->nHeight - nForkHeight)) , false);
        if (!RollforwardBlock(pindex, cache, params)) return false;
    }

    cache.SetBestBlock(pindexNew->GetBlockHash());
    cache.Flush();
    uiInterface.ShowProgress("", 100, false);
    return true;
}

//! Helper for CChainState::RewindBlockIndex
void CChainState::EraseBlockData(CBlockIndex* index)
{
    AssertLockHeld(cs_main);
    assert(!m_chain.Contains(index)); // Make sure this block isn't active

    // Reduce validity
    index->nStatus = std::min<unsigned int>(index->nStatus & BLOCK_VALID_MASK, BLOCK_VALID_TREE) | (index->nStatus & ~BLOCK_VALID_MASK);
    // Remove have-data flags.
    index->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
    // Remove storage location.
    index->nFile = 0;
    index->nDataPos = 0;
    index->nUndoPos = 0;
    // Remove various other things
    index->nTx = 0;
    index->nChainTx = 0;
    index->nSequenceId = 0;
    // Make sure it gets written.
    setDirtyBlockIndex.insert(index);
    // Update indexes
    setBlockIndexCandidates.erase(index);
    auto ret = m_blockman.m_blocks_unlinked.equal_range(index->pprev);
    while (ret.first != ret.second) {
        if (ret.first->second == index) {
            m_blockman.m_blocks_unlinked.erase(ret.first++);
        } else {
            ++ret.first;
        }
    }
    // Mark parent as eligible for main chain again
    if (index->pprev && index->pprev->IsValid(BLOCK_VALID_TRANSACTIONS) && index->pprev->HaveTxsDownloaded()) {
        setBlockIndexCandidates.insert(index->pprev);
    }
}

bool CChainState::RewindBlockIndex(const CChainParams& params)
{
    // Note that during -reindex-chainstate we are called with an empty m_chain!

    // First erase all post-segwit blocks without witness not in the main chain,
    // as this can we done without costly DisconnectTip calls. Active
    // blocks will be dealt with below (releasing cs_main in between).
    {
        LOCK(cs_main);
        for (const auto& entry : m_blockman.m_block_index) {
            if (IsWitnessEnabled(entry.second->pprev, params.GetConsensus()) && !(entry.second->nStatus & BLOCK_OPT_WITNESS) && !m_chain.Contains(entry.second)) {
                EraseBlockData(entry.second);
            }
        }
    }

    // Find what height we need to reorganize to.
    CBlockIndex *tip;
    int nHeight = 1;
    {
        LOCK(cs_main);
        while (nHeight <= m_chain.Height()) {
            // Although SCRIPT_VERIFY_WITNESS is now generally enforced on all
            // blocks in ConnectBlock, we don't need to go back and
            // re-download/re-verify blocks from before segwit actually activated.
            if (IsWitnessEnabled(m_chain[nHeight - 1], params.GetConsensus()) && !(m_chain[nHeight]->nStatus & BLOCK_OPT_WITNESS)) {
                break;
            }
            nHeight++;
        }

        tip = m_chain.Tip();
    }
    // nHeight is now the height of the first insufficiently-validated block, or tipheight + 1

    BlockValidationState state;
    // Loop until the tip is below nHeight, or we reach a pruned block.
    while (!ShutdownRequested()) {
        {
            LOCK2(cs_main, ::mempool.cs);
            // Make sure nothing changed from under us (this won't happen because RewindBlockIndex runs before importing/network are active)
            assert(tip == m_chain.Tip());
            if (tip == nullptr || tip->nHeight < nHeight) break;
            if (fPruneMode && !(tip->nStatus & BLOCK_HAVE_DATA)) {
                // If pruning, don't try rewinding past the HAVE_DATA point;
                // since older blocks can't be served anyway, there's
                // no need to walk further, and trying to DisconnectTip()
                // will fail (and require a needless reindex/redownload
                // of the blockchain).
                break;
            }

            // Disconnect block
            if (!DisconnectTip(state, params, nullptr)) {
                return error("RewindBlockIndex: unable to disconnect block at height %i (%s)", tip->nHeight, state.ToString());
            }

            // Reduce validity flag and have-data flags.
            // We do this after actual disconnecting, otherwise we'll end up writing the lack of data
            // to disk before writing the chainstate, resulting in a failure to continue if interrupted.
            // Note: If we encounter an insufficiently validated block that
            // is on m_chain, it must be because we are a pruning node, and
            // this block or some successor doesn't HAVE_DATA, so we were unable to
            // rewind all the way.  Blocks remaining on m_chain at this point
            // must not have their validity reduced.
            EraseBlockData(tip);

            tip = tip->pprev;
        }
        // Make sure the queue of validation callbacks doesn't grow unboundedly.
        LimitValidationInterfaceQueue();

        // Occasionally flush state to disk.
        if (!FlushStateToDisk(params, state, FlushStateMode::PERIODIC)) {
            LogPrintf("RewindBlockIndex: unable to flush state to disk (%s)\n", state.ToString());
            return false;
        }
    }

    {
        LOCK(cs_main);
        if (m_chain.Tip() != nullptr) {
            // We can't prune block index candidates based on our tip if we have
            // no tip due to m_chain being empty!
            PruneBlockIndexCandidates();

            CheckBlockIndex(params.GetConsensus());
        }
    }

    return true;
}

bool RewindBlockIndex(const CChainParams& params) {
    if (!::ChainstateActive().RewindBlockIndex(params)) {
        return false;
    }

    LOCK(cs_main);
    if (::ChainActive().Tip() != nullptr) {
        // FlushStateToDisk can possibly read ::ChainActive(). Be conservative
        // and skip it here, we're about to -reindex-chainstate anyway, so
        // it'll get called a bunch real soon.
        BlockValidationState state;
        if (!::ChainstateActive().FlushStateToDisk(params, state, FlushStateMode::ALWAYS)) {
            LogPrintf("RewindBlockIndex: unable to flush state to disk (%s)\n", state.ToString());
            return false;
        }
    }

    return true;
}

void CChainState::UnloadBlockIndex() {
    nBlockSequenceId = 1;
    setBlockIndexCandidates.clear();
}

// May NOT be used after any connections are up as much
// of the peer-processing logic assumes a consistent
// block index state
void UnloadBlockIndex()
{
    LOCK(cs_main);
    ::ChainActive().SetTip(nullptr);
    g_blockman.Unload();
    pindexBestInvalid = nullptr;
    pindexBestHeader = nullptr;
    mempool.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();
    versionbitscache.Clear();
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].clear();
    }
    fHavePruned = false;

    ::ChainstateActive().UnloadBlockIndex();
}

bool LoadBlockIndex(const CChainParams& chainparams)
{
    // Load block index from databases
    bool needs_init = fReindex;
    if (!fReindex) {
        bool ret = LoadBlockIndexDB(chainparams);
        if (!ret) return false;
        needs_init = g_blockman.m_block_index.empty();
    }

    if (needs_init) {
        // Everything here is for *new* reindex/DBs. Thus, though
        // LoadBlockIndexDB may have set fReindex if we shut down
        // mid-reindex previously, we don't check fReindex and
        // instead only check it prior to LoadBlockIndexDB to set
        // needs_init.

        LogPrintf("Initializing databases...\n");
        // Use the provided setting for -logevents in the new database
        fLogEvents = gArgs.GetBoolArg("-logevents", DEFAULT_LOGEVENTS);
        pblocktree->WriteFlag("logevents", fLogEvents);
        /////////////////////////////////////////////////////////////// // qtum
        fAddressIndex = gArgs.GetBoolArg("-addrindex", DEFAULT_ADDRINDEX);
        pblocktree->WriteFlag("addrindex", fAddressIndex);
        ///////////////////////////////////////////////////////////////
    }
    return true;
}

bool CChainState::LoadGenesisBlock(const CChainParams& chainparams)
{
    LOCK(cs_main);

    // Check whether we're already initialized by checking for genesis in
    // m_blockman.m_block_index. Note that we can't use m_chain here, since it is
    // set based on the coins db, not the block index db, which is the only
    // thing loaded at this point.
    if (m_blockman.m_block_index.count(chainparams.GenesisBlock().GetHash()))
        return true;

    try {
        const CBlock& block = chainparams.GenesisBlock();
        FlatFilePos blockPos = SaveBlockToDisk(block, 0, chainparams, nullptr);
        if (blockPos.IsNull())
            return error("%s: writing genesis block to disk failed", __func__);
        CBlockIndex *pindex = m_blockman.AddToBlockIndex(block);
        pindex->hashProof = chainparams.GetConsensus().hashGenesisBlock;
        ReceivedBlockTransactions(block, pindex, blockPos, chainparams.GetConsensus());
    } catch (const std::runtime_error& e) {
        return error("%s: failed to write genesis block: %s", __func__, e.what());
    }

    return true;
}

bool LoadGenesisBlock(const CChainParams& chainparams)
{
    return ::ChainstateActive().LoadGenesisBlock(chainparams);
}

bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, FlatFilePos *dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, FlatFilePos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*dgpMaxBlockSerSize, dgpMaxBlockSerSize+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> buf;
                if (memcmp(buf, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > dgpMaxBlockSerSize)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
                CBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                uint256 hash = block.GetHash();
                {
                    LOCK(cs_main);
                    // detect out of order blocks, and store them for later
                    if (hash != chainparams.GetConsensus().hashGenesisBlock && !LookupBlockIndex(block.hashPrevBlock)) {
                        LogPrint(BCLog::REINDEX, "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                                block.hashPrevBlock.ToString());
                        if (dbp)
                            mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                        continue;
                    }

                    // process in case the block isn't known yet
                    CBlockIndex* pindex = LookupBlockIndex(hash);
                    if (!pindex || (pindex->nStatus & BLOCK_HAVE_DATA) == 0) {
                      BlockValidationState state;
                      if (::ChainstateActive().AcceptBlock(pblock, state, chainparams, nullptr, true, dbp, nullptr)) {
                          nLoaded++;
                      }
                      if (state.IsError()) {
                          break;
                      }
                    } else if (hash != chainparams.GetConsensus().hashGenesisBlock && pindex->nHeight % 1000 == 0) {
                      LogPrint(BCLog::REINDEX, "Block Import: already had block %s at height %d\n", hash.ToString(), pindex->nHeight);
                    }
                }

                // In Bitcoin this only needed to be done for genesis and at the end of block indexing
                // But for Qtum PoS we need to sync this after every block to ensure txdb is populated for
                // validating PoS proofs
                {
                    BlockValidationState state;
                    if (!ActivateBestChain(state, chainparams)) {
                        break;
                    }
                }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, FlatFilePos>::iterator, std::multimap<uint256, FlatFilePos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, FlatFilePos>::iterator it = range.first;
                        std::shared_ptr<CBlock> pblockrecursive = std::make_shared<CBlock>();
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, chainparams.GetConsensus()))
                        {
                            LogPrint(BCLog::REINDEX, "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->GetHash().ToString(),
                                    head.ToString());
                            LOCK(cs_main);
                            BlockValidationState dummy;
                            if (::ChainstateActive().AcceptBlock(pblockrecursive, dummy, chainparams, nullptr, true, &it->second, nullptr))
                            {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

void CChainState::CheckBlockIndex(const Consensus::Params& consensusParams)
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in m_blockman.m_block_index but no active chain. (A few of the
    // tests when iterating the block tree require that m_chain has been initialized.)
    if (m_chain.Height() < 0) {
        assert(m_blockman.m_block_index.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*,CBlockIndex*> forward;
    for (const std::pair<const uint256, CBlockIndex*>& entry : m_blockman.m_block_index) {
        forward.insert(std::make_pair(entry.second->pprev, entry.second));
    }

    assert(forward.size() == m_blockman.m_block_index.size());

    std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(nullptr);
    CBlockIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent nullptr.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = nullptr; // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = nullptr; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = nullptr; // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != nullptr) {
        nNodes++;
        if (pindexFirstInvalid == nullptr && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == nullptr && !(pindex->nStatus & BLOCK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == nullptr && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTreeValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTransactionsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotChainValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pindexFirstNotChainValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotScriptsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == nullptr) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == m_chain.Genesis()); // The current active chain's genesis block must be this block.
        }
        if (!pindex->HaveTxsDownloaded()) assert(pindex->nSequenceId <= 0); // nSequenceId can't be set positive for blocks that aren't linked (negative is used for preciousblock)
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!fHavePruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BLOCK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to HaveTxsDownloaded().
        assert((pindexFirstNeverProcessed == nullptr) == pindex->HaveTxsDownloaded());
        assert((pindexFirstNotTransactionsValid == nullptr) == pindex->HaveTxsDownloaded());
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(pindex->pprev == nullptr || pindex->nChainWork >= pindex->pprev->nChainWork); // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == nullptr); // All m_blockman.m_block_index entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == nullptr); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == nullptr); // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == nullptr); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, m_chain.Tip()) && pindexFirstNeverProcessed == nullptr) {
            if (pindexFirstInvalid == nullptr) {
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  m_chain.Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == nullptr || pindex == m_chain.Tip()) {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in m_blocks_unlinked -- see test below.
            }
        } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in m_blocks_unlinked.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeUnlinked = m_blockman.m_blocks_unlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != nullptr && pindexFirstInvalid == nullptr) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in m_blocks_unlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in m_blocks_unlinked if we don't HAVE_DATA
        if (pindexFirstMissing == nullptr) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in m_blocks_unlinked.
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == nullptr && pindexFirstMissing != nullptr) {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(fHavePruned); // We must have pruned.
            // This block may have entered m_blocks_unlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between m_chain and the
            //    tip.
            // So if this block is itself better than m_chain.Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in m_blocks_unlinked.
            if (!CBlockIndexWorkComparator()(pindex, m_chain.Tip()) && setBlockIndexCandidates.count(pindex) == 0) {
                if (pindexFirstInvalid == nullptr) {
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = nullptr;
            if (pindex == pindexFirstMissing) pindexFirstMissing = nullptr;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = nullptr;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = nullptr;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = nullptr;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = nullptr;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = nullptr;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

bool CChainState::RemoveBlockIndex(CBlockIndex *pindex)
{
    // Check if the block index is present in any variable and remove it
    if(pindexBestInvalid == pindex)
        pindexBestInvalid = nullptr;

    if(pindexBestHeader == pindex)
        pindexBestHeader = nullptr;

    if(pindexBestForkTip == pindex)
        pindexBestForkTip = nullptr;

    if(pindexBestForkBase == pindex)
        pindexBestForkBase = nullptr;


    // Check if the block index is present in any list and remove it
    for (auto it=m_blockman.m_blocks_unlinked.begin(); it!=m_blockman.m_blocks_unlinked.end();){
        if(it->first == pindex || it->second == pindex)
        {
            it = m_blockman.m_blocks_unlinked.erase(it);
        }
        else{
            it++;
        }
    }

    setBlockIndexCandidates.erase(pindex);

    m_blockman.m_failed_blocks.erase(pindex);

    setDirtyBlockIndex.erase(pindex);

    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].erase(pindex);
    }

    for (int b = 0; b < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; b++) {
        versionbitscache.caches[b].erase(pindex);
    }

    return true;
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, FormatISO8601Date(nTimeFirst), FormatISO8601Date(nTimeLast));
}

CBlockFileInfo* GetBlockFileInfo(size_t n)
{
    LOCK(cs_LastBlockFile);

    return &vinfoBlockFile.at(n);
}

ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsState(::ChainActive().Tip(), params, pos, versionbitscache);
}

BIP9Stats VersionBitsTipStatistics(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStatistics(::ChainActive().Tip(), params, pos);
}

int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStateSinceHeight(::ChainActive().Tip(), params, pos, versionbitscache);
}

static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool(CTxMemPool& pool)
{
    const CChainParams& chainparams = Params();
    int64_t nExpiryTimeout = gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat", "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t expired = 0;
    int64_t failed = 0;
    int64_t already_there = 0;
    int64_t nNow = GetTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        }
        uint64_t num;
        file >> num;
        while (num--) {
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                pool.PrioritiseTransaction(tx->GetHash(), amountdelta);
            }
            TxValidationState state;
            if (nTime + nExpiryTimeout > nNow) {
                LOCK(cs_main);
                AcceptToMemoryPoolWithTime(chainparams, pool, state, tx, nTime,
                                           nullptr /* plTxnReplaced */, false /* bypass_limits */, 0 /* nAbsurdFee */,
                                           false /* test_accept */);
                if (state.IsValid()) {
                    ++count;
                } else {
                    // mempool may contain the transaction already, e.g. from
                    // wallet(s) having loaded it while we were processing
                    // mempool transactions; consider these as valid, instead of
                    // failed, but mark them as 'already there'
                    if (pool.exists(tx->GetHash())) {
                        ++already_there;
                    } else {
                        ++failed;
                    }
                }
            } else {
                ++expired;
            }
            if (ShutdownRequested())
                return false;
        }
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            pool.PrioritiseTransaction(i.first, i.second);
        }
    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i succeeded, %i failed, %i expired, %i already there\n", count, failed, expired, already_there);
    return true;
}

bool DumpMempool(const CTxMemPool& pool)
{
    int64_t start = GetTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;

    static Mutex dump_mutex;
    LOCK(dump_mutex);

    {
        LOCK(pool.cs);
        for (const auto &i : pool.mapDeltas) {
            mapDeltas[i.first] = i.second;
        }
        vinfo = pool.infoAll();
    }

    int64_t mid = GetTimeMicros();

    try {
        FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat.new", "wb");
        if (!filestr) {
            return false;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << *(i.tx);
            file << int64_t{count_seconds(i.m_time)};
            file << int64_t{i.nFeeDelta};
            mapDeltas.erase(i.tx->GetHash());
        }

        file << mapDeltas;
        if (!FileCommit(file.Get()))
            throw std::runtime_error("FileCommit failed");
        file.fclose();
        RenameOver(GetDataDir() / "mempool.dat.new", GetDataDir() / "mempool.dat");
        int64_t last = GetTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid-start)*MICRO, (last-mid)*MICRO);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
        return false;
    }
    return true;
}

//! Guess how far we are in the verification process at the given block index
//! require cs_main if pindex has not been validated yet (because nChainTx might be unset)
double GuessVerificationProgress(const ChainTxData& data, const CBlockIndex *pindex) {
    if (pindex == nullptr)
        return 0.0;

    int64_t nNow = time(nullptr);

    double fTxTotal;

    if (pindex->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->nChainTx + (nNow - pindex->GetBlockTime()) * data.dTxRate;
    }

    return std::min<double>(pindex->nChainTx / fTxTotal, 1.0);
}

std::string exceptedMessage(const dev::eth::TransactionException& excepted, const dev::bytes& output)
{
    std::string message;
    try
    {
        // Process the revert message from the output
        if(excepted == dev::eth::TransactionException::RevertInstruction)
        {
            // Get function: Error(string)
            dev::bytesConstRef oRawData(&output);
            dev::bytes errorFunc = oRawData.cropped(0, 4).toBytes();
            if(dev::toHex(errorFunc) == "08c379a0")
            {
                dev::bytesConstRef oData = oRawData.cropped(4);
                message = dev::eth::ABIDeserialiser<std::string>::deserialise(oData);
            }
        }
    }
    catch(...)
    {}

    return message;
}

bool RemoveStateBlockIndex(CBlockIndex *pindex)
{
    return ::ChainstateActive().RemoveBlockIndex(pindex);
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        BlockMap::iterator it1 = g_blockman.m_block_index.begin();
        for (; it1 != g_blockman.m_block_index.end(); it1++)
            delete (*it1).second;
        g_blockman.m_block_index.clear();
    }
};
static CMainCleanup instance_of_cmaincleanup;

////////////////////////////////////////////////////////////////////////////////// // qtum
bool GetAddressIndex(uint256 addressHash, int type, std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex, int start, int end)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    if (!pblocktree->ReadAddressIndex(addressHash, type, addressIndex, start, end))
        return error("unable to get txids for address");

    return true;
}

bool GetSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value)
{
    if (!fAddressIndex)
        return false;

    if (mempool.getSpentIndex(key, value))
        return true;

    if (!pblocktree->ReadSpentIndex(key, value))
        return false;

    return true;
}

bool GetAddressUnspent(uint256 addressHash, int type, std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    if (!pblocktree->ReadAddressUnspentIndex(addressHash, type, unspentOutputs))
        return error("unable to get txids for address");

    return true;
}

bool GetTimestampIndex(const unsigned int &high, const unsigned int &low, const bool fActiveOnly, std::vector<std::pair<uint256, unsigned int> > &hashes)
{
    if (!fAddressIndex)
        return error("Timestamp index not enabled");

    if (!pblocktree->ReadTimestampIndex(high, low, fActiveOnly, hashes))
        return error("Unable to get hashes for timestamps");

    return true;
}

CAmount GetTxGasFee(const CMutableTransaction& _tx)
{
    CTransaction tx(_tx);
    CAmount nGasFee = 0;
    if(tx.HasCreateOrCall())
    {
        CCoinsViewCache& view = ::ChainstateActive().CoinsTip();
        const CChainParams& chainparams = Params();
        unsigned int contractflags = GetContractScriptFlags(GetSpendHeight(view), chainparams.GetConsensus());
        QtumTxConverter convert(tx, NULL, NULL, contractflags);

        ExtractQtumTX resultConvertQtumTX;
        if(!convert.extractionQtumTransactions(resultConvertQtumTX)){
            return nGasFee;
        }

        dev::u256 sumGas = dev::u256(0);
        for(QtumTransaction& qtx : resultConvertQtumTX.first){
            sumGas += qtx.gas() * qtx.gasPrice();
        }

        nGasFee = (CAmount) sumGas;
    }
    return nGasFee;
}

bool GetAddressWeight(uint256 addressHash, int type, const std::map<COutPoint, uint32_t>& immatureStakes, int32_t nHeight, uint64_t& nWeight)
{
    nWeight = 0;

    if (!fAddressIndex)
        return error("address index not enabled");

    // Get address utxos
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;
    if (!GetAddressUnspent(addressHash, type, unspentOutputs)) {
        throw error("No information available for address");
    }

    // Add the utxos to the list if they are mature
    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator i=unspentOutputs.begin(); i!=unspentOutputs.end(); i++) {

        int nDepth = nHeight - i->second.blockHeight + 1;
        if (nDepth < COINBASE_MATURITY)
            continue;

        if(i->second.satoshis < 0)
            continue;

        COutPoint prevout = COutPoint(i->first.txhash, i->first.index);
        if(immatureStakes.find(prevout) == immatureStakes.end())
        {
            nWeight+= i->second.satoshis;
        }
    }

    return true;
}

std::map<COutPoint, uint32_t> GetImmatureStakes()
{
    std::map<COutPoint, uint32_t> immatureStakes;
    int height = ::ChainActive().Height();
    for(int i = 0; i < COINBASE_MATURITY -1; i++) {
        CBlockIndex* block = ::ChainActive()[height - i];
        if(block)
        {
            immatureStakes[block->prevoutStake] = block->nTime;
        }
        else
        {
            break;
        }
    }
    return immatureStakes;
}
//////////////////////////////////////////////////////////////////////////////////
