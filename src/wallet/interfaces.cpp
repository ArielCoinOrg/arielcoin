// Copyright (c) 2018-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/wallet.h>

#include <amount.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <policy/fees.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <script/standard.h>
#include <support/allocators/secure.h>
#include <sync.h>
#include <uint256.h>
#include <util/check.h>
#include <util/system.h>
#include <util/ui_change_type.h>
#include <wallet/context.h>
#include <wallet/feebumper.h>
#include <wallet/fees.h>
#include <wallet/ismine.h>
#include <wallet/load.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <key_io.h>
#include <qtum/qtumdelegation.h>
#include <miner.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <algorithm>

using interfaces::Chain;
using interfaces::FoundBlock;
using interfaces::Handler;
using interfaces::MakeHandler;
using interfaces::Wallet;
using interfaces::WalletAddress;
using interfaces::WalletBalances;
using interfaces::WalletClient;
using interfaces::WalletOrderForm;
using interfaces::WalletTx;
using interfaces::WalletTxOut;
using interfaces::WalletTxStatus;
using interfaces::WalletValueMap;
using interfaces::TokenInfo;
using interfaces::TokenTx;
using interfaces::ContractBookData;
using interfaces::DelegationInfo;
using interfaces::DelegationDetails;
using interfaces::SuperStakerInfo;
using interfaces::DelegationStakerInfo;
using interfaces::SuperStakerAddressList;
using interfaces::SignDelegation;

namespace wallet {
namespace {
//! Construct wallet tx struct.
WalletTx MakeWalletTx(CWallet& wallet, const CWalletTx& wtx)
{
    LOCK(wallet.cs_wallet);
    WalletTx result;
    result.tx = wtx.tx;
    result.txin_is_mine.reserve(wtx.tx->vin.size());
    for (const auto& txin : wtx.tx->vin) {
        result.txin_is_mine.emplace_back(wallet.IsMine(txin));
    }
    result.txout_is_mine.reserve(wtx.tx->vout.size());
    result.txout_address.reserve(wtx.tx->vout.size());
    result.txout_address_is_mine.reserve(wtx.tx->vout.size());
    for (const auto& txout : wtx.tx->vout) {
        result.txout_is_mine.emplace_back(wallet.IsMine(txout));
        result.txout_address.emplace_back();
        result.txout_address_is_mine.emplace_back(ExtractDestination(txout.scriptPubKey, result.txout_address.back()) ?
                                                      wallet.IsMine(result.txout_address.back()) :
                                                      ISMINE_NO);
    }
    result.credit = wtx.GetCredit(ISMINE_ALL);
    result.debit = wtx.GetDebit(ISMINE_ALL);
    result.change = wtx.GetChange();
    result.time = wtx.GetTxTime();
    result.value_map = wtx.mapValue;
    result.is_coinbase = wtx.IsCoinBase();
    result.is_coinstake = wtx.IsCoinStake();
    result.is_in_main_chain = wtx.IsInMainChain();
    result.has_create_or_call = wtx.tx->HasCreateOrCall();
    if(result.has_create_or_call)
    {
        CTxDestination tx_sender_address;
        if(wtx.tx && wtx.tx->vin.size() > 0 && wallet.mapWallet.find(wtx.tx->vin[0].prevout.hash) != wallet.mapWallet.end() &&
                ExtractDestination(wallet.mapWallet.at(wtx.tx->vin[0].prevout.hash).tx->vout[wtx.tx->vin[0].prevout.n].scriptPubKey, tx_sender_address)) {
            result.tx_sender_key = wallet.GetKeyForDestination(tx_sender_address);
        }

        for(CTxDestination address : result.txout_address) {
            result.txout_keys.emplace_back(wallet.GetKeyForDestination(address));
        }
    }
    return result;
}

//! Construct wallet tx status struct.
WalletTxStatus MakeWalletTxStatus(const CWallet& wallet, const CWalletTx& wtx)
{
    WalletTxStatus result;
    result.block_height = wtx.m_confirm.block_height > 0 ? wtx.m_confirm.block_height : std::numeric_limits<int>::max();
    result.blocks_to_maturity = wtx.GetBlocksToMaturity();
    result.depth_in_main_chain = wtx.GetDepthInMainChain();
    result.time_received = wtx.nTimeReceived;
    result.lock_time = wtx.tx->nLockTime;
    result.is_final = wallet.chain().checkFinalTx(*wtx.tx);
    result.is_trusted = wtx.IsTrusted();
    result.is_abandoned = wtx.isAbandoned();
    result.is_coinbase = wtx.IsCoinBase();
    result.is_in_main_chain = wtx.IsInMainChain();
    result.is_coinstake = wtx.IsCoinStake();
    return result;
}

//! Construct wallet TxOut struct.
WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const CWalletTx& wtx,
    int n,
    int depth) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = wtx.tx->vout[n];
    result.time = wtx.GetTxTime();
    result.depth_in_main_chain = depth;
    result.is_spent = wallet.IsSpent(wtx.GetHash(), n);
    return result;
}

//! Construct token info.
CTokenInfo MakeTokenInfo(const TokenInfo& token)
{
    CTokenInfo result;
    result.strContractAddress = token.contract_address;
    result.strTokenName = token.token_name;
    result.strTokenSymbol = token.token_symbol;
    result.nDecimals = token.decimals;
    result.strSenderAddress = token.sender_address;
    result.nCreateTime = token.time;
    result.blockHash = token.block_hash;
    result.blockNumber = token.block_number;
    return result;
}

//! Construct wallet token info.
TokenInfo MakeWalletTokenInfo(const CTokenInfo& token)
{
    TokenInfo result;
    result.contract_address = token.strContractAddress;
    result.token_name = token.strTokenName;
    result.token_symbol = token.strTokenSymbol;
    result.decimals = token.nDecimals;
    result.sender_address = token.strSenderAddress;
    result.time = token.nCreateTime;
    result.block_hash = token.blockHash;
    result.block_number = token.blockNumber;
    result.hash = token.GetHash();
    return result;
}

//! Construct token transaction.
CTokenTx MakeTokenTx(const TokenTx& tokenTx)
{
    CTokenTx result;
    result.strContractAddress = tokenTx.contract_address;
    result.strSenderAddress = tokenTx.sender_address;
    result.strReceiverAddress = tokenTx.receiver_address;
    result.nValue = tokenTx.value;
    result.transactionHash = tokenTx.tx_hash;
    result.nCreateTime = tokenTx.time;
    result.blockHash = tokenTx.block_hash;
    result.blockNumber = tokenTx.block_number;
    result.strLabel = tokenTx.label;
    return result;
}

//! Construct wallet token transaction.
TokenTx MakeWalletTokenTx(const CTokenTx& tokenTx)
{
    TokenTx result;
    result.contract_address = tokenTx.strContractAddress;
    result.sender_address = tokenTx.strSenderAddress;
    result.receiver_address = tokenTx.strReceiverAddress;
    result.value = tokenTx.nValue;
    result.tx_hash = tokenTx.transactionHash;
    result.time = tokenTx.nCreateTime;
    result.block_hash = tokenTx.blockHash;
    result.block_number = tokenTx.blockNumber;
    result.label = tokenTx.strLabel;
    result.hash = tokenTx.GetHash();
    return result;
}

ContractBookData MakeContractBook(const std::string& id, const CContractBookData& data)
{
    ContractBookData result;
    result.address = id;
    result.name = data.name;
    result.abi = data.abi;
    return result;
}

uint160 StringToKeyId(const std::string& strAddress)
{
    CTxDestination dest = DecodeDestination(strAddress);
    if(std::holds_alternative<PKHash>(dest))
    {
        PKHash keyID = std::get<PKHash>(dest);
        return uint160(keyID);
    }
    return uint160();
}

std::string KeyIdToString(const uint160& keyID)
{
    return EncodeDestination(PKHash(keyID));
}

std::vector<uint160> StringToKeyIdList(const std::vector<std::string>& listAddress)
{
    std::vector<uint160> ret;
    for(auto address : listAddress)
    {
        ret.push_back(StringToKeyId(address));
    }
    return ret;
}

std::vector<std::string> KeyIdToStringList(const std::vector<uint160>& listKeyID)
{
    std::vector<std::string> ret;
    for(auto keyId : listKeyID)
    {
        ret.push_back(KeyIdToString(keyId));
    }
    return ret;
}

//! Construct delegation info.
CDelegationInfo MakeDelegationInfo(const DelegationInfo& delegation)
{
    CDelegationInfo result;
    result.delegateAddress = StringToKeyId(delegation.delegate_address);
    result.stakerAddress = StringToKeyId(delegation.staker_address);
    result.strStakerName = delegation.staker_name;
    result.nFee = delegation.fee;
    result.nCreateTime = delegation.time;
    result.blockNumber = delegation.block_number;
    result.createTxHash = delegation.create_tx_hash;
    result.removeTxHash = delegation.remove_tx_hash;
    return result;
}

//! Construct wallet delegation info.
DelegationInfo MakeWalletDelegationInfo(const CDelegationInfo& delegation)
{
    DelegationInfo result;
    result.delegate_address = KeyIdToString(delegation.delegateAddress);
    result.staker_address = KeyIdToString(delegation.stakerAddress);
    result.staker_name = delegation.strStakerName;
    result.fee = delegation.nFee;
    result.time = delegation.nCreateTime;
    result.block_number = delegation.blockNumber;
    result.time = delegation.nCreateTime;
    result.create_tx_hash = delegation.createTxHash;
    result.remove_tx_hash = delegation.removeTxHash;
    result.hash = delegation.GetHash();
    return result;
}

//! Construct super staker info.
CSuperStakerInfo MakeSuperStakerInfo(const SuperStakerInfo& superStaker)
{
    CSuperStakerInfo result;
    result.stakerAddress = StringToKeyId(superStaker.staker_address);
    result.strStakerName = superStaker.staker_name;
    result.nMinFee = superStaker.min_fee;
    result.nCreateTime = superStaker.time;
    result.fCustomConfig = superStaker.custom_config;
    result.nMinDelegateUtxo = superStaker.min_delegate_utxo;
    result.delegateAddressList = StringToKeyIdList(superStaker.delegate_address_list);
    result.nDelegateAddressType = superStaker.delegate_address_type;
    return result;
}

//! Construct wallet super staker info.
SuperStakerInfo MakeWalletSuperStakerInfo(const CSuperStakerInfo& superStaker)
{
    SuperStakerInfo result;
    result.staker_address = KeyIdToString(superStaker.stakerAddress);
    result.staker_name = superStaker.strStakerName;
    result.min_fee = superStaker.nMinFee;
    result.time = superStaker.nCreateTime;
    result.custom_config = superStaker.fCustomConfig;
    result.min_delegate_utxo = superStaker.nMinDelegateUtxo;
    result.delegate_address_list = KeyIdToStringList(superStaker.delegateAddressList);
    result.delegate_address_type = superStaker.nDelegateAddressType;
    result.hash = superStaker.GetHash();
    return result;
}

//! Construct wallet delegation staker info.
DelegationStakerInfo MakeWalletDelegationStakerInfo(CWallet& wallet, const uint160& id, const Delegation& delegation)
{
    DelegationStakerInfo result;
    result.delegate_address = EncodeDestination(PKHash(id));
    result.staker_address = EncodeDestination(PKHash(delegation.staker));
    result.PoD = HexStr(delegation.PoD);
    result.fee = delegation.fee;
    result.time = -1;
    wallet.chain().findBlock(wallet.chain().getBlockHash(delegation.blockHeight), FoundBlock().time(result.time));
    result.block_number = delegation.blockHeight;
    std::map<uint160, CAmount>::iterator it = wallet.m_delegations_weight.find(id);
    if(it != wallet.m_delegations_weight.end())
    {
        result.weight = it->second;
    }
    result.hash = id;
    return result;
}

bool TokenTxStatus(CWallet& wallet, const uint256& txid, int& block_number, bool& in_mempool, int& num_blocks) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    auto mi = wallet.mapTokenTx.find(txid);
    if (mi == wallet.mapTokenTx.end()) {
        return false;
    }
    block_number = mi->second.blockNumber;
    auto it = wallet.mapWallet.find(mi->second.transactionHash); 
    if(it != wallet.mapWallet.end())
    {
        in_mempool = it->second.InMempool();
    }
    num_blocks = wallet.GetLastBlockHeight();
    return true;
}

class WalletImpl : public Wallet
{
public:
    explicit WalletImpl(const std::shared_ptr<CWallet>& wallet) : m_wallet(wallet) {}

    bool encryptWallet(const SecureString& wallet_passphrase) override
    {
        return m_wallet->EncryptWallet(wallet_passphrase);
    }
    bool isCrypted() override { return m_wallet->IsCrypted(); }
    bool lock() override { return m_wallet->Lock(); }
    bool unlock(const SecureString& wallet_passphrase) override { return m_wallet->Unlock(wallet_passphrase); }
    bool isLocked() override { return m_wallet->IsLocked(); }
    bool changeWalletPassphrase(const SecureString& old_wallet_passphrase,
        const SecureString& new_wallet_passphrase) override
    {
        return m_wallet->ChangeWalletPassphrase(old_wallet_passphrase, new_wallet_passphrase);
    }
    void abortRescan() override { m_wallet->AbortRescan(); }
    bool backupWallet(const std::string& filename) override { return m_wallet->BackupWallet(filename); }
    std::string getWalletName() override { return m_wallet->GetName(); }
    bool getNewDestination(const OutputType type, const std::string label, CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        std::string error;
        return m_wallet->GetNewDestination(type, label, dest, error);
    }
    bool getPubKey(const CScript& script, const CKeyID& address, CPubKey& pub_key) override
    {
        std::unique_ptr<SigningProvider> provider = m_wallet->GetSolvingProvider(script);
        if (provider) {
            return provider->GetPubKey(address, pub_key);
        }
        return false;
    }
    SigningResult signMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) override
    {
        return m_wallet->SignMessage(message, pkhash, str_sig);
    }
    bool isSpendable(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(dest) & ISMINE_SPENDABLE;
    }
    bool haveWatchOnly() override
    {
        auto spk_man = m_wallet->GetLegacyScriptPubKeyMan();
        if (spk_man) {
            return spk_man->HaveWatchOnly();
        }
        return false;
    };
    bool setAddressBook(const CTxDestination& dest, const std::string& name, const std::string& purpose) override
    {
        return m_wallet->SetAddressBook(dest, name, purpose);
    }
    bool delAddressBook(const CTxDestination& dest) override
    {
        return m_wallet->DelAddressBook(dest);
    }
    bool getAddress(const CTxDestination& dest,
        std::string* name,
        isminetype* is_mine,
        std::string* purpose) override
    {
        LOCK(m_wallet->cs_wallet);
        auto it = m_wallet->m_address_book.find(dest);
        if (it == m_wallet->m_address_book.end() || it->second.IsChange()) {
            return false;
        }
        if (name) {
            *name = it->second.GetLabel();
        }
        if (is_mine) {
            *is_mine = m_wallet->IsMine(dest);
        }
        if (purpose) {
            *purpose = it->second.purpose;
        }
        return true;
    }
    std::vector<WalletAddress> getAddresses() override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletAddress> result;
        for (const auto& item : m_wallet->m_address_book) {
            if (item.second.IsChange()) continue;
            result.emplace_back(item.first, m_wallet->IsMine(item.first), item.second.GetLabel(), item.second.purpose);
        }
        return result;
    }
    std::vector<std::string> getAddressReceiveRequests() override {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetAddressReceiveRequests();
    }
    bool setAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& value) override {
        LOCK(m_wallet->cs_wallet);
        WalletBatch batch{m_wallet->GetDatabase()};
        return m_wallet->SetAddressReceiveRequest(batch, dest, id, value);
    }
    bool displayAddress(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->DisplayAddress(dest);
    }
    void lockCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->LockCoin(output);
    }
    void unlockCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->UnlockCoin(output);
    }
    bool isLockedCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsLockedCoin(output.hash, output.n);
    }
    void listLockedCoins(std::vector<COutPoint>& outputs) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->ListLockedCoins(outputs);
    }
    CTransactionRef createTransaction(const std::vector<CRecipient>& recipients,
        const CCoinControl& coin_control,
        bool sign,
        int& change_pos,
        CAmount& fee,
        bilingual_str& fail_reason) override
    {
        LOCK(m_wallet->cs_wallet);
        CTransactionRef tx;
        FeeCalculation fee_calc_out;
        if (!m_wallet->CreateTransaction(recipients, tx, fee, change_pos,
                fail_reason, coin_control, fee_calc_out, sign)) {
            return {};
        }
        return tx;
    }
    void commitTransaction(CTransactionRef tx,
        WalletValueMap value_map,
        WalletOrderForm order_form) override
    {
        LOCK(m_wallet->cs_wallet);
        m_wallet->CommitTransaction(std::move(tx), std::move(value_map), std::move(order_form));
    }
    bool transactionCanBeAbandoned(const uint256& txid) override { return m_wallet->TransactionCanBeAbandoned(txid); }
    bool abandonTransaction(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->AbandonTransaction(txid);
    }
    bool transactionCanBeBumped(const uint256& txid) override
    {
        return feebumper::TransactionCanBeBumped(*m_wallet.get(), txid);
    }
    bool createBumpTransaction(const uint256& txid,
        const CCoinControl& coin_control,
        std::vector<bilingual_str>& errors,
        CAmount& old_fee,
        CAmount& new_fee,
        CMutableTransaction& mtx) override
    {
        return feebumper::CreateRateBumpTransaction(*m_wallet.get(), txid, coin_control, errors, old_fee, new_fee, mtx) == feebumper::Result::OK;
    }
    bool signBumpTransaction(CMutableTransaction& mtx) override { return feebumper::SignTransaction(*m_wallet.get(), mtx); }
    bool commitBumpTransaction(const uint256& txid,
        CMutableTransaction&& mtx,
        std::vector<bilingual_str>& errors,
        uint256& bumped_txid) override
    {
        return feebumper::CommitTransaction(*m_wallet.get(), txid, std::move(mtx), errors, bumped_txid) ==
               feebumper::Result::OK;
    }
    CTransactionRef getTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return mi->second.tx;
        }
        return {};
    }
    WalletTx getWalletTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return MakeWalletTx(*m_wallet, mi->second);
        }
        return {};
    }
    std::vector<WalletTx> getWalletTxs() override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletTx> result;
        result.reserve(m_wallet->mapWallet.size());
        for (const auto& entry : m_wallet->mapWallet) {
            result.emplace_back(MakeWalletTx(*m_wallet, entry.second));
        }
        return result;
    }
    bool tryGetTxStatus(const uint256& txid,
        interfaces::WalletTxStatus& tx_status,
        int& num_blocks,
        int64_t& block_time) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi == m_wallet->mapWallet.end()) {
            return false;
        }
        num_blocks = m_wallet->GetLastBlockHeight();
        block_time = -1;
        CHECK_NONFATAL(m_wallet->chain().findBlock(m_wallet->GetLastBlockHash(), FoundBlock().time(block_time)));
        tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
        return true;
    }
    WalletTx getWalletTxDetails(const uint256& txid,
        WalletTxStatus& tx_status,
        WalletOrderForm& order_form,
        bool& in_mempool,
        int& num_blocks) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            num_blocks = m_wallet->GetLastBlockHeight();
            in_mempool = mi->second.InMempool();
            order_form = mi->second.vOrderForm;
            tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
            return MakeWalletTx(*m_wallet, mi->second);
        }
        return {};
    }
    TransactionError fillPSBT(int sighash_type,
        bool sign,
        bool bip32derivs,
        size_t* n_signed,
        PartiallySignedTransaction& psbtx,
        bool& complete) override
    {
        return m_wallet->FillPSBT(psbtx, complete, sighash_type, sign, bip32derivs, n_signed);
    }
    WalletBalances getBalances() override
    {
        const auto bal = m_wallet->GetBalance();
        WalletBalances result;
        result.balance = bal.m_mine_trusted;
        result.unconfirmed_balance = bal.m_mine_untrusted_pending;
        result.immature_balance = bal.m_mine_immature;
        result.stake = bal.m_mine_stake;
        result.have_watch_only = haveWatchOnly();
        if (result.have_watch_only) {
            result.watch_only_balance = bal.m_watchonly_trusted;
            result.unconfirmed_watch_only_balance = bal.m_watchonly_untrusted_pending;
            result.immature_watch_only_balance = bal.m_watchonly_immature;
            result.watch_only_stake = bal.m_watchonly_stake;
        }
        return result;
    }
    bool tryGetBalances(WalletBalances& balances, uint256& block_hash) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        block_hash = m_wallet->GetLastBlockHash();
        balances = getBalances();
        return true;
    }
    CAmount getBalance() override { return m_wallet->GetBalance().m_mine_trusted; }
    CAmount getAvailableBalance(const CCoinControl& coin_control) override
    {
        return m_wallet->GetAvailableBalance(&coin_control);
    }
    isminetype txinIsMine(const CTxIn& txin) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(txin);
    }
    isminetype txoutIsMine(const CTxOut& txout) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(txout);
    }
    CAmount getDebit(const CTxIn& txin, isminefilter filter) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetDebit(txin, filter);
    }
    CAmount getCredit(const CTxOut& txout, isminefilter filter) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetCredit(txout, filter);
    }
    bool isUnspentAddress(const std::string &qtumAddress) override
    {
        LOCK(m_wallet->cs_wallet);

        std::vector<COutput> vecOutputs;
        m_wallet->AvailableCoins(vecOutputs);
        for (const COutput& out : vecOutputs)
        {
            CTxDestination address;
            const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
            bool fValidAddress = ExtractDestination(scriptPubKey, address);

            if(fValidAddress && EncodeDestination(address) == qtumAddress && out.tx->tx->vout[out.i].nValue)
            {
                return true;
            }
        }
        return false;
    }
    bool isMineAddress(const std::string &strAddress) override
    {
        LOCK(m_wallet->cs_wallet);

        CTxDestination address = DecodeDestination(strAddress);
        if(!IsValidDestination(address) || !m_wallet->IsMine(address))
        {
            return false;
        }
        return true;
    }
    std::vector<std::string> availableAddresses(bool fIncludeZeroValue) EXCLUSIVE_LOCKS_REQUIRED(m_wallet->cs_wallet)
    {
        std::vector<std::string> result;
        std::vector<COutput> vecOutputs;
        std::map<std::string, bool> mapAddress;

        if(fIncludeZeroValue)
        {
            // Get the user created addresses in from the address book and add them if they are mine
            for (const auto& item : m_wallet->m_address_book) {
                if(!m_wallet->IsMine(item.first)) continue;
                if(item.second.purpose != "receive") continue;
                if(item.second.destdata.size() == 0) continue;

                std::string strAddress = EncodeDestination(item.first);
                if (mapAddress.find(strAddress) == mapAddress.end())
                {
                    mapAddress[strAddress] = true;
                    result.push_back(strAddress);
                }
            }

            // Get all coins including the 0 values
            m_wallet->AvailableCoins(vecOutputs, nullptr, 0);
        }
        else
        {
            // Get all spendable coins
            m_wallet->AvailableCoins(vecOutputs);
        }

        // Extract all coins addresses and add them in the list
        for (const COutput& out : vecOutputs)
        {
            CTxDestination address;
            const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
            bool fValidAddress = ExtractDestination(scriptPubKey, address);

            if (!fValidAddress || !m_wallet->IsMine(address)) continue;

            std::string strAddress = EncodeDestination(address);
            if (mapAddress.find(strAddress) == mapAddress.end())
            {
                mapAddress[strAddress] = true;
                result.push_back(strAddress);
            }
        }

        return result;
    }
    bool tryGetAvailableAddresses(std::vector<std::string> &spendableAddresses, std::vector<std::string> &allAddresses, bool &includeZeroValue) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }

        spendableAddresses = availableAddresses(false);
        allAddresses = availableAddresses(true);
        int num_blocks = m_wallet->GetLastBlockHeight();
        includeZeroValue = num_blocks >= Params().GetConsensus().QIP5Height;

        return true;
    }
    CoinsList listCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        CoinsList result;
        for (const auto& entry : m_wallet->ListCoins()) {
            auto& group = result[entry.first];
            for (const auto& coin : entry.second) {
                group.emplace_back(COutPoint(coin.tx->GetHash(), coin.i),
                    MakeWalletTxOut(*m_wallet, *coin.tx, coin.i, coin.nDepth));
            }
        }
        return result;
    }
    std::vector<WalletTxOut> getCoins(const std::vector<COutPoint>& outputs) override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletTxOut> result;
        result.reserve(outputs.size());
        for (const auto& output : outputs) {
            result.emplace_back();
            auto it = m_wallet->mapWallet.find(output.hash);
            if (it != m_wallet->mapWallet.end()) {
                int depth = it->second.GetDepthInMainChain();
                if (depth >= 0) {
                    result.back() = MakeWalletTxOut(*m_wallet, it->second, output.n, depth);
                }
            }
        }
        return result;
    }
    CAmount getRequiredFee(unsigned int tx_bytes) override { return GetRequiredFee(*m_wallet, tx_bytes); }
    CAmount getMinimumFee(unsigned int tx_bytes,
        const CCoinControl& coin_control,
        int* returned_target,
        FeeReason* reason) override
    {
        FeeCalculation fee_calc;
        CAmount result;
        result = GetMinimumFee(*m_wallet, tx_bytes, coin_control, &fee_calc);
        if (returned_target) *returned_target = fee_calc.returnedTarget;
        if (reason) *reason = fee_calc.reason;
        return result;
    }
    unsigned int getConfirmTarget() override { return m_wallet->m_confirm_target; }
    bool hdEnabled() override { return m_wallet->IsHDEnabled(); }
    bool canGetAddresses() override { return m_wallet->CanGetAddresses(); }
    bool hasExternalSigner() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER); }
    bool privateKeysDisabled() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS); }
    OutputType getDefaultAddressType() override { return m_wallet->m_default_address_type; }
    CAmount getDefaultMaxTxFee() override { return m_wallet->m_default_max_tx_fee; }
    void remove() override
    {
        RemoveWallet(m_wallet, false /* load_on_start */);
    }
    bool isLegacy() override { return m_wallet->IsLegacy(); }
    bool addTokenEntry(const TokenInfo &token) override
    {
        return m_wallet->AddTokenEntry(MakeTokenInfo(token), true);
    }
    bool addTokenTxEntry(const TokenTx& tokenTx, bool fFlushOnClose) override
    {
        return m_wallet->AddTokenTxEntry(MakeTokenTx(tokenTx), fFlushOnClose);
    }
    bool existTokenEntry(const TokenInfo &token) override
    {
        LOCK(m_wallet->cs_wallet);

        uint256 hash = MakeTokenInfo(token).GetHash();
        std::map<uint256, CTokenInfo>::iterator it = m_wallet->mapToken.find(hash);

        return it != m_wallet->mapToken.end();
    }
    bool removeTokenEntry(const std::string &sHash) override
    {
        return m_wallet->RemoveTokenEntry(uint256S(sHash), true);
    }
    std::vector<TokenInfo> getInvalidTokens() override
    {
        LOCK(m_wallet->cs_wallet);

        std::vector<TokenInfo> listInvalid;
        for(auto& info : m_wallet->mapToken)
        {
            std::string strAddress = info.second.strSenderAddress;
            CTxDestination address = DecodeDestination(strAddress);
            if(!m_wallet->IsMine(address))
            {
                listInvalid.push_back(MakeWalletTokenInfo(info.second));
            }
        }

        return listInvalid;
    }
    TokenTx getTokenTx(const uint256& txid) override
    {
        LOCK(m_wallet->cs_wallet);

        auto mi = m_wallet->mapTokenTx.find(txid);
        if (mi != m_wallet->mapTokenTx.end()) {
            return MakeWalletTokenTx(mi->second);
        }
        return {};
    }
    std::vector<TokenTx> getTokenTxs() override
    {
        LOCK(m_wallet->cs_wallet);

        std::vector<TokenTx> result;
        result.reserve(m_wallet->mapTokenTx.size());
        for (const auto& entry : m_wallet->mapTokenTx) {
            result.emplace_back(MakeWalletTokenTx(entry.second));
        }
        return result;
    }
    TokenInfo getToken(const uint256& id) override
    {
        LOCK(m_wallet->cs_wallet);

        auto mi = m_wallet->mapToken.find(id);
        if (mi != m_wallet->mapToken.end()) {
            return MakeWalletTokenInfo(mi->second);
        }
        return {};
    }
    std::vector<TokenInfo> getTokens() override
    {
        LOCK(m_wallet->cs_wallet);

        std::vector<TokenInfo> result;
        result.reserve(m_wallet->mapToken.size());
        for (const auto& entry : m_wallet->mapToken) {
            result.emplace_back(MakeWalletTokenInfo(entry.second));
        }
        return result;
    }
    bool tryGetTokenTxStatus(const uint256& txid, int& block_number, bool& in_mempool, int& num_blocks) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        return TokenTxStatus(*m_wallet, txid, block_number, in_mempool, num_blocks);
    }
    bool getTokenTxStatus(const uint256& txid, int& block_number, bool& in_mempool, int& num_blocks) override
    {
        LOCK(m_wallet->cs_wallet);

        return TokenTxStatus(*m_wallet, txid, block_number, in_mempool, num_blocks);
    }
    bool getTokenTxDetails(const TokenTx &wtx, uint256& credit, uint256& debit, std::string& tokenSymbol, uint8_t& decimals) override
    {
        return m_wallet->GetTokenTxDetails(MakeTokenTx(wtx), credit, debit, tokenSymbol, decimals);
    }
    bool isTokenTxMine(const TokenTx &wtx) override
    {
        return m_wallet->IsTokenTxMine(MakeTokenTx(wtx));
    }
    ContractBookData getContractBook(const std::string& id) override
    {
        LOCK(m_wallet->cs_wallet);

        auto mi = m_wallet->mapContractBook.find(id);
        if (mi != m_wallet->mapContractBook.end()) {
            return MakeContractBook(id, mi->second);
        }
        return {};
    }
    std::vector<ContractBookData> getContractBooks() override
    {
        LOCK(m_wallet->cs_wallet);

        std::vector<ContractBookData> result;
        result.reserve(m_wallet->mapContractBook.size());
        for (const auto& entry : m_wallet->mapContractBook) {
            result.emplace_back(MakeContractBook(entry.first, entry.second));
        }
        return result;
    }
    bool existContractBook(const std::string& id) override
    {
        LOCK(m_wallet->cs_wallet);

        auto mi = m_wallet->mapContractBook.find(id);
        return mi != m_wallet->mapContractBook.end();
    }
    bool delContractBook(const std::string& id) override
    {
        return m_wallet->DelContractBook(id);
    }
    bool setContractBook(const std::string& id, const std::string& name, const std::string& abi) override
    {
        return m_wallet->SetContractBook(id, name, abi);
    }
    uint32_t restoreDelegations() override
    {
        RefreshDelegates(m_wallet.get(), true, false);

        LOCK(m_wallet->cs_wallet);

        int ret = 0;
        for (const auto& item : m_wallet->m_my_delegations) {
            DelegationDetails details = getDelegationDetails(KeyIdToString(item.first));
            if(!details.w_entry_exist && details.c_entry_exist)
            {
                DelegationInfo info = details.toInfo(false);
                info.staker_name = info.staker_address;
                if(addDelegationEntry(info))
                    ret++;
            }
        }

        return ret;
    }
    bool addDelegationEntry(const DelegationInfo &delegation) override
    {
        return m_wallet->AddDelegationEntry(MakeDelegationInfo(delegation), true);
    }
    bool existDelegationEntry(const DelegationInfo &delegation) override
    {
        LOCK(m_wallet->cs_wallet);

        uint256 hash = MakeDelegationInfo(delegation).GetHash();
        std::map<uint256, CDelegationInfo>::iterator it = m_wallet->mapDelegation.find(hash);

        return it != m_wallet->mapDelegation.end();
    }
    DelegationInfo getDelegation(const uint256& id) override
    {
        LOCK(m_wallet->cs_wallet);

        auto mi = m_wallet->mapDelegation.find(id);
        if (mi != m_wallet->mapDelegation.end()) {
            return MakeWalletDelegationInfo(mi->second);
        }
        return {};
    }
    DelegationInfo getDelegationContract(const std::string &sHash, bool& validated, bool& contractRet) override
    {
        LOCK(m_wallet->cs_wallet);

        uint256 id;
        id.SetHex(sHash);
        auto mi = m_wallet->mapDelegation.find(id);
        if (mi != m_wallet->mapDelegation.end()) {
            DelegationInfo info = MakeWalletDelegationInfo(mi->second);
            Delegation delegation;
            CTxDestination dest = DecodeDestination(info.delegate_address);
            if(std::holds_alternative<PKHash>(dest))
            {
                PKHash keyID = std::get<PKHash>(dest);
                uint160 address(keyID);
                contractRet = m_qtumDelegation.ExistDelegationContract() ? m_qtumDelegation.GetDelegation(address, delegation, m_wallet->chain().chainman().ActiveChainstate()) : false;
                if(contractRet)
                {
                    validated = m_qtumDelegation.VerifyDelegation(address, delegation);
                    info.staker_address = EncodeDestination(PKHash(delegation.staker));
                    info.fee = delegation.fee;
                    info.block_number = delegation.blockHeight;
                }
                return info;
            }
        }
        return {};
    }
    DelegationDetails getDelegationDetails(const std::string &sAddress) override
    {
        LOCK(m_wallet->cs_wallet);
        DelegationDetails details;

        // Get wallet delegation details
        for(auto mi : m_wallet->mapDelegation)
        {
            if(KeyIdToString(mi.second.delegateAddress) == sAddress)
            {
                details.w_entry_exist = true;
                details.w_delegate_address = KeyIdToString(mi.second.delegateAddress);
                details.w_staker_address = KeyIdToString(mi.second.stakerAddress);
                details.w_staker_name = mi.second.strStakerName;
                details.w_fee = mi.second.nFee;
                details.w_time = mi.second.nCreateTime;
                details.w_block_number = mi.second.blockNumber;
                details.w_hash = mi.first;
                details.w_create_tx_hash = mi.second.createTxHash;
                details.w_remove_tx_hash = mi.second.removeTxHash;
                break;
            }
        }

        // Get wallet create tx details
        const CWalletTx* wtx = m_wallet->GetWalletTx(details.w_create_tx_hash);
        if(wtx)
        {
            details.w_create_exist = true;
            details.w_create_in_main_chain = wtx->IsInMainChain();
            details.w_create_in_mempool = wtx->InMempool();
            details.w_create_abandoned = wtx->isAbandoned();
        }

        // Get wallet remove tx details
        wtx = m_wallet->GetWalletTx(details.w_remove_tx_hash);
        if(wtx)
        {
            details.w_remove_exist = true;
            details.w_remove_in_main_chain = wtx->IsInMainChain();
            details.w_remove_in_mempool = wtx->InMempool();
            details.w_remove_abandoned = wtx->isAbandoned();
        }

        // Delegation contract details
        Delegation delegation;
        CTxDestination dest = DecodeDestination(sAddress);
        if(std::holds_alternative<PKHash>(dest))
        {
            PKHash keyID = std::get<PKHash>(dest);
            uint160 address(keyID);
            details.c_contract_return = m_qtumDelegation.ExistDelegationContract() ? m_qtumDelegation.GetDelegation(address, delegation, m_wallet->chain().chainman().ActiveChainstate()) : false;
            if(details.c_contract_return)
            {
                details.c_entry_exist = m_qtumDelegation.VerifyDelegation(address, delegation);
                details.c_delegate_address = sAddress;
                details.c_staker_address = EncodeDestination(PKHash(delegation.staker));
                details.c_fee = delegation.fee;
                details.c_block_number = delegation.blockHeight;
            }
        }

        return details;
    }
    std::vector<DelegationInfo> getDelegations() override
    {
        LOCK(m_wallet->cs_wallet);

        std::vector<DelegationInfo> result;
        result.reserve(m_wallet->mapDelegation.size());
        for (const auto& entry : m_wallet->mapDelegation) {
            result.emplace_back(MakeWalletDelegationInfo(entry.second));
        }
        return result;
    }
    bool removeDelegationEntry(const std::string &sHash) override
    {
        return m_wallet->RemoveDelegationEntry(uint256S(sHash), true);
    }
    bool setDelegationRemoved(const std::string &sHash, const std::string &sTxid) override
    {
        bool found = false;
        DelegationInfo info;
        {
            LOCK(m_wallet->cs_wallet);

            uint256 id;
            id.SetHex(sHash);

            uint256 txid;
            txid.SetHex(sTxid);

            auto mi = m_wallet->mapDelegation.find(id);
            if (mi != m_wallet->mapDelegation.end()) {
                info = MakeWalletDelegationInfo(mi->second);
                info.remove_tx_hash = txid;
                found = true;
            }
        }

        return found ? addDelegationEntry(info) : 0;
    }
    uint32_t restoreSuperStakers() override
    {
        RefreshDelegates(m_wallet.get(), false, true);

        LOCK(m_wallet->cs_wallet);

        std::map<uint160, bool> stakerAddressExist;
        for (const auto& item : m_wallet->m_delegations_staker) {
            uint160 staker = item.second.staker;
            if(!stakerAddressExist[staker])
                stakerAddressExist[staker] = true;
        }

        int ret = 0;
        for (const auto& item : stakerAddressExist) {
            std::string staker_address = KeyIdToString(item.first);
            if(!existSuperStaker(staker_address))
            {
                SuperStakerInfo info;
                info.staker_name = staker_address;
                info.staker_address = staker_address;
                if(addSuperStakerEntry(info))
                    ret++;
            }
        }

        return ret;
    }
    bool existSuperStaker(const std::string &sAddress) override
    {
        LOCK(m_wallet->cs_wallet);
        uint160 address = StringToKeyId(sAddress);
        if(address.IsNull())
            return false;

        for (const auto& entry : m_wallet->mapSuperStaker) {
            if(entry.second.stakerAddress == address)
                return true;
        }

        return false;
    }
    SuperStakerInfo getSuperStaker(const uint256& id) override
    {
        LOCK(m_wallet->cs_wallet);

        auto mi = m_wallet->mapSuperStaker.find(id);
        if (mi != m_wallet->mapSuperStaker.end()) {
            return MakeWalletSuperStakerInfo(mi->second);
        }
        return {};
    }
    SuperStakerInfo getSuperStakerRecommendedConfig() override
    {
        LOCK(m_wallet->cs_wallet);

        // Set recommended config
        SuperStakerInfo config;
        config.custom_config = false;
        config.min_fee = m_wallet->m_staking_min_fee;
        config.min_delegate_utxo = m_wallet->m_staking_min_utxo_value;
        config.delegate_address_type = SuperStakerAddressList::AcceptAll;

        // Get allow list
        std::vector<std::string> allowList;
        for (const std::string& strAddress : gArgs.GetArgs("-stakingallowlist"))
        {
            if(!StringToKeyId(strAddress).IsNull())
            {
                if(std::find(allowList.begin(), allowList.end(), strAddress) == allowList.end())
                    allowList.push_back(strAddress);
            }
        }

        // Get exclude list
        std::vector<std::string> excludeList;
        for (const std::string& strAddress : gArgs.GetArgs("-stakingexcludelist"))
        {
            if(!StringToKeyId(strAddress).IsNull())
            {
                if(std::find(excludeList.begin(), excludeList.end(), strAddress) == excludeList.end())
                    excludeList.push_back(strAddress);
            }
        }

        // Set the address list
        if(!allowList.empty())
        {
            config.delegate_address_type =  SuperStakerAddressList::AllowList;
            config.delegate_address_list = allowList;
        }
        else if(!excludeList.empty())
        {
            config.delegate_address_type = SuperStakerAddressList::ExcludeList;
            config.delegate_address_list = excludeList;
        }

        return config;
    }
    std::vector<SuperStakerInfo> getSuperStakers() override
    {
        LOCK(m_wallet->cs_wallet);

        std::vector<SuperStakerInfo> result;
        result.reserve(m_wallet->mapSuperStaker.size());
        for (const auto& entry : m_wallet->mapSuperStaker) {
            result.emplace_back(MakeWalletSuperStakerInfo(entry.second));
        }
        return result;
    }
    bool addSuperStakerEntry(const SuperStakerInfo &superStaker) override
    {
        return m_wallet->AddSuperStakerEntry(MakeSuperStakerInfo(superStaker), true);
    }
    bool removeSuperStakerEntry(const std::string &sHash) override
    {
        return m_wallet->RemoveSuperStakerEntry(uint256S(sHash), true);
    }
    bool tryGetStakeWeight(uint64_t& nWeight) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }

        nWeight = m_wallet->GetStakeWeight();
        return true;
    }
    uint64_t getStakeWeight() override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetStakeWeight();
    }
    int64_t getLastCoinStakeSearchInterval() override 
    { 
        return m_wallet->m_last_coin_stake_search_interval;
    }
    bool getWalletUnlockStakingOnly() override
    {
        return m_wallet->m_wallet_unlock_staking_only;
    }
    void setWalletUnlockStakingOnly(bool unlock) override
    {
        m_wallet->m_wallet_unlock_staking_only = unlock;
    }
    bool cleanTokenTxEntries() override
    {
        return m_wallet->CleanTokenTxEntries();
    }
    void setEnabledStaking(bool enabled) override
    {
        m_wallet->m_enabled_staking = enabled;
    }
    bool getEnabledStaking() override
    {
        return m_wallet->m_enabled_staking;
    }
    bool getEnabledSuperStaking() override
    {
        bool fSuperStake = gArgs.GetBoolArg("-superstaking", DEFAULT_SUPER_STAKE);
        return fSuperStake;
    }
    DelegationStakerInfo getDelegationStaker(const uint160& id) override
    {
        LOCK(m_wallet->cs_wallet);

        auto mi = m_wallet->m_delegations_staker.find(id);
        if (mi != m_wallet->m_delegations_staker.end()) {
            return MakeWalletDelegationStakerInfo(*m_wallet, mi->first, mi->second);
        }
        return {};
    }
    std::vector<DelegationStakerInfo> getDelegationsStakers() override
    {
        LOCK(m_wallet->cs_wallet);

        std::vector<DelegationStakerInfo> result;
        result.reserve(m_wallet->m_delegations_staker.size());
        for (const auto& entry : m_wallet->m_delegations_staker) {
            result.emplace_back(MakeWalletDelegationStakerInfo(*m_wallet, entry.first, entry.second));
        }
        return result;
    }
    uint64_t getSuperStakerWeight(const uint256& id) override
    {
        LOCK(m_wallet->cs_wallet);
        SuperStakerInfo info = getSuperStaker(id);
        CTxDestination dest = DecodeDestination(info.staker_address);
        if(std::holds_alternative<PKHash>(dest))
        {
            PKHash keyID = std::get<PKHash>(dest);
            uint160 address(keyID);
            return m_wallet->GetSuperStakerWeight(address);
        }

        return 0;
    }
    bool isSuperStakerStaking(const uint256& id, CAmount& delegationsWeight) override
    {
        uint64_t lastCoinStakeSearchInterval = getEnabledStaking() ? getLastCoinStakeSearchInterval() : 0;
        delegationsWeight = getSuperStakerWeight(id);
        return lastCoinStakeSearchInterval && delegationsWeight;
    }
    bool getStakerAddressBalance(const std::string& staker, CAmount& balance, CAmount& stake, CAmount& weight) override
    {
        LOCK(m_wallet->cs_wallet);

        CTxDestination dest = DecodeDestination(staker);
        if(std::holds_alternative<PKHash>(dest))
        {
            PKHash keyID = std::get<PKHash>(dest);
            m_wallet->GetStakerAddressBalance(keyID, balance, stake, weight);
            return true;
        }

        return false;
    }
    bool getAddDelegationData(const std::string& psbt, std::map<int, SignDelegation>& signData, std::string& error) override
    {
        LOCK(m_wallet->cs_wallet);

        try
        {
            // Decode transaction
            PartiallySignedTransaction decoded_psbt;
            if(!DecodeBase64PSBT(decoded_psbt, psbt, error))
            {
                error = "Fail to decode PSBT transaction";
                return false;
            }

            if(decoded_psbt.tx->HasOpCall())
            {
                // Get sender destination
                CTransaction tx(*(decoded_psbt.tx));
                CTxDestination txSenderDest;
                if(m_wallet->GetSenderDest(tx, txSenderDest, false) == false)
                {
                    error = "Fail to get sender destination";
                    return false;
                }

                // Get sender HD path
                std::string strSender;
                if(m_wallet->GetHDKeyPath(txSenderDest, strSender) == false)
                {
                    error = "Fail to get HD key path for sender";
                    return false;
                }

                // Get unsigned staker
                for(size_t i = 0; i < decoded_psbt.tx->vout.size(); i++){
                    CTxOut v = decoded_psbt.tx->vout[i];
                    if(v.scriptPubKey.HasOpCall()){
                        std::vector<unsigned char> data;
                        v.scriptPubKey.GetData(data);
                        if(QtumDelegation::IsAddBytecode(data))
                        {
                            std::string hexStaker;
                            if(!QtumDelegation::GetUnsignedStaker(data, hexStaker))
                            {
                                error = "Fail to get unsigned staker";
                                return false;
                            }

                            // Set data to sign
                            SignDelegation signDeleg;
                            signDeleg.delegate = strSender;
                            signDeleg.staker = hexStaker;
                            signData[i] = signDeleg;
                        }
                    }
                }
            }
        }
        catch(...)
        {
            error = "Unknown error happen";
            return false;
        }

        return true;
    }
    bool setAddDelegationData(std::string& psbt, const std::map<int, SignDelegation>& signData, std::string& error) override
    {
        // Decode transaction
        PartiallySignedTransaction decoded_psbt;
        if(!DecodeBase64PSBT(decoded_psbt, psbt, error))
        {
            error = "Fail to decode PSBT transaction";
            return false;
        }

        // Set signed staker address
        size_t size = decoded_psbt.tx->vout.size();
        for (auto it = signData.begin(); it != signData.end(); it++)
        {
            size_t n = it->first;
            std::string PoD = it->second.PoD;

            if(n >= size)
            {
                error = "Output not found";
                return false;
            }

            CTxOut& v = decoded_psbt.tx->vout[n];
            if(v.scriptPubKey.HasOpCall()){
                std::vector<unsigned char> data;
                v.scriptPubKey.GetData(data);
                CScript scriptRet;
                if(QtumDelegation::SetSignedStaker(data, PoD) && v.scriptPubKey.SetData(data, scriptRet))
                {
                    v.scriptPubKey = scriptRet;
                }
                else
                {
                    error = "Fail to set PoD";
                    return false;
                }
            }
            else
            {
                error = "Output not op_call";
                return false;
            }
        }

        // Serialize the PSBT
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << decoded_psbt;
        psbt = EncodeBase64(ssTx.str());

        return true;
    }
    void setStakerLedgerId(const std::string& ledgerId) override
    {
        LOCK(m_wallet->cs_wallet);
        m_wallet->m_ledger_id = ledgerId;
    }
    std::string getStakerLedgerId() override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->m_ledger_id;
    }
    std::unique_ptr<Handler> handleUnload(UnloadFn fn) override
    {
        return MakeHandler(m_wallet->NotifyUnload.connect(fn));
    }
    std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) override
    {
        return MakeHandler(m_wallet->ShowProgress.connect(fn));
    }
    std::unique_ptr<Handler> handleStatusChanged(StatusChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyStatusChanged.connect([fn](CWallet*) { fn(); }));
    }
    std::unique_ptr<Handler> handleAddressBookChanged(AddressBookChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyAddressBookChanged.connect(
            [fn](const CTxDestination& address, const std::string& label, bool is_mine,
                 const std::string& purpose, ChangeType status) { fn(address, label, is_mine, purpose, status); }));
    }
    std::unique_ptr<Handler> handleTransactionChanged(TransactionChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyTransactionChanged.connect(
            [fn](const uint256& txid, ChangeType status) { fn(txid, status); }));
    }
    std::unique_ptr<Handler> handleTokenTransactionChanged(TokenTransactionChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyTokenTransactionChanged.connect(
            [fn](CWallet*, const uint256& id, ChangeType status) { fn(id, status); }));
    }
    std::unique_ptr<Handler> handleTokenChanged(TokenChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyTokenChanged.connect(
            [fn](CWallet*, const uint256& id, ChangeType status) { fn(id, status); }));
    }
    std::unique_ptr<Handler> handleWatchOnlyChanged(WatchOnlyChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyWatchonlyChanged.connect(fn));
    }
    std::unique_ptr<Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyCanGetAddressesChanged.connect(fn));
    }
    std::unique_ptr<Handler> handleContractBookChanged(ContractBookChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyContractBookChanged.connect(
            [fn](CWallet*, const std::string& address, const std::string& label,
                const std::string& abi, ChangeType status) { fn(address, label, abi, status); }));
    }
    std::unique_ptr<Handler> handleDelegationChanged(DelegationChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyDelegationChanged.connect(
            [fn](CWallet*, const uint256& id, ChangeType status) { fn(id, status); }));
    }
    std::unique_ptr<Handler> handleSuperStakerChanged(SuperStakerChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifySuperStakerChanged.connect(
            [fn](CWallet*, const uint256& id, ChangeType status) { fn(id, status); }));
    }
    std::unique_ptr<Handler> handleDelegationsStakerChanged(DelegationsStakerChangedFn fn) override
    {
        return MakeHandler(m_wallet->NotifyDelegationsStakerChanged.connect(
            [fn](CWallet*, const uint160& id, ChangeType status) { fn(id, status); }));
    }
    CWallet* wallet() override { return m_wallet.get(); }

    std::shared_ptr<CWallet> m_wallet;
    QtumDelegation m_qtumDelegation;
};

class WalletClientImpl : public WalletClient
{
public:
    WalletClientImpl(Chain& chain, ArgsManager& args)
    {
        m_context.chain = &chain;
        m_context.args = &args;
    }
    ~WalletClientImpl() override { UnloadWallets(); }

    //! ChainClient methods
    void registerRpcs() override
    {
        for (const CRPCCommand& command : GetWalletRPCCommands()) {
            m_rpc_commands.emplace_back(command.category, command.name, [this, &command](const JSONRPCRequest& request, UniValue& result, bool last_handler) {
                JSONRPCRequest& wallet_request = (JSONRPCRequest&)request;
                wallet_request.context = &m_context;
                return command.actor(wallet_request, result, last_handler);
            }, command.argNames, command.unique_id);
            m_rpc_handlers.emplace_back(m_context.chain->handleRpc(m_rpc_commands.back()));
        }
    }
    bool verify() override { return VerifyWallets(*m_context.chain); }
    bool load() override { return LoadWallets(*m_context.chain); }
    void start(CScheduler& scheduler) override { return StartWallets(scheduler, *Assert(m_context.args)); }
    void flush() override { return FlushWallets(); }
    void stop() override { return StopWallets(); }
    void setMockTime(int64_t time) override { return SetMockTime(time); }

    //! WalletClient methods
    std::unique_ptr<Wallet> createWallet(const std::string& name, const SecureString& passphrase, uint64_t wallet_creation_flags, bilingual_str& error, std::vector<bilingual_str>& warnings) override
    {
        std::shared_ptr<CWallet> wallet;
        DatabaseOptions options;
        DatabaseStatus status;
        options.require_create = true;
        options.create_flags = wallet_creation_flags;
        options.create_passphrase = passphrase;
        return MakeWallet(CreateWallet(*m_context.chain, name, true /* load_on_start */, options, status, error, warnings));
    }
    std::unique_ptr<Wallet> loadWallet(const std::string& name, bilingual_str& error, std::vector<bilingual_str>& warnings) override
    {
        DatabaseOptions options;
        DatabaseStatus status;
        options.require_existing = true;
        return MakeWallet(LoadWallet(*m_context.chain, name, true /* load_on_start */, options, status, error, warnings));
    }
    std::string getWalletDir() override
    {
        return GetWalletDir().string();
    }
    std::vector<std::string> listWalletDir() override
    {
        std::vector<std::string> paths;
        for (auto& path : ListDatabases(GetWalletDir())) {
            paths.push_back(path.string());
        }
        return paths;
    }
    std::vector<std::unique_ptr<Wallet>> getWallets() override
    {
        std::vector<std::unique_ptr<Wallet>> wallets;
        for (const auto& wallet : GetWallets()) {
            wallets.emplace_back(MakeWallet(wallet));
        }
        return wallets;
    }
    std::unique_ptr<Handler> handleLoadWallet(LoadWalletFn fn) override
    {
        return HandleLoadWallet(std::move(fn));
    }

    WalletContext m_context;
    const std::vector<std::string> m_wallet_filenames;
    std::vector<std::unique_ptr<Handler>> m_rpc_handlers;
    std::list<CRPCCommand> m_rpc_commands;
};
} // namespace
} // namespace wallet

namespace interfaces {
std::unique_ptr<Wallet> MakeWallet(const std::shared_ptr<CWallet>& wallet) { return wallet ? std::make_unique<wallet::WalletImpl>(wallet) : nullptr; }

std::unique_ptr<WalletClient> MakeWalletClient(Chain& chain, ArgsManager& args)
{
    return std::make_unique<wallet::WalletClientImpl>(chain, args);
}
} // namespace interfaces
