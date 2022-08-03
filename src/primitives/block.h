// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <libdevcore/SHA3.h>
#include <libdevcore/RLP.h>
#include "arith_uint256.h"
#include <util/convert.h>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */

static const uint32_t nSmartActivationBlock = 1000;

class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    uint32_t nHeight;
    uint64_t nNonce64;
    uint256 mix_hash;

    uint256 hashStateRoot = uint256S("9514771014c9ae803d8cea2731b2063e83de44802b40dce2d06acd02d0ff65e9"); // qtum; // qtum
    uint256 hashUTXORoot = uint256S("21b463e3b52f6201c0ad6c991be0485b6ef8c092e64583ffa655cc1b171fe856"); // qtum; // qtum
    // proof-of-stake specific fields
    COutPoint prevoutStake;
    std::vector<unsigned char> vchBlockSigDlgt; // The delegate is 65 bytes or 0 bytes, it can be added in the signature paramether at the end to avoid compatibility problems

    CBlockHeader()
    {
        SetNull();
    }
    virtual ~CBlockHeader(){};

    SERIALIZE_METHODS(CBlockHeader, obj) {
        READWRITE(obj.nVersion);
        READWRITE(obj.hashPrevBlock);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.nTime);
        READWRITE(obj.nBits);
//        READWRITE(obj.nNonce);
        READWRITE(obj.nHeight);
        READWRITE(obj.nNonce64);
        READWRITE(obj.mix_hash);
        if (nSmartActivationBlock < obj.nHeight){
            READWRITE(obj.hashStateRoot);
            READWRITE(obj.hashUTXORoot);
            READWRITE(obj.prevoutStake);
            READWRITE(obj.vchBlockSigDlgt);
        }
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;

        nNonce64 = 0;
        nHeight = 0;
        mix_hash.SetNull();

        hashStateRoot.SetNull(); // qtum
        hashUTXORoot.SetNull(); // qtum
        vchBlockSigDlgt.clear();
        prevoutStake.SetNull();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    uint256 GetHashWithoutSign() const;

    std::string GetWithoutSign() const;

    uint256 GetHashFull(uint256& mix_hash) const;
    uint256 GetKAWPOWHeaderHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    // ppcoin: two types of block: proof-of-work or proof-of-stake
    virtual bool IsProofOfStake() const //qtum
    {
        return !prevoutStake.IsNull();
    }

    virtual bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    virtual uint32_t StakeTime() const
    {
        uint32_t ret = 0;
        if(IsProofOfStake())
        {
            ret = nTime;
        }
        return ret;
    }

    void SetBlockSignature(const std::vector<unsigned char>& vchSign);
    std::vector<unsigned char> GetBlockSignature() const;

    void SetProofOfDelegation(const std::vector<unsigned char>& vchPoD);
    std::vector<unsigned char> GetProofOfDelegation() const;

    bool HasProofOfDelegation() const;

    CBlockHeader& operator=(const CBlockHeader& other) //qtum
    {
        if (this != &other)
        {
            this->nVersion       = other.nVersion;
            this->hashPrevBlock  = other.hashPrevBlock;
            this->hashMerkleRoot = other.hashMerkleRoot;
            this->nTime          = other.nTime;
            this->nBits          = other.nBits;
            this->nNonce         = other.nNonce;
            this->nHeight        = other.nHeight;
            this->nNonce64       = other.nNonce64;
            this->mix_hash       = other.mix_hash;
            this->hashStateRoot  = other.hashStateRoot;
            this->hashUTXORoot   = other.hashUTXORoot;
            this->vchBlockSigDlgt    = other.vchBlockSigDlgt;
            this->prevoutStake   = other.prevoutStake;
        }
        return *this;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    std::pair<COutPoint, unsigned int> GetProofOfStake() const //qtum
    {
        return IsProofOfStake()? std::make_pair(prevoutStake, nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;

        block.nHeight        = nHeight;
        block.nNonce64       = nNonce64;
        block.mix_hash       = mix_hash;

        block.hashStateRoot  = hashStateRoot; // qtum
        block.hashUTXORoot   = hashUTXORoot; // qtum
        block.vchBlockSigDlgt    = vchBlockSigDlgt;
        block.prevoutStake   = prevoutStake;
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

class CKAWPOWInput : private CBlockHeader
{
public:
    CKAWPOWInput(const CBlockHeader &header)
    {
        CBlockHeader::SetNull();
        *((CBlockHeader*)this) = header;
    }

    SERIALIZE_METHODS(CKAWPOWInput, obj)
    {
        READWRITE(obj.nVersion);
        READWRITE(obj.hashPrevBlock);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.nTime);
        READWRITE(obj.nBits);
        READWRITE(obj.nHeight);
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
