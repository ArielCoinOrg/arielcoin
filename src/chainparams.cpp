// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <arith_uint256.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward, uint64_t nNonce64, uint256 mix_hash)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nNonce64  = nNonce64;
    genesis.mix_hash  = mix_hash;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward, uint64_t nNonce64, uint256 mix_hash)
{
    const char* pszTimestamp = "whitehouse.gov 19/Jan/2022 Memorandum on Improving the Cybersecurity";
    const CScript genesisOutputScript = CScript() << ParseHex("07c36441284b082151a216e7105cda5f51e7cbceea126fd1af7f20023331735300f7c803d53edbb1acf7376c9f23562e5fd23960be1cd386303d8a474300b3f25f60ff81b5056cddf63dc41c9fd9aaa844467d8bcee77b3ae089d20acd270f075ff4db493930aacb0891fb5f77425c4e1405de0139c5968295f86de7c9e641fda224af41ba2188a283b103e7d5b3a7fa03a3b14939dacd49b565e6dbdd8707412c000722f998afd5ca42f3c4034ad6db32c05540e61818bfc551681f921180c4d69764d41fb150758dfcf54273c77a27aa727f985ccf2f688fec0a37643ebcbc7b692498321949dd97fb1f0619d4831326d7402cdf652431b469de8b7fdb6a269dc76dfea3c566a8172cb6610ca3a676e203ecde4fa48453932e760810757c0b557ce700ba976403312b4266a1f89c1a5ed84e28b4ae9cc3f73b66847c4594cbb176c0856dafa306d2ef0ebb5182ac7bff955bbaf445a025230c532b5d4ab42d05ebf448b6467d1ff6f7f706688517cc2cbefd69dfbe82d0ee83490071ee78ae6b6b80dd5c10e6b91b168361d6dd02b52b04bb46cae63dc6455ac91e4dc3deef348d0868002e53a5311bab915ad52ee36618ef85a1196dc67a2814dad2125ddadb965bab01970eee12af39085ecdb53786fe5cf8778ab833372ce1a7f0d5a18e81a9b3a6b61f6e2715dfce99b2c58b25917192fc0569970670a7d1e0dc7553707c3608d385eddd1134f5edcc6b4afe7ae4071f32e2da547aaf6fd0207111f2197fa7e56fa2b469d932dfd4ba76b8a7bfb91ec0ff9b3a0e22627c1e4b21c327b3c76990fafe7e6b10a0cc670dcba1e431fe13c09bb5b5bba84389aa1ff85bdbd6de48999829c85020b3a37ba47692139f9436d0e1755e448b8d856d54ea8298704afb34480414f1e993cb8f59d6c55a0be19bb18de0f4c10d742de4478c6f529aac37e32375e8923864e467ce1814635cc243b294d6f5ec9dd93d5929fce37b1daa3c0821337d84644822d41adbc72bb5b0c97cd1218788e2fe1d7d3bb2456e7d31a702f0e4d4a026c66761cc8a86610f19f169ff682338c4f9375ad82647fee4c452708ec9670e9f90abc4642cd8d2d6208ab3137f9bfc65a46ead3dfe5abf16ece4c936eee869718ad64b39d58359e450a2988c3986c591a3381ec7e425fbd282ff799e41cf3f553aefe13be0ba7ffff0f6a8a73b24d2117961fdb7993fb3a26175edce550c78b21a255e333a5d7f32afae546ea456a19a5c91e6dd8d9c394723783fd443bb4fa996816896d10d2c71bb8da23aa202d6af26879c202681cae33a250c9ff3f8cc643daa7907460dd4ff3e7ecbdea949d2e7251ece688ad9225fd287459a4894af8abc1294a509f1e5773d073590bcc3d2116f696e70d42f870dea9a69d23db353e0cd146bc75cb719472eb9e07625401b4613d49237ba38c1ac9674e65df9834e1b273734a8eabef6d3d388ab90e0cd45b339f0afbb0f5b297682c24a3e70390fb1f3deb94053551dd9940019931261bcb641361baae5e875d18d23a4ffd4b36db36ea176821609fdbe95d2d6a7714665f9b86e9f17c2b2df00d384f057bee7de14fc218379f7ce575f978c7f8113569c0893ab0cbbcd06cd94d595536803d7089af0fa72bb5e49483729fe952a5bba2c1c20b2a6552ba599d83320174e5c373e9a5fb63fb8ddd736ce307c487f6d053d376047ec60cd6b9f747d271d849a13215dc257543ca50548e521d4420dada351e2f2d19b8ad935e4ab7eb129eb65768754920faa100221087db5846d4de6d476696bbbf38527f339149c8688365952e6400db43c3f7a43e438ee26dbfcb25870b65161fed7411a25d4acda5da36c7ba7c40c6d51a59a320ba14a21538c763113fcb1a3154fdc91551ec7433d56bda5fd8ffdaf15db6668727869ba154a7eed0dda06d24fa2d457fa12a51032d00b9763586e8baf7e1db5b569d96f7a1fbdc1c18054fa8939f5b099fb6935a6af05f6a9691a8c36c8d2aebd6bb97ee0834267698eaf0f7e85ffd0e8784f5749bb8608ef26a95aae7232425073f0c882445c163d79a2a957029e576806ac969cdb0c825e82ed8b7a1020807a0fbe0dc239034315d2bc9894994f17623d08427c4fc9bfb01a49f2fd8cd0f7b138343e30df07a15ba37606f06492bd311a81528ffda080f7be3d13c1edbb930912e11e5caaf2e95b069af07ed56b06f18ef8abff4e7b9b8378831dd3cb63254f119e25918f080c0d75425d6f0e773642c2b4fd96f8f34bc8d560ae7b9f11c6bb82a04f6d1aad4d65bd2aec4d8a71533f10a427b557939521c634ec2e51adad1b3236e1ae0b619451c1707945506c325f2b3647921d10f527119f2bb90354f8b6d273c6ac31ab80521239f32d3441930851ed5312138e25889571f2126b5fef0820cc6edb5ba23fdc56f367b9b88f2007071976e5dad91f112c98f1728d41a287e28c44de5ab5c851a8ba37c41c988cdd4980b89e11fd00733dde98e90afa1fc58563a5a1b07f64bac86efd105500a293057f13487e29277e9828ea11d9bce233ab9bfae14a6cf1e253f818104370080feba70a5dd2dd31d6f3282f23fb91fe933dea9e67904515c05e844f413e744106eab3b1b7e23a8c314bd20887c7c6aa4efe3d54d286b86112499f40035e0808f597be9a39b82e7468722291c38652a15b59f6b8a81fcbc97c5cf95476ff63f8b1ea90502eae674d8539ecec5146ea218d1b9d9b535bb64bcb0934f08f29577434bc19") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward,nNonce64,mix_hash);
}

bool CheckPoW(uint256 hash, unsigned int nBits, uint256 powLimit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

static CBlock FindGenesisBlock()
{

    CBlock block = CreateGenesisBlock(1645356868, 0, 0x1e00ffff, 1, 50 * COIN, 1, uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"));

    arith_uint256 bnTarget;
    bnTarget.SetCompact(block.nBits);
    
    std::cout << "Target: " << bnTarget.ToString()<< std::endl;
    std::cout.flush();
        

    for (uint64_t nNonce = 32768333; nNonce < UINT64_MAX; nNonce++) {    

    block.nNonce64=nNonce;

    uint256 hash = block.GetHash();

    if(!CheckPoW(hash, block.nBits, uint256S("0000ffff00000000000000000000000000000000000000000000000000000000")) ) {        
        std::cout << "Hash: " << hash.ToString() << " work: " << UintToArith256(hash).ToString() << " Target: " << bnTarget.ToString() << std::endl;
        std::cout.flush();        
    } else {
                uint256 mix_hash;
                uint256 hashfull = block.GetHashFull(mix_hash);
    
                std::cout << "BLOCK NOONCE: " << block.nNonce64 << std::endl;
                std::cout << "BLOCK HASH: " << hash.ToString() << std::endl;
                std::cout << "BLOCK FULLHASH: " << hashfull .ToString() << std::endl;
                std::cout << "BLOCK MIX_HASH: " << mix_hash.ToString() << std::endl;
                std::cout << "BLOCK NONCE64: " << block.nNonce64 << std::endl;
                std::cout << "BLOCK NONCE: " << block.nNonce64 << std::endl;
                std::cout << "BLOCK ROOT: " << block.hashMerkleRoot.ToString() << std::endl;
                std::cout.flush();
                return block;
                
            }
    }

    assert(false);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 525600;
        consensus.BIP16Height = 1;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("");
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nPowTargetTimespan = 24 * 60 * 60; // 5 day
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nPowKGWHeight = 5;
        consensus.nPowDGWHeight = 10;
        consensus.nMinimumDifficultyBlocks = 10;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing * 4
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0; 
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE; 
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT; 

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x01");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S(""); //1683528

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x51;
        pchMessageStart[1] = 0x42;
        pchMessageStart[2] = 0x49;
        pchMessageStart[3] = 0x54;
        nDefaultPort = 8686;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

    


        genesis = CreateGenesisBlock(1645356868, 0, 0x1e00ffff, 1, 50 * COIN, 38899382, uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"));
        consensus.hashGenesisBlock = genesis.GetHash();
        //std::cout << "GENESIS BLOCK HASH: " << genesis.GetHash().ToString() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S("0x000000a9ea82f2b776be3115ecd5d72333fcb0f9d9cb3dacbc881c6090f9378f"));
        assert(genesis.hashMerkleRoot == uint256S("0x443e96d1f6f788de8c18024f57e7c6e77ea983f14a7a4f540cc48858f343db68"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        
        vSeeds.emplace_back("seed.arielcoin.org");
        vSeeds.emplace_back("seed.qubit.black");
        vSeeds.emplace_back("seed.qubit.red");
        
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,58);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,70);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,23);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,125);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x07, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x07, 0x88, 0xAD, 0xE4};

        bech32_hrp = "arl";

        //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + 0);
        vFixedSeeds.clear();
        //vSeeds.clear();

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {            
            //   { 1500, uint256S("e588ef31c4ea967932fcd7b487b4a6e9ef2994417b95e84a920bf3d241689167")},
            //   { 3000, uint256S("98f019517ad92d0221189b40c75f0e5ffe0367a61dfd03f668b3fccfb89fdb0a")},
            //   { 4500, uint256S("b56661efe2a30617162e7974f665b7b0c8f44cf36ade2b85141883528903f914")},
            //   { 6000, uint256S("0a2f3c68489fc3a6139a47844fd2e0b6d64f2fd910e7ecfc95e770ea4d833097")},
            //   { 8000, uint256S("d622d8bdcea37448de74f81ae7303c0c22c8660fcd264bb9b176258b8f4b9746")},
            //   { 9450, uint256S("c24419a117f4ed9c88ea21342f3f2b91bb549166e4417c8f315a323c1f7edfaf")},
            //   { 11443, uint256S("928357d009ebe470e29ae8a6e71d1657fda98260249b2ababb94ef5118d107dd")},
            //   { 14870, uint256S("fbb5bf51bcc94c56c172949709e72a888422cd521b07df7bda862df38b6a8697")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 2cdba8c47858d34cf0e02dfb8733263a3ed8705b1663ec7c158783d77b93e7ee
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 525600;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on testnet
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("");
        consensus.BIP65Height = 1; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.BIP66Height = 1; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 5* 24 * 60 * 60; // 5 days
        consensus.nPowTargetSpacing = 60;
        consensus.nPowKGWHeight = 4002; // nPowKGWHeight >= nPowDGWHeight means "no KGW"
        consensus.nPowDGWHeight = 4002; // TODO: make sure to drop all spork6 related code on next testnet reset
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x01");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("");

        pchMessageStart[0] = 0x74;
        pchMessageStart[1] = 0x61;
        pchMessageStart[2] = 0x72;
        pchMessageStart[3] = 0x6c;
        nDefaultPort = 18686;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 2;
        m_assumed_chain_state_size = 1;
        
        
        genesis = CreateGenesisBlock(1645356868, 0, 0x1e00ffff, 1, 50 * COIN, 38899382, uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"));
        consensus.hashGenesisBlock = genesis.GetHash();
        //std::cout << "GENESIS BLOCK HASH: " << genesis.GetHash().ToString() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S("0x000000a9ea82f2b776be3115ecd5d72333fcb0f9d9cb3dacbc881c6090f9378f"));
        assert(genesis.hashMerkleRoot == uint256S("0x443e96d1f6f788de8c18024f57e7c6e77ea983f14a7a4f540cc48858f343db68"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testseed.qubit.black");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,132);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,127);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x07, 0x57, 0x28, 0xAF};
        base58Prefixes[EXT_SECRET_KEY] = {0x07, 0x57, 0x37, 0xB6};

        bech32_hrp = "tarl";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 e79561972208ba3a02c308482176b33f3ec841d4213ea7bbaa3f22b7c8a16f32
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 20;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x01");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x72;
        pchMessageStart[1] = 0x61;
        pchMessageStart[2] = 0x72;
        pchMessageStart[3] = 0x6c;
        nDefaultPort = 18778;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateVersionBitsParametersFromArgs(args);



        genesis = CreateGenesisBlock(1645356868, 0, 0x1e00ffff, 1, 50 * COIN, 38899382, uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"));
        consensus.hashGenesisBlock = genesis.GetHash();
        //std::cout << "GENESIS BLOCK HASH: " << genesis.GetHash().ToString() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S("0x000000a9ea82f2b776be3115ecd5d72333fcb0f9d9cb3dacbc881c6090f9378f"));
        assert(genesis.hashMerkleRoot == uint256S("0x443e96d1f6f788de8c18024f57e7c6e77ea983f14a7a4f540cc48858f343db68"));


        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = {
            {
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,123);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x07, 0x45, 0x65, 0xAF};
        base58Prefixes[EXT_SECRET_KEY] = {0x07, 0x45, 0x56, 0xCE};

        bech32_hrp = "rarl";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
