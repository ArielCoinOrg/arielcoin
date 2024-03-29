// Copyright (c) 2014-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <net.h>
#include <signet.h>
#include <uint256.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    int maxHalvings = 7;
    CAmount nInitialSubsidy = 4 * COIN;

    CAmount nPreviousSubsidy = nInitialSubsidy * 2; // for height == LastPoWBlock + 1
    BOOST_CHECK_EQUAL(nPreviousSubsidy, nInitialSubsidy * 2);
    for (int nHalvings = 0; nHalvings < maxHalvings; nHalvings++) {
        int nHeight = nHalvings * consensusParams.nSubsidyHalvingInterval + consensusParams.nLastBigReward + 1;
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy <= nInitialSubsidy);
        BOOST_CHECK_EQUAL(nSubsidy, nPreviousSubsidy / 2);
        nPreviousSubsidy = nSubsidy;
    }
    BOOST_CHECK_EQUAL(GetBlockSubsidy(maxHalvings * consensusParams.nSubsidyHalvingInterval + consensusParams.nLastBigReward + 1, consensusParams), 0);
}

static void TestBlockSubsidyHalvings(int nSubsidyHalvingInterval)
{
    Consensus::Params consensusParams;
    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
    consensusParams.nReduceBlocktimeHeight = 0x7fffffff;
    TestBlockSubsidyHalvings(consensusParams);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    Consensus::Params consensusParams = chainParams->GetConsensus();
    consensusParams.nReduceBlocktimeHeight = 0x7fffffff; // Check for the halving before fork for target spacing
    TestBlockSubsidyHalvings(consensusParams); // As in main
    TestBlockSubsidyHalvings(150); // As in regtest
    TestBlockSubsidyHalvings(1000); // Just another interval
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, CBaseChainParams::MAIN);
    Consensus::Params consensusParams = chainParams->GetConsensus();
    consensusParams.nReduceBlocktimeHeight = 800000; // Check for the halving after fork for target spacing
    int nMaxHeight = 14000000 * consensusParams.nBlocktimeDownscaleFactor;
    CAmount nSum = 0;
    for (int nHeight = 1; nHeight < nMaxHeight; nHeight++) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        int nSubsidyHalvingWeight = consensusParams.SubsidyHalvingWeight(nHeight);
        int nSubsidyHalvingInterval = consensusParams.SubsidyHalvingInterval(nHeight);
        int nBlocktimeDownscaleFactor = consensusParams.BlocktimeDownscaleFactor(nHeight);

        if(nSubsidyHalvingWeight <= 0){
            BOOST_CHECK_EQUAL(nSubsidy, (20000 * COIN));
        }
        else if(nSubsidyHalvingWeight <= nSubsidyHalvingInterval){
            BOOST_CHECK_EQUAL(nSubsidy, 4 * COIN / nBlocktimeDownscaleFactor);
        }
        else if(nSubsidyHalvingWeight <= nSubsidyHalvingInterval*2){
            BOOST_CHECK_EQUAL(nSubsidy, 2 * COIN / nBlocktimeDownscaleFactor);
        }
        else if(nSubsidyHalvingWeight <= nSubsidyHalvingInterval*3){
            BOOST_CHECK_EQUAL(nSubsidy, 1 * COIN / nBlocktimeDownscaleFactor);
        }
        else if(nSubsidyHalvingWeight <= nSubsidyHalvingInterval*4){
            BOOST_CHECK_EQUAL(nSubsidy, 0.5 * COIN / nBlocktimeDownscaleFactor);
        }
        else if(nSubsidyHalvingWeight <= nSubsidyHalvingInterval*5){
            BOOST_CHECK_EQUAL(nSubsidy, 0.25 * COIN / nBlocktimeDownscaleFactor);
        }
        else if(nSubsidyHalvingWeight <= nSubsidyHalvingInterval*6){
            BOOST_CHECK_EQUAL(nSubsidy, 0.125 * COIN / nBlocktimeDownscaleFactor);
        }
        else if(nSubsidyHalvingWeight <= nSubsidyHalvingInterval*7){
            BOOST_CHECK_EQUAL(nSubsidy, 0.0625 * COIN / nBlocktimeDownscaleFactor);
        }
        else{
            BOOST_CHECK_EQUAL(nSubsidy, 0);
        }
        nSum += nSubsidy;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, 10782240625000000ULL);
}
//! Test retrieval of valid assumeutxo values.
BOOST_AUTO_TEST_CASE(test_assumeutxo)
{
    const auto params = CreateChainParams(*m_node.args, CBaseChainParams::UNITTEST);

    // These heights don't have assumeutxo configurations associated, per the contents
    // of chainparams.cpp.
    std::vector<int> bad_heights{0, 2000, 2011, 2015, 2109, 2111};

    for (auto empty : bad_heights) {
        const auto out = ExpectedAssumeutxo(empty, *params);
        BOOST_CHECK(!out);
    }

    const auto out110 = *ExpectedAssumeutxo(2010, *params);
    BOOST_CHECK_EQUAL(out110.hash_serialized.ToString(), "f3ad83776715ee9b09a7a43421b6fe17701fb2247370a4ea9fcf0b073639cac9");
    BOOST_CHECK_EQUAL(out110.nChainTx, 2010U);

    const auto out210 = *ExpectedAssumeutxo(2100, *params);
    BOOST_CHECK_EQUAL(out210.hash_serialized.ToString(), "677f8902ca481677862d19fbe8c6214f596c8b475aabfe4273361485fc4e6fb4");
    BOOST_CHECK_EQUAL(out210.nChainTx, 2100U);
}

BOOST_AUTO_TEST_SUITE_END()
