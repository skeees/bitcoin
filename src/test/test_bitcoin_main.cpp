// Copyright (c) 2011-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Bitcoin Test Suite

#include <net.h>

#include <memory>

#include <boost/test/unit_test.hpp>
#include <walletinitinterface.h>

[[noreturn]] void Shutdown(void* parg) {
    std::exit(EXIT_SUCCESS);
}

class DummyWalletInit : public WalletInitInterface
{
public:
    void AddWalletOptions() const override {}
    bool ParameterInteraction() const override { return true; }
    void RegisterRPC(CRPCTable&) const override {}
    bool Verify() const override { return true; }
    bool Open() const override
    {
        LogPrintf("No wallet support compiled in!\n");
        return true;
    }
    void Start(CScheduler& scheduler) const override {}
    void Flush() const override {}
    void Stop() const override {}
    void Close() const override {}
};

const WalletInitInterface& g_wallet_init_interface = DummyWalletInit();
