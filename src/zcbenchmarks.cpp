#include <cassert>
#include <unistd.h>

#include "key.h"
#include "pubkey.h"
#include "keystore.h"
#include "script/sign.h"
#include "streams.h"
#include "zcbenchmarks.h"

#define TARGET_TX_SIZE 1000000


void timer_start(timeval &tv_start)
{
    gettimeofday(&tv_start, 0);
}

double timer_stop(timeval &tv_start)
{
    double elapsed;
    struct timeval tv_end;
    gettimeofday(&tv_end, 0);
    elapsed = double(tv_end.tv_sec-tv_start.tv_sec) +
        (tv_end.tv_usec-tv_start.tv_usec)/double(1000000);
    return elapsed;
}

double benchmark_sleep()
{
    struct timeval tv_start;
    timer_start(tv_start);
    sleep(1);
    return timer_stop(tv_start);
}

double benchmark_large_tx()
{
    // Number of inputs in the spending transaction that we will simulate
    const size_t NUM_INPUTS = 555;

    // Create priv/pub key
    CKey priv;
    priv.MakeNewKey(false);
    CPubKey pub = priv.GetPubKey();
    CBasicKeyStore tempKeystore;
    tempKeystore.AddKey(priv);

    // The "original" transaction that the spending transaction will spend
    // from.
    CMutableTransaction m_orig_tx;
    m_orig_tx.vout.resize(1);
    m_orig_tx.vout[0].nValue = 1000000;
    CScript prevPubKey = GetScriptForDestination(pub.GetID());
    m_orig_tx.vout[0].scriptPubKey = prevPubKey;

    CTransaction orig_tx = CTransaction(m_orig_tx);

    CMutableTransaction spending_tx;
    uint256 input_hash = orig_tx.GetHash();
    // Add NUM_INPUTS inputs
    for (size_t i = 0; i < NUM_INPUTS; i++) {
        spending_tx.vin.push_back(CTxIn(input_hash, 0));
    }

    // Sign for all the inputs
    for (size_t i = 0; i < NUM_INPUTS; i++) {
        SignSignature(tempKeystore, prevPubKey, spending_tx, i, SIGHASH_ALL);
    }

    // Serialize:
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << spending_tx;
        //std::cout << "SIZE OF SPENDING TX: " << ss.size() << std::endl;

        uint64_t error = TARGET_TX_SIZE / 20; // 5% error
        assert(ss.size() < TARGET_TX_SIZE + error);
        assert(ss.size() > TARGET_TX_SIZE - error);
    }

    // Spending tx has all its inputs signed and does not need to be mutated anymore
    CTransaction final_spending_tx(spending_tx);

    // Benchmark signature verification costs:
    struct timeval tv_start;
    timer_start(tv_start);
    for (size_t i = 0; i < NUM_INPUTS; i++) {
        ScriptError serror = SCRIPT_ERR_OK;
        assert(VerifyScript(final_spending_tx.vin[i].scriptSig,
                            prevPubKey,
                            STANDARD_SCRIPT_VERIFY_FLAGS,
                            TransactionSignatureChecker(&final_spending_tx, i),
                            &serror));
    }
    return timer_stop(tv_start);
}
