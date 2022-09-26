#include <ariel/qtumutils.h>
#include <libdevcore/CommonData.h>
#include <pubkey.h>
#include <util/convert.h>
#include <logging.h>

using namespace dev;

bool qtumutils::btc_ecrecover(const dev::h256 &hash, const dev::u256 &v, const dev::h256 &r, const dev::h256 &s, dev::h256 &key)
{
    // Check input parameters
    if(v >= 256)
    {
        // Does not fit into 1 byte
        return false;
    }

    // Convert the data into format usable for btc
    CPubKey pubKey;
    std::vector<unsigned char> vchSig;
    vchSig.push_back((unsigned char)v);
    vchSig += r.asBytes();
    vchSig += s.asBytes();
    uint256 mesage = h256Touint(hash);

    // Recover public key from compact signature (65 bytes)
    // The public key can be compressed (33 bytes) or uncompressed (65 bytes)
    // Pubkeyhash is RIPEMD160 hash of the public key, handled both types
    if(pubKey.RecoverCompact(mesage, vchSig))
    {
        // Get the pubkeyhash
        CKeyID id = pubKey.GetID();
        size_t padding = sizeof(key) - sizeof(id);
        memset(key.data(), 0, padding);
        memcpy(key.data() + padding, id.begin(), sizeof(id));
        return true;
    }

    return false;
}

bool qtumutils::arl_dilithiumrecover(const dev::bytes &hash, const dev::bytes &signaturebytes, dev::h256 &key)
{
    LogPrintf("arl_dilithiumrecover 1 \n");
    // Convert the data into format usable for btc
    CPubKey pubKey;
    LogPrintf("arl_dilithiumrecover 22 \n");
    uint256 message = uint256(hash);
    LogPrintf("arl_dilithiumrecover 2 %s\n", message);

    // Recover public key from compact signature (65 bytes)
    // The public key can be compressed (33 bytes) or uncompressed (65 bytes)
    // Pubkeyhash is RIPEMD160 hash of the public key, handled both types
    if(pubKey.RecoverCompact(message, signaturebytes))
    {
        // Get the pubkeyhash
        CKeyID id = pubKey.GetID();
        size_t padding = sizeof(key) - sizeof(id);
        memset(key.data(), 0, padding);
        memcpy(key.data() + padding, id.begin(), sizeof(id));
        return true;
    }
    LogPrintf("arl_dilithiumrecover 3");

    return false;
}
