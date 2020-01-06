// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#pragma once

#include "Address.h"
#include "Data.h"
#include "../PublicKey.h"

#include <string>

namespace TW::CardanoShelley {

/// A Cardano-Shelley address, V3 or V2.
class Address {
  public:
    enum Discrimination: uint8_t {
        Discrim_Production = 0,
        Discrim_Test = 1,
    };

    enum Kind: uint8_t {
        Kind_Sentinel_Low = 2,
        Kind_Single = 3,
        Kind_Group = 4,
        Kind_Account = 5,
        Kind_Multisig = 6,
        Kind_Sentinel_High = 7,
    };

    Discrimination discrimination;

    Kind kind;

    /// key1: spending key or account key
    Data key1;

    /// group key (in case of Group address, empty otherwise)
    Data groupKey;

    /// Used in case of legacy address (V2)
    TW::Cardano::Address* legacyAddress;

    /// Determines whether a string makes a valid address.
    static bool isValid(const std::string& addr);

    /// Initializes a Cardano address with a string representation.  Throws if invalid.
    explicit Address(const std::string& addr);

    /// Initializes a V2, public key type Cardano address from an extended public key.
    explicit Address(const PublicKey& publicKey);

    ~Address() {
        if (legacyAddress != nullptr) {
            delete legacyAddress;
        }
    }

    /// Returns a string representation of the address.
    std::string string() const;

    /// compute hash of public key, for address root
    static TW::Data keyHash(const TW::Data& xpub);

    /// Check validity and parse elements of a string address.  Throws on error. Used internally by isValid and ctor.
    static bool parseAndCheckV3(const std::string& addr, Discrimination& discrimination, Kind& kind, TW::Data& key1, TW::Data& key2);
};

inline bool operator==(const Address& lhs, const Address& rhs) {
    return lhs.discrimination == rhs.discrimination && lhs.kind == rhs.kind && lhs.key1 == rhs.key1 && lhs.groupKey == rhs.groupKey;
}

} // namespace TW::CardanoShelley

/// Wrapper for C interface.
struct TWCardanoShelleyAddress {
    TW::CardanoShelley::Address impl;
};
