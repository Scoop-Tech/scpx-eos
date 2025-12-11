#include <eosio/system.hpp>
#include <eosio/eosio.hpp>
#include <eosio/time.hpp>
#include <eosio/multi_index.hpp>
#include <eosio/crypto.hpp>
#include <eosio/print.hpp>

using namespace eosio;

class [[eosio::contract]] scpx : public contract
{
public:
    using contract::contract;

    scpx(name self, name code, datastream<const char *> ds) : contract(self, code, ds), table(self, self.value) {}

    [[eosio::action]] void newuser(const name scp_account, const std::string e_email, const uint128_t e_hash_hex128) 
    {
        require_auth(_self);
        print("newuser - scp_account = ", eosio::name{scp_account}, "\n");
        print("newuser - e_email = ", e_email, "\n");
        print("newuser - e_hash_hex128 = ", e_hash_hex128, "\n");
        auto idx = table.get_index<name("idx2")>();
        auto secondary_key_itr = idx.find(e_hash_hex128);
        if (secondary_key_itr == idx.end()) {
            table.emplace(_self, [&](auto &current_imp) {
                current_imp.owner = scp_account;
                current_imp.e_email = e_email;
                current_imp.h_email_ui128 = e_hash_hex128;
                current_imp.created_at = eosio::time_point_sec(current_time_point().sec_since_epoch());
            });
        }
        else {
            check(true == false, "Email already in use.");
        }
    }

    [[eosio::action]] void deleteuser(const name scp_account)
    {
        require_auth(_self);
        print("deleteuser - account = ", eosio::name{scp_account}, "\n");
        auto itr = table.find(scp_account.value);
        check(itr != table.end(), "Row not found (2).");
        table.erase(itr);
    }

    [[eosio::action]] void setassets(const name scp_account, std::string assets_json)
    {
        require_auth(_self);
        print("setassets - account = ", eosio::name{scp_account}, "\n");
        table.modify(table.get(scp_account.value), _self, [&](auto &setvalue) {
            setvalue.assets_json = assets_json;
        });
    }

    [[eosio::action]] void setdata(const name scp_account, std::string data_json)
    {
        require_auth(_self);
        print("setdata - account = ", eosio::name{scp_account}, "\n");
        table.modify(table.get(scp_account.value), _self, [&](auto &setvalue) {
            setvalue.data_json = data_json;
        });
    }

    struct [[eosio::table]] users_table {
        name owner;
        std::string e_email;
        //checksum256 email_hash;
        uint128_t h_email_ui128;

        time_point_sec created_at;
        std::string assets_json;
        std::string data_json;
        std::string ex1;
        std::string ex2;

        uint64_t primary_key() const { return owner.value; }

        // just *cannot* get getTableRows lookups by sha256 index to work; using uint128_t e_hash_hex128 instead
        /*key256 by_email_hash() const { return get_email_hash(email_hash); } 
        static key256 get_email_hash(const checksum256& email_hash) {
            const uint128_t *p128 = reinterpret_cast<const uint128_t *>(&email_hash);            
            key256 k;
            k.data()[0] = p128[0];
            k.data()[1] = p128[1];
            return k;
            //const uint64_t *p64 = reinterpret_cast<const uint64_t *>(&email_hash);
            //return key256::make_from_word_sequence<uint64_t>(p64[0], p64[1], p64[2], p64[3]);
        }*/

        uint128_t by_h_email_ui128() const { return h_email_ui128; }
    };

    typedef eosio::multi_index<"scpusers"_n, users_table,
      //eosio::indexed_by<"idx_email_hash"_n, eosio::const_mem_fun<users_table, key256,    &users_table::by_email_hash> > ,  // lookusps with getTableRows not working
        eosio::indexed_by<"idx2"_n, eosio::const_mem_fun<users_table, uint128_t, &users_table::by_h_email_ui128> > 
        >
        users_index;

    users_index table;
};
EOSIO_DISPATCH(scpx, (newuser)(setassets)(setdata)(deleteuser))
