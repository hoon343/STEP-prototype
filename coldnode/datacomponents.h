#pragma once
#include<string>
#include<vector>
#include<map>
#include"aes.h"
//ECDSA
#include"eccrypto.h"
#include"sha.h"
#include"osrng.h"
//#include"asn.h"
#include"oids.h"
#include"hex.h"
#include"base64.h"
//boost
#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
using namespace std;
class Account {
public:
	//constructor
	Account();
	Account(string account_id);
	Account(string account_id, unsigned long long int account_valance);

	//gets
	string GetId();
	unsigned long long int GetValance();

	//sets
	void SetValance(unsigned long long int amount);
private:
	string id;
	unsigned long long int valance;
};
class Transaction {
public:
	//constructor
	Transaction();
	Transaction(string tr_from, string tr_to);
	Transaction(string tr_from, string tr_to, unsigned long long int tr_amount);
	//Transaction(string serial_str);

	//function
	string serializer();
	static Transaction* deserializer(string serial_str);
	static vector<Transaction> vec_deserializer(string serial_str);

	//gets
	string GetFrom();
	string GetTo();
	unsigned long long int GetAmount();

	//sets
	//void SetId1(string id);
	//void SetId2(string id);

private:
	string from;
	string to;
	unsigned long long int amount;
	//string id1;
	//string id2;

	//for serialization
	friend class boost::serialization::access;
	template<class Archive> void serialize(Archive& ar, const unsigned int version) {
		ar& from;
		ar& to;
		ar& amount;
		//ar& id1;
		//ar& id2;
	}

};
class ValidationProof {
public:
	//constructor
	ValidationProof();
	ValidationProof(unsigned long long int vp_block_number, unsigned long long int vp_transaction_number, CryptoPP::SecByteBlock vp_key, CryptoPP::SecByteBlock vp_iv);

	//gets
	unsigned long long int GetBlock_number();
	unsigned long long int GetTransaction_number();
	CryptoPP::SecByteBlock GetKey();
	CryptoPP::SecByteBlock GetIv();

private:
	unsigned long long int block_number;
	unsigned long long int transaction_number;
	CryptoPP::SecByteBlock key;
	CryptoPP::SecByteBlock iv;
};
class DecryptedProof {
public:
	//constructor
	DecryptedProof();
	DecryptedProof(string d_decrypted, string d_encodedkey, string d_validatee);

	//gets
	string GetValidatee();

	//function
	bool ValidateDpf(string message);

private:
	string decrypted;
	string encodedkey;
	string validatee;

	//for serialization
	friend class boost::serialization::access;
	template<class Archive> void serialize(Archive& ar, const unsigned int version) {
		ar& decrypted;
		ar& encodedkey;
		ar& validatee;
	}
};
class EncryptedProof {
public:
	//constructor
	EncryptedProof();
	EncryptedProof(unsigned long long int e_blocknum, vector<unsigned char> e_encrypted, CryptoPP::SecByteBlock& e_key, CryptoPP::SecByteBlock& e_iv);

	//gets
	unsigned long long int GetBlocknumber();
	vector<unsigned char>& GetEncrypted();
	vector<unsigned char>& GetKey();
	vector<unsigned char>& GetIv();

private:
	unsigned long long int blocknumber;
	vector<unsigned char> encrypted;
	vector<unsigned char> key;
	vector<unsigned char> iv;

	//for serialization
	friend class boost::serialization::access;
	template<class Archive> void serialize(Archive& ar, const unsigned int version) {
		ar& blocknumber;
		ar& encrypted;
		ar& key;
		ar& iv;
	}
};
class Block {
public:
	//constructor
	Block();
	Block(unsigned long long int block_number, string block_prev_hash, string block_random_value);

	//methods
	void push_transaction(Transaction* block_transaction);
	void push_transactions(vector<Transaction> block_transactions);
	//void set_transactions(vector<Transaction>* transaction_vector);
	void push_claim(EncryptedProof& block_proof);
	bool validate_transactions();
	static bool validate_transaction(Transaction tx);
	//bool validate_claim();
	string serializer();
	static Block* deserializer(string serial_str);
	string merkleroot(string id1, string id2);

	//gets
	unsigned long long int GetNumber();
	string GetPrev_hash();
	string GetRandom_value();
	vector<EncryptedProof>& GetClaim();
	vector<Transaction>& GetTransactions();

private:
	unsigned long long int number;
	string prev_hash;
	string producer;
	string random_value;
	vector<EncryptedProof> claim;
	vector<Transaction> transactions;

	//for serialize
	friend class boost::serialization::access;
	template<class Archive> void serialize(Archive& ar, const unsigned int version) {
		//ar& boost::serialization::base_object<something>(*this);
		//boost::serialization::void_cast_register(static_cast<something*>(NULL),static_cast<something *>(NULL));
		ar& number;
		ar& prev_hash;
		ar& random_value;
		ar& claim;
		ar& transactions;
	}
};
extern map <string, Account*> accounts;