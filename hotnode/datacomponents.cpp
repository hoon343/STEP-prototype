#include<string>
#include<chrono>
#include"datacomponents.h"
#include"aes.h"
#include"modes.h"
using namespace std;
using namespace CryptoPP;

map <string, Account*> accounts;
//Account{
	//constructor
	Account::Account() {}
	Account::Account(string account_id) {
		if (accounts.find(account_id) == accounts.end()) {
			accounts[account_id] = this;
			id = account_id;
			valance = 0;
		}
	}
	Account::Account(string account_id, unsigned long long int account_valance) {
		if (accounts.find(account_id) == accounts.end()) {
			accounts[account_id] = this;
			id = account_id;
			valance = account_valance;
		}
	}

	//gets
	string Account::GetId() { return id; }
	unsigned long long int Account::GetValance() { return valance; }

	//sets
	void Account::SetValance(unsigned long long int amount) { valance = amount; }

//}
//Transaction{

	//constructor
	Transaction::Transaction() {}
	Transaction::Transaction(string tr_from, string tr_to) {
		from = tr_from;
		to = tr_to;
		amount = 0;
	}
	Transaction::Transaction(string tr_from, string tr_to, unsigned long long int tr_amount) {
		from = tr_from;
		to = tr_to;
		amount = tr_amount;
	}
	 /*Transaction::Transaction(std::string serial_str) {//deserializer

		Transaction* l;
		boost::iostreams::basic_array_source<char> device(serial_str.c_str(), serial_str.size());
		boost::iostreams::stream<boost::iostreams::basic_array_source<char> > u(device);
		boost::archive::binary_iarchive ia(u);
		ia >> l;
		to = l->GetTo();
		from = l->GetFrom();
		amount = l->GetAmount();
		delete l;

	}*/


	//function
	string Transaction::serializer() {//serializer
		std::string serial_str;
		boost::iostreams::back_insert_device<std::string> inserter(serial_str);
		boost::iostreams::stream< boost::iostreams::back_insert_device<std::string> > s(inserter);
		boost::archive::binary_oarchive oa(s);
		oa << this;
		s.flush();
		return serial_str;
	}
	Transaction* Transaction::deserializer(std::string serial_str) {//deserializer

		Transaction* l;
		boost::iostreams::basic_array_source<char> device(serial_str.c_str(), serial_str.size());
		boost::iostreams::stream<boost::iostreams::basic_array_source<char> > u(device);
		boost::archive::binary_iarchive ia(u);
		ia >> l;
		return l;
		
	}
	vector<Transaction> Transaction::vec_deserializer(string serial_str) {
		
		vector<Transaction> l;
		boost::iostreams::basic_array_source<char> device(serial_str.c_str(), serial_str.size());
		boost::iostreams::stream<boost::iostreams::basic_array_source<char> > u(device);
		boost::archive::binary_iarchive ia(u);
		ia >> l;
		return l;
	}

	//gets
	string Transaction::GetFrom() { return from; }
	string Transaction::GetTo() { return to; }
	unsigned long long int Transaction::GetAmount() { return amount; }

	//sets
	//void Transaction::SetId1(string id) { id1 = id; }
	//void Transaction::SetId2(string id) { id2 = id; }

//}

//ValidationProof{
	ValidationProof::ValidationProof() {}
	ValidationProof::ValidationProof(unsigned long long int vp_block_number, unsigned long long int vp_transaction_number, CryptoPP::SecByteBlock vp_key, CryptoPP::SecByteBlock vp_iv) {
		block_number = vp_block_number;
		transaction_number = vp_transaction_number;
		key = vp_key;
		iv = vp_iv;
	}
	unsigned long long int ValidationProof::GetBlock_number() { return block_number; }
	unsigned long long int ValidationProof::GetTransaction_number() { return transaction_number; }
	CryptoPP::SecByteBlock ValidationProof::GetKey() {return key; }
	CryptoPP::SecByteBlock ValidationProof::GetIv() {return iv; }
//}

//DecryptedProof{
	DecryptedProof::DecryptedProof() {}
	DecryptedProof::DecryptedProof(string d_decrypted, string d_encodedkey, string d_validatee) {
		decrypted = d_decrypted;
		encodedkey = d_encodedkey;
		validatee = d_validatee;
	}
	string DecryptedProof::GetValidatee() { return validatee; }
	bool DecryptedProof::ValidateDpf(string message) {
		auto pub = new ECDSA<ECP, SHA256>::PublicKey();
		CryptoPP::StringSource stringSource(encodedkey, true, new Base64Decoder);
		pub->BERDecode(stringSource);
		auto veri = new ECDSA<ECP, SHA256>::Verifier(*pub);
		string decoded;

		StringSource decoder(decrypted, true,
			new Base64Decoder(
				new StringSink(decoded)
			) // Base64Decoder
		); // StringSource

		//printf("decoded: %s\npublicstring: %s\n", decoded.c_str(), validatee.c_str());

		bool result = false;
		StringSource vfer(decoded + message + validatee, true /*pump all*/, 
			new SignatureVerificationFilter(
				*veri,
				new ArraySink((byte*)& result, sizeof(result))
			) // SignatureVerificationFilter
		);

		delete pub;
		delete veri;

		return result;
	}

//}

//EncryptedProof{
	EncryptedProof::EncryptedProof() {}
	EncryptedProof::EncryptedProof(unsigned long long int e_blocknumber, vector<unsigned char> e_encrypted, CryptoPP::SecByteBlock& e_key, CryptoPP::SecByteBlock& e_iv) {
		blocknumber = e_blocknumber;
		encrypted = e_encrypted;
		for (int i = 0; i < 32; i++) key.push_back(e_key.BytePtr()[i]);
		for (int i = 0; i < 16; i++) iv.push_back(e_iv.BytePtr()[i]);
	}
	unsigned long long int EncryptedProof::GetBlocknumber(){ return blocknumber; }
	vector<unsigned char>& EncryptedProof::GetEncrypted(){ return encrypted; }
	vector<unsigned char>& EncryptedProof::GetKey(){ return key; }
	vector<unsigned char>& EncryptedProof::GetIv(){ return iv; }
//}

//Block{
	//constructor
	Block::Block() {}
	Block::Block(unsigned long long int block_number, string block_prev_hash, string block_random_value) {
		number = block_number;
		prev_hash = block_prev_hash;
		random_value = block_random_value;
	}

	//methods
	void Block::push_transaction(Transaction* block_transaction) {
		transactions.push_back(*block_transaction);
	}
	void Block::push_transactions(vector<Transaction> block_transactions) {
		for (auto it : block_transactions) transactions.push_back(it);
	}
	/*void Block::set_transactions(vector<Transaction>* transaction_vector) {
		transactions = transaction_vector;
	}*/
	void Block::push_claim(EncryptedProof& block_proof) {
		claim.push_back(block_proof);
	}

	bool Block::validate_transactions() {
		chrono::system_clock::time_point start = chrono::system_clock::now();
		map<string, unsigned long long int> tmp_account;
		for (auto tx : transactions) {
			//if tx is invalid
			if (tx.GetFrom() == "init") {
				new Account(tx.GetTo(), tx.GetAmount());
				//accounts[tx.GetTo()]->SetValance(accounts[tx.GetTo()]->GetValance() + tx.GetAmount());
			}
			else if (accounts[tx.GetFrom()]->GetValance() < tx.GetAmount()) {
				chrono::system_clock::time_point end = chrono::system_clock::now();
				chrono::nanoseconds duration = chrono::duration_cast<chrono::nanoseconds>(end - start);
				printf("Block %d: transaction validation failed in %lld (%d) nanoseconds\n", number, duration.count(), duration.count());
				return false;
			}
			//else if overflow does not occur
			else if (accounts[tx.GetFrom()]->GetValance() - tx.GetAmount() < accounts[tx.GetFrom()]->GetValance()
				&& accounts[tx.GetTo()]->GetValance() + tx.GetAmount() > accounts[tx.GetTo()]->GetValance()) {
				accounts[tx.GetFrom()]->SetValance(accounts[tx.GetFrom()]->GetValance() - tx.GetAmount());
				accounts[tx.GetTo()]->SetValance(accounts[tx.GetTo()]->GetValance() + tx.GetAmount());
			}
		}
		chrono::system_clock::time_point end = chrono::system_clock::now();
		chrono::nanoseconds duration = chrono::duration_cast<chrono::nanoseconds>(end - start);
		printf("Block %d: transaction validated in %lld (%d) nanoseconds\n", number, duration.count(), duration.count());
		return true;
	}

	bool Block::validate_transaction(Transaction tx) {
		//if tx is invalid
		if (tx.GetFrom() == "init") {
			new Account(tx.GetTo(), tx.GetAmount());
			//accounts[tx.GetTo()]->SetValance(accounts[tx.GetTo()]->GetValance() + tx.GetAmount());
			return true;
		}
		else if (accounts[tx.GetFrom()]->GetValance() < tx.GetAmount()) {
			return false;
		}
		//else if overflow does not occur
		else if (accounts[tx.GetFrom()]->GetValance() - tx.GetAmount() < accounts[tx.GetFrom()]->GetValance()
			&& accounts[tx.GetTo()]->GetValance() + tx.GetAmount() > accounts[tx.GetTo()]->GetValance()) {
			accounts[tx.GetFrom()]->SetValance(accounts[tx.GetFrom()]->GetValance() - tx.GetAmount());
			accounts[tx.GetTo()]->SetValance(accounts[tx.GetTo()]->GetValance() + tx.GetAmount());
			return true;
		}
		return false;
	}

/*	bool Block::validate_claim() {
		for (int i = 0; i < claim.size(); i++) {

			//Get key and iv
			SecByteBlock key(32);
			for (int j = 0; j < 32; j++) key.data()[j] = claim[i].GetKey()[j];
			SecByteBlock iv(16);
			for (int j = 0; j < 16; j++) iv.data()[j] = claim[i].GetIv()[j];

			//Decrypt AES
			auto pbyte = unique_ptr<byte[]>(new byte[claim[i].GetEncrypted().size() + 1]);
			copy(claim[i].GetEncrypted().begin(), claim[i].GetEncrypted().end(), pbyte.get());
			auto decrypted = unique_ptr<byte[]>(new byte[claim[i].GetEncrypted().size() + 1]);
			CFB_Mode<AES>::Decryption aesDecryption(key, key.size(), iv);
			aesDecryption.ProcessData(decrypted.get(), pbyte.get(), claim[i].GetEncrypted().size() + 1);

			//Deserialize Decryption
			vector<DecryptedProof> current_proof;
			boost::iostreams::basic_array_source<char> device((char*)decrypted.get(), claim[i].GetEncrypted().size() + 1);
			boost::iostreams::stream<boost::iostreams::basic_array_source<char> > u(device);
			boost::archive::binary_iarchive ia(u);
			ia >> current_proof;
			for (int j = 0; j < current_proof.size(); j++) {
				if (!current_proof[j].ValidateDpf(this->merkleroot("", ""))) {
					printf("Proof incorrect\n");
					return false;
				}
			}
		}
		printf("Proof correct\n");
		return true;
	}*/

	string Block::serializer() {
		std::string serial_str;
		boost::iostreams::back_insert_device<std::string> inserter(serial_str);
		boost::iostreams::stream< boost::iostreams::back_insert_device<std::string> > s(inserter);
		boost::archive::binary_oarchive oa(s);
		oa << this;
		s.flush();
		return serial_str;
	}

	Block* Block::deserializer(string serial_str) {//deserializer

		Block* l;
		boost::iostreams::basic_array_source<char> device(serial_str.c_str(), serial_str.size());
		boost::iostreams::stream<boost::iostreams::basic_array_source<char> > u(device);
		boost::archive::binary_iarchive ia(u);
		ia >> l;
		return l;

	}

	string Block::merkleroot(string id1, string id2) {
		chrono::system_clock::time_point start = chrono::system_clock::now();
		vector<string>merkles;
		//merkles.resize(transactions.size());
		for (auto tx : transactions) {
			//Transaction tmp = tx;
			//tmp.SetId1(id1);
			//tmp.SetId2(id2);
			string message = tx.serializer() + id1 + id2;
			CryptoPP::SHA256 hash;
			string digest;
			CryptoPP::StringSource s(message, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
			merkles.push_back(digest);
		}
		while (merkles.size() > 1) {
			for (int i = 0; i < merkles.size() / 2; i++) {
				string beforehash = merkles[2 * i] + merkles[2 * i + 1];
				CryptoPP::SHA256 hash;
				string digest;
				CryptoPP::StringSource s(beforehash, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
				merkles[i] = digest;
			}
			if (merkles.size() % 2 == 1) {
				string beforehash = merkles[merkles.size()/2] + merkles[merkles.size() / 2];
				CryptoPP::SHA256 hash;
				string digest;
				CryptoPP::StringSource s(beforehash, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
				merkles[merkles.size() / 2] = digest;
			}
			merkles.resize((merkles.size()+1) / 2);
		}
		chrono::system_clock::time_point end = chrono::system_clock::now();
		chrono::nanoseconds duration = chrono::duration_cast<chrono::nanoseconds>(end - start);
		if (id1 == "" && id2 == "") printf("Block %d: pure merkle ", number);
		else printf("Block %d: merkle ", number);
		printf("generated in %lld (%d) nanoseconds.\n", duration.count(), duration.count());
		return merkles[0];
	}

	//gets
	unsigned long long int Block::GetNumber() { return number; }
	string Block::GetPrev_hash() { return prev_hash; }
	string Block::GetRandom_value() { return random_value; }
	vector<EncryptedProof>& Block::GetClaim() { return claim; }
	vector<Transaction>& Block::GetTransactions() { return transactions; }

//}