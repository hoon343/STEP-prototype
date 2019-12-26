#include<cstdio>
#include<iostream>
#include<fstream>
#include<vector>
#include<map>
#include<queue>
#include<chrono>

//ECDSA
#include"eccrypto.h"
#include"sha.h"
#include"osrng.h"
#include"asn.h"
#include"oids.h"
#include"hex.h"
#include"base64.h"
//AES
#include"aes.h"
#include"modes.h"

#include "uv.h"
#include "datacomponents.h"
#include "uvw.hpp"

#include <boost/serialization/string.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>

using namespace std;
using namespace CryptoPP;

map<int, Block*> ledger;
map<int, string> pure_merkles;
map<int, vector<DecryptedProof>> proofs;
map<uvw::TCPHandle*, string> t_buffer;
map<uvw::TCPHandle*, string> c_buffer;

class proofcomponent {
public:
	//constructor
	proofcomponent() {}
	proofcomponent(int n, string peer_ip, string i1, string i2, string t) {
		blocknum = n;
		ip = peer_ip;
		id1 = i1;
		id2 = i2;
		token = t;
	}

	int blocknum;
	string ip;
	string id1;
	string id2;
	string token;
};

class peerinfo {
public:
	//constructor
	peerinfo() {}
	shared_ptr<uvw::TCPHandle> socket;
	string encodedkey;
	ECDSA<ECP, SHA256>::PublicKey* decodedkey;
	ECDSA<ECP, SHA256>::Verifier* vf;
};

bool validate_claim(Block& current){
	printf("Validating %d claims: ", current.GetClaim().size());
	chrono::system_clock::time_point start = chrono::system_clock::now();
	for (int i = 0; i < current.GetClaim().size(); i++) {

		//Get key and iv
		SecByteBlock key(32);
		for (int j = 0; j < 32; j++) key.data()[j] = current.GetClaim()[i].GetKey()[j];
		SecByteBlock iv(16);
		for (int j = 0; j < 16; j++) iv.data()[j] = current.GetClaim()[i].GetIv()[j];

		//Decrypt AES
		auto pbyte = unique_ptr<byte[]>(new byte[current.GetClaim()[i].GetEncrypted().size() + 1]);
		copy(current.GetClaim()[i].GetEncrypted().begin(), current.GetClaim()[i].GetEncrypted().end(), pbyte.get());
		auto decrypted = unique_ptr<byte[]>(new byte[current.GetClaim()[i].GetEncrypted().size() + 1]);
		CFB_Mode<AES>::Decryption aesDecryption(key, key.size(), iv);
		aesDecryption.ProcessData(decrypted.get(), pbyte.get(), current.GetClaim()[i].GetEncrypted().size() + 1);

		//Deserialize Decryption
		vector<DecryptedProof> current_proof;
		boost::iostreams::basic_array_source<char> device((char*)decrypted.get(), current.GetClaim()[i].GetEncrypted().size() + 1);
		boost::iostreams::stream<boost::iostreams::basic_array_source<char> > u(device);
		boost::archive::binary_iarchive ia(u);
		ia >> current_proof;
		if (pure_merkles.find(current.GetClaim()[i].GetBlocknumber()) == pure_merkles.end()) {
			pure_merkles[current.GetClaim()[i].GetBlocknumber()] = ledger[current.GetClaim()[i].GetBlocknumber()]->merkleroot("", "");
		}
		for (int j = 0; j < current_proof.size(); j++) {
			if (!current_proof[j].ValidateDpf(pure_merkles[current.GetClaim()[i].GetBlocknumber()])) {
				chrono::system_clock::time_point end = chrono::system_clock::now();
				chrono::nanoseconds duration = chrono::duration_cast<chrono::nanoseconds>(end - start);
				printf("Block %d: claim validation failed in %lld (%d) nanoseconds\n", current.GetNumber(), duration.count(), duration.count());
				return false;
			}
		}
	}
	chrono::system_clock::time_point end = chrono::system_clock::now();
	chrono::nanoseconds duration = chrono::duration_cast<chrono::nanoseconds>(end - start);
	printf("Block %d: claim validated in %lld (%d) nanoseconds\n", current.GetNumber(), duration.count(), duration.count());
	printf("correct\n");
	return true;
}

int main() {

	auto loop = uvw::Loop::create();
	auto fromhot = loop->resource<uvw::TCPHandle>();
	auto tohot = loop->resource<uvw::TCPHandle>();
	auto fromcold = loop->resource<uvw::TCPHandle>();
	auto init = loop->resource<uvw::IdleHandle>();
	auto workqueue = loop->resource<uvw::IdleHandle>();
	
	queue<proofcomponent> q;
	map<string, peerinfo*> m; //(ip,<socket,key>)
	map<uvw::TCPHandle*, pair<string, int> >connection;
	AutoSeededRandomPool prng;
	ECDSA<ECP, SHA256>::PrivateKey pvk;
	ECDSA<ECP, SHA256>::PublicKey pbk;
	ECDSA<ECP, SHA256>::Signer* signer;
	string publicstring;
	unique_ptr<char[]> pubdata;
	int pbksize;
	string myip, hotip;
	int ismain, n, hotport, tohotport, coldport, min_node;

	init->once<uvw::IdleEvent>([&](const uvw::IdleEvent, uvw::IdleHandle& init){
		pvk.Initialize(prng, ASN1::secp256k1());
		pvk.MakePublicKey(pbk);
		//encode pbk into base64
		Base64Encoder pubKeySink(new StringSink(publicstring));
		pbk.DEREncode(pubKeySink);
		pubKeySink.MessageEnd();

		//string to char[]
		vector<char> pubvec(publicstring.begin(), publicstring.end());
		pubvec.insert(pubvec.begin(), 'K');//K for key
		pbksize = pubvec.size() + 1;
		pubdata = unique_ptr<char[]>(new char[pbksize]);
		copy(pubvec.begin(), pubvec.end(), pubdata.get());
		pubdata[pubvec.size()] = '\0';

		//myip,hotport,coldport,n,ismain,[peers]
		ifstream in("setting.txt");
		in >> myip;
		in >> hotip;
		in >> hotport;
		in >> tohotport;
		in >> coldport;
		in >> min_node;
		in >> ismain;
		in >> n;
		for (int i = 0; i < n; i++) {
			string ip;
			int port;
			in >> ip;
			in >> port;
			auto tmp = loop->resource<uvw::TCPHandle>();

			tmp->on<uvw::ErrorEvent>([&](const uvw::ErrorEvent e, uvw::TCPHandle& t) {
				t.connect(connection[&t].first, connection[&t].second);
			});

			tmp->once<uvw::ConnectEvent>([&](const uvw::ConnectEvent&, uvw::TCPHandle& tmp) {
				auto pubonce = unique_ptr<char[]>(new char[pbksize]);
				copy(&pubdata[0], &pubdata[pbksize], pubonce.get());
				printf("Peer connected: %s, %d\n", tmp.peer().ip.c_str(), tmp.peer().port);
				int writeresult = tmp.tryWrite(move(pubonce), pbksize);
			});

			m[ip] = new peerinfo();
			connection[tmp.get()] = make_pair(ip, port);
			tmp->connect(ip, port);
			m[ip]->socket = tmp;
			//if(writeresult>0) 
			
		}
		//making key
		signer= new ECDSA<ECP, SHA256>::Signer(pvk);

		fromhot->bind(myip, hotport);
		fromcold->bind(myip, coldport);
		fromhot->listen();
		fromcold->listen();
		tohot->on<uvw::ConnectEvent>([](const uvw::ConnectEvent&, uvw::TCPHandle& tcp) {
			printf("Hot node connected\n");
		});
		tohot->on<uvw::ErrorEvent>([&](const uvw::ErrorEvent e, uvw::TCPHandle& tohot) {
			tohot.connect(hotip, tohotport);
		});
		if (ismain == 1) {
			tohot->connect(hotip, tohotport);
		}
		workqueue->start();
		init.stop();
	});

	tohot->once<uvw::EndEvent>([](const uvw::EndEvent&, uvw::TCPHandle& tohot) {
		printf("tohot closed\n");
		string ip = tohot.peer().ip;
		int port = tohot.peer().port;
		tohot.close();
		tohot.connect(ip, port);
	});

	fromhot->on<uvw::ErrorEvent>([](const uvw::ErrorEvent e, uvw::TCPHandle& t) {
		printf("fromhot: %s (%s)\n", e.what(), e.name());
	});

	
	fromhot->on<uvw::ListenEvent>([&] (const uvw::ListenEvent, uvw::TCPHandle & fromhot) {
		shared_ptr<uvw::TCPHandle> client = fromhot.loop().resource<uvw::TCPHandle>();
		client->on<uvw::DataEvent>([&] (const uvw::DataEvent & d, uvw::TCPHandle & t) {
			string tmp_s(d.data.get(), d.length);//except for the final null charcter
			t_buffer[&t] += tmp_s;
			string 	s(t_buffer[&t]);
			unsigned long long int siz = s.size();
			Block* recv_block;
			try {

				recv_block = Block::deserializer(s);
			}
			//if buffer is not enough
			catch (boost::archive::archive_exception e) {
				printf("Extending...\n");
				return;
			}

			//right action
			printf("\nReceived Block %llu, size: %u\n", recv_block->GetNumber(), t_buffer[&t].length());
			t_buffer[&t].clear();

			//validating block
			if (recv_block->validate_transactions() && validate_claim(*recv_block)) {
				ledger[recv_block->GetNumber()] = recv_block;

				//generating pure merkle root
				pure_merkles[recv_block->GetNumber()] = recv_block->merkleroot("","");

				//send to every cold to collect proofs
				for (map<string, peerinfo*>::iterator iter = m.begin(); iter != m.end();iter++) {
					//generating merkle root with peerid
					string mroot;
					printf("Peer merkle root with %s on block %d\n", iter->second->socket->peer().ip.c_str(), recv_block->GetNumber());
					mroot = recv_block->merkleroot(publicstring, iter->second->encodedkey);
					
					//string to char[]: M+(cipher(hex))+(blocknumstr(hex))+(mroot)
					char blocknumstr[10];
					int cipher;
					cipher = sprintf(blocknumstr, "%x", recv_block->GetNumber());
					vector<char> mervec;
					mervec.push_back('M');//M for merkle
					mervec.push_back(cipher+'0');
					for (int i = 0; i < cipher; i++) mervec.push_back(blocknumstr[i]);
					//mervec.insert(mervec.begin() + 1, blocknumstr, &blocknumstr[cipher]);
					mervec.insert(mervec.end(), mroot.begin(), mroot.end());
					int mersize = mervec.size() + 1;
					auto merdata = unique_ptr<char[]>(new char[mersize]);
					copy(mervec.begin(), mervec.end(), merdata.get());
					merdata[mervec.size()] = '\0';
					iter->second->socket->write(move(merdata), mersize);
				}
			}

		});
		fromhot.accept(*client);
		client->read();
	});

	fromcold->on<uvw::ErrorEvent>([](const uvw::ErrorEvent e, uvw::TCPHandle& t) {
		printf("fromcold: %s (%s)\n", e.what(), e.name());
	});

	fromcold->on<uvw::ListenEvent>([&](const uvw::ListenEvent, uvw::TCPHandle& fromcold) {
		shared_ptr<uvw::TCPHandle> client = fromcold.loop().resource<uvw::TCPHandle>();
		client->on<uvw::DataEvent>([&](const uvw::DataEvent& d, uvw::TCPHandle& client) {
			//received key: cold node registration
			string tmp_s(d.data.get(), d.length);
			c_buffer[&client] += tmp_s;
			if (c_buffer[&client].size() < 2) return;
			if (c_buffer[&client][0] == 'K') {//K for key
				if (c_buffer[&client].size() < 124) {
					printf("Extending key...\n");
					return;
				}
				string s(c_buffer[&client], 1, c_buffer[&client].size() - 2);//except for the final null character
				c_buffer[&client].clear();
				printf("Received key: %s\nsize: %d\n", s.c_str(), s.size() + 1);
				//TODO:get listen port
				if (m.find(client.peer().ip) == m.end()) {//if ip is not registered
					m[client.peer().ip] = new peerinfo();
					auto tmp = loop->resource<uvw::TCPHandle>();
					tmp->connect(client.peer().ip, client.peer().port);
					m[client.peer().ip]->socket = tmp;
					tmp->write(move(pubdata), pbksize);
				}
				m[client.peer().ip]->encodedkey = s;

				auto pub = new ECDSA<ECP, SHA256>::PublicKey();
				StringSource stringSource(m[client.peer().ip]->encodedkey, true, new Base64Decoder);
				pub->BERDecode(stringSource);
				m[client.peer().ip]->decodedkey = pub;
				auto veri = new ECDSA<ECP, SHA256>::Verifier(*pub);
				m[client.peer().ip]->vf = veri;

			}
			//received merkle root: merkle root validation
			else if (c_buffer[&client][0] == 'M') {//M for merkle
				int cipher = (char)c_buffer[&client][1] - '0';
				if (c_buffer[&client].size() - cipher < 67) {
					printf("Extending merkle...\n");
					return;
				}
				string s(c_buffer[&client]);
				c_buffer[&client].clear();
				printf("Received merkle root. Size: %d\n", s.size());
				char blocknumstr[10];
				int blocknum;
				string recv_m;
				string mroot;

				for (int i = 0; i < cipher; i++) blocknumstr[i] = s[2 + i];
				blocknum = strtol(blocknumstr, NULL, 16);
				recv_m.assign(s, 2 + cipher, s.size() - 2 - cipher - 1);

				//put them into queue
				proofcomponent tmp_proof(blocknum, client.peer().ip, m[client.peer().ip]->encodedkey, publicstring, recv_m);
				q.push(tmp_proof);
				
			}
			//received sign: collecting proof
			else if (c_buffer[&client][0] == 'S') {//S for Sign
				int cipher = (char)c_buffer[&client][1] - '0';
				if (c_buffer[&client].size() - cipher < 93) {
					printf("Extending sign...\n");
					return;
				}
				string s(c_buffer[&client]);
				c_buffer[&client].clear();
				printf("Received sign. Size: %d\n", s.size());
				char blocknumstr[10];
				int blocknum;
				string recv_s;

				for (int i = 0; i < cipher; i++) blocknumstr[i] = s[2 + i];
				blocknum = strtol(blocknumstr, NULL, 16);
				recv_s.assign(s, 2 + cipher, string::npos);

				chrono::system_clock::time_point signdecode_start = chrono::system_clock::now();
				//decode ECDSA
				string decoded;

				StringSource decoder(recv_s, true,
					new Base64Decoder(
						new StringSink(decoded)
					) // Base64Decoder
				); // StringSource

				if (pure_merkles.find(blocknum) == pure_merkles.end()) {
					pure_merkles[blocknum] = ledger[blocknum]->merkleroot("", "");
				}

				string message = pure_merkles[blocknum] + publicstring;
				//printf("decoded: %s\npublicstring: %s\n", decoded.c_str(),publicstring.c_str());

				//verify
				bool result = false;
				StringSource vfer(decoded + message, true /*pump all*/,
					new SignatureVerificationFilter(
						*(m[client.peer().ip]->vf),
						new ArraySink((byte*)& result, sizeof(result))
					) // SignatureVerificationFilter
				);

				chrono::system_clock::time_point signdecode_end = chrono::system_clock::now();
				chrono::nanoseconds signdecodeduration = chrono::duration_cast<chrono::nanoseconds>(signdecode_end - signdecode_start);
				printf("Signature decoding from %s on block %d is done in %lld (%d) nanoseconds. ", client.peer().ip.c_str(), blocknum, signdecodeduration.count(), signdecodeduration.count());

				if (result) {
					DecryptedProof pf(recv_s, m[client.peer().ip]->encodedkey, publicstring);
					proofs[blocknum].push_back(pf);
					printf("Proof on block %d added\n", blocknum);
				}
				else return;



				//Done: Add proof and send it to cold/hot nodes
				if (proofs[blocknum].size() >= min_node) {

					//serialization
					std::string serial_str;
					boost::iostreams::back_insert_device<std::string> inserter(serial_str);
					boost::iostreams::stream< boost::iostreams::back_insert_device<std::string> > s(inserter);
					boost::archive::binary_oarchive oa(s);
					oa << proofs[blocknum];
					s.flush();

					//Generate a random key
					SecByteBlock key(0x00, AES::MAX_KEYLENGTH);
					prng.GenerateBlock(key, key.size());

					//Generate a random IV
					SecByteBlock iv(AES::BLOCKSIZE);
					prng.GenerateBlock(iv, iv.size());

					vector<byte> writable(serial_str.begin(), serial_str.end());
					auto dataWrite = unique_ptr<byte[]>(new byte[writable.size() + 1]);
					copy(writable.begin(), writable.end(), dataWrite.get());
					dataWrite[writable.size()] = '\0';
					size_t messageLen = writable.size() + 1;
					auto encrypted = unique_ptr<byte[]>(new byte[writable.size() + 1]);

					//Encrypt
					CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
					cfbEncryption.ProcessData(encrypted.get(), dataWrite.get(), messageLen);
					

					//send to every cold nodes
					char blocknumstr[10];
					int cipher;
					cipher = sprintf(blocknumstr, "%x", blocknum);

					//string to char[]: P+(cipher(hex))+(blocknumstr(hex))+(encoded)
					vector<char> prfvec;
					prfvec.push_back('P');//P for proof
					prfvec.push_back(cipher + '0');
					for (int i = 0; i < cipher; i++) prfvec.push_back(blocknumstr[i]);
					for (int i = 0; i < messageLen; i++) prfvec.push_back(encrypted[i]);
					//prfvec.insert(prfvec.end(), encrypted.get(), &encrypted.get()[messageLen-1]);
					int prfsize = prfvec.size() + 1;

					//main cold node have to send her key and iv to hot node
					//string to char[]: p+(bytes(hex))+(blocksizestr(hex))+(cipher(hex))+(blocknumstr(hex))+(AESkey(32byte))+(AESiv(16byte))+(encoded)
					if (ismain == 1) {
						vector<char> pkvec;
						char blocksizestr[10];
						int bytes = sprintf(blocksizestr, "%x", 3 + cipher + 32 + 16 + messageLen + 1);
						bytes = sprintf(blocksizestr, "%x", 3 + bytes + cipher + 32 + 16 + messageLen + 1);
						bytes = sprintf(blocksizestr, "%x", 3 + bytes + cipher + 32 + 16 + messageLen + 1);
						pkvec.push_back('p');//P for proof
						pkvec.push_back(bytes+'0');
						for (int i = 0; i < bytes; i++) pkvec.push_back(blocksizestr[i]);
						pkvec.push_back(cipher + '0');
						for (int i = 0; i < cipher; i++) pkvec.push_back(blocknumstr[i]);
						for (int i = 0; i < 32; i++) pkvec.push_back(key.BytePtr()[i]);
						for (int i = 0; i < 16; i++) pkvec.push_back(iv.BytePtr()[i]);
						for (int i = 0; i < messageLen; i++) pkvec.push_back(encrypted[i]);
						//prfvec.insert(prfvec.end(), encrypted.get(), &encrypted.get()[messageLen-1]);
						int pksize = pkvec.size() + 1;
						auto pkdata = unique_ptr<char[]>(new char[pksize]);
						copy(pkvec.begin(), pkvec.end(), pkdata.get());
						pkdata[pkvec.size()] = '\0';
						tohot->write(move(pkdata),pksize);
						printf("Proof and key are sent to hot node. Size: %d\n", pksize);
					}
				}
			}
		});
		fromcold.accept(*client);
		client->read();
	});

	workqueue->on<uvw::IdleEvent>([&](const uvw::IdleEvent, uvw::IdleHandle& workqueue) {

		if (q.empty()) return;

		proofcomponent current_proof = q.front();
		q.pop();

		//if the block is not received, push the proof back
		if (ledger.find(current_proof.blocknum) == ledger.end()) {
			q.push(current_proof);
			return;
		}

		chrono::system_clock::time_point peerStartTime = std::chrono::system_clock::now();
		string mroot = ledger[current_proof.blocknum]->merkleroot(current_proof.id1, current_proof.id2);
		//if the token is validated
		if (mroot == current_proof.token) {
			chrono::system_clock::time_point peerEndTime = std::chrono::system_clock::now();
			chrono::nanoseconds micro = std::chrono::duration_cast<std::chrono::nanoseconds>(peerEndTime - peerStartTime);
			printf("Peer %s's proof on block%d validated in %lld (%d) nanoseconds.\n", current_proof.ip.c_str(), current_proof.blocknum, micro.count(), micro.count());
			if (pure_merkles.find(current_proof.blocknum) == pure_merkles.end()) {
				pure_merkles[current_proof.blocknum] = ledger[current_proof.blocknum]->merkleroot("", "");
			}
			//make Sign(Y, M_n(0,0)+ID_X)
			string message = pure_merkles[current_proof.blocknum] + m[current_proof.ip]->encodedkey;
			size_t siglen = signer->MaxSignatureLength();
			string signature(siglen, 0x00);
			siglen = signer->SignMessage(prng, (const byte*)&message[0], message.size(), (byte*)&signature[0]);
			signature.resize(siglen);

			//encode in base64
			string encoded;
			StringSource b64(signature, true,
				new Base64Encoder(
					new StringSink(encoded)
				) // Base64Encoder
			); // StringSource

			//send the signature to current_proof.ip
			//string to char[]: S+(cipher(hex))+(blocknumstr(hex))+(encoded)
			vector<char> signvec;
			char blocknumstr[10];
			int cipher;
			cipher = sprintf(blocknumstr, "%x", current_proof.blocknum);
			signvec.push_back('S');//S for sign
			signvec.push_back(cipher + '0');
			for (int i = 0; i < cipher; i++) signvec.push_back(blocknumstr[i]);
			signvec.insert(signvec.end(), encoded.begin(), encoded.end());
			int signsize = signvec.size() + 1;
			auto merdata = unique_ptr<char[]>(new char[signsize]);
			copy(signvec.begin(), signvec.end(), merdata.get());
			merdata[signvec.size()] = '\0';

			m[current_proof.ip]->socket->write(move(merdata),signsize);
			printf("Sign sent\n");

		}

	});
	init->start();
	loop->run();

	return 0;
}