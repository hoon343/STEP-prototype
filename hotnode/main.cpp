#include<cstdio>
#include<ctime>
#include<mutex>
#include<iostream>
#include<fstream>
#include<string>
#include<vector>
#include<map>
#include"datacomponents.h"
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
//uvw
#include"uv.h"
#include<stdlib.h>
#include"uvw.hpp"

using namespace std;
using namespace CryptoPP;

Block* current;
int st_time=0;
map<int, EncryptedProof > claims;
vector<Block*> ledger;
vector<Transaction>* tmp_transaction;
int proof_limit = 50;
int cnt = 0;
shared_ptr<uvw::TCPHandle> global_tcp;
mutex mtx;
string myip;
int rtgport, n_cold;
map<uvw::TCPHandle*, string> c_buffer;

class coldinfo {
public:
	coldinfo() {}

	shared_ptr<uvw::TCPHandle> socket;
	string encodedkey;
};

map<string, coldinfo*> coldlist;
map<uvw::TCPHandle*, pair<string, int> > connection;

int main() {

	auto loop = uvw::Loop::create();
	auto server = loop->resource<uvw::TCPHandle>();
	auto tocold = loop->resource<uvw::TCPHandle>();
	auto idle = loop->resource<uvw::TimerHandle>();
	auto init = loop->resource<uvw::IdleHandle>();
	init->stop();
	idle->stop();

	//basic function test and initialization
	init->once<uvw::IdleEvent>([&](const uvw::IdleEvent&, uvw::IdleHandle& init) {
		
		//sample code for ECDSA encryption
		AutoSeededRandomPool prng;
		ECDSA<ECP, SHA256>::PrivateKey privateKey;
		ECDSA<ECP, SHA256>::PublicKey publicKey;

		privateKey.Initialize(prng, ASN1::secp256k1());
		privateKey.MakePublicKey(publicKey);
		ECDSA<ECP, SHA256>::Signer signer(privateKey);

		if (!privateKey.Validate(prng, 3)) {
			cout << "private key validation failed" << endl;
		}
		if (!publicKey.Validate(prng, 3)) {
			cout << "public key validation failed" << endl;
		}

		string message = "ABCDE";
		string signature;

		//key to string
		string publicstring;
		Base64Encoder pubKeySink(new StringSink(publicstring));
		publicKey.DEREncode(pubKeySink);
		pubKeySink.MessageEnd();

		ECDSA<ECP, SHA256>::PublicKey pub;
		StringSource stringSource(publicstring, true, new Base64Decoder);
		pub.BERDecode(stringSource);


		ECDSA<ECP, SHA256>::Verifier verifier(pub);

		bool result = false;

		StringSource s(message, true, new SignerFilter(prng, signer, new StringSink(signature)));

		string encoded;
		StringSource hexed(signature, true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource

		StringSource ss(signature + message, true /*pump all*/,
			new SignatureVerificationFilter(
				verifier,
				new ArraySink((byte*)& result, sizeof(result))
			) // SignatureVerificationFilter
		);

		cout << "original message: " << message << endl;
		cout << "signature: " << signature << endl;
		cout << "hexed signature: " << encoded << endl;
		if (!result) cout << "verification failed" << endl;
		else cout << "verified" << endl;

		//\sample code for ECDSA encryption



		//sample code for AES encryption(aes.h)

		//Generate a random key
		SecByteBlock key(0x00, AES::MAX_KEYLENGTH);
		prng.GenerateBlock(key, key.size());


		//Generate a random IV
		SecByteBlock iv(AES::BLOCKSIZE);
		prng.GenerateBlock(iv, iv.size());
		byte plaintext[] = "VWXYZ";
		size_t messageLen = std::strlen((char*)plaintext) + 1;

		//Encrypt
		CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
		cfbEncryption.ProcessData(plaintext, plaintext, messageLen);
		cout << "Encrypted(AES): " << plaintext << endl;

		//Decrypt
		CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
		cfbDecryption.ProcessData(plaintext, plaintext, messageLen);
		cout << "Decrypted(AES): " << plaintext << endl;

		//\sample code for AES encryption


		//sample code for block
		Block testblock(25, "hash", "random");
		vector<Transaction*> v;
		Account Me("hoon", 300);
		Account You("joon");
		for (int i = 1; i < 10; i++) {
			v.push_back(new Transaction(Me.GetId(), You.GetId(), i));
		}

		current = new Block(0, "", "");
		tmp_transaction = new vector<Transaction>();

		ifstream in("setting.txt");
		in >> myip;
		in >> rtgport;
		in >> n_cold;
		for (int i = 0; i < n_cold; i++) {
			string ip;
			int port;
			in >> ip;
			in >> port;
			coldlist[ip] = new coldinfo();
			coldlist[ip]->socket = loop->resource<uvw::TCPHandle>();
			coldlist[ip]->socket->on<uvw::ErrorEvent>([&](const uvw::ErrorEvent e, uvw::TCPHandle& t) {
				printf("coldnode: %s (%s)\nRetrying...\n", e.what(), e.name());
				t.connect(connection[&t].first, connection[&t].second);
			});
			coldlist[ip]->socket->once<uvw::ConnectEvent>([](const uvw::ConnectEvent&, uvw::TCPHandle& tcp) {
				printf("Cold node connected: %s, %d\n",tcp.peer().ip.c_str(), tcp.peer().port);
			});
			connection[coldlist[ip]->socket.get()] = make_pair(ip, port);
			coldlist[ip]->socket->connect(ip, port);
		}

		server->bind(myip, rtgport);
		server->noDelay(true);
		server->simultaneousAccepts(true);
		server->listen();
		init.stop();

	});

	//Block generation
	idle->on<uvw::TimerEvent>([&](const uvw::TimerEvent&, uvw::TimerHandle& idle) {

		//push claims
		int istart = 0;
		if (ledger.size() >= proof_limit) istart = ledger.size() - proof_limit + 1;
		for (int i = istart; i < ledger.size(); i++) {
			if (claims.find(i) != claims.end()) {
				current->push_claim(claims[i]);
			}
		}

		ledger.push_back(current);

		//serialize
		string s = current->serializer();

		//send to cold node
		vector<char> writable(s.begin(), s.end());
		auto dataWrite = unique_ptr<char[]>(new char[writable.size() + 1]);
		copy(writable.begin(), writable.end(), dataWrite.get());
		dataWrite[writable.size()] = '\0';
		for (map<string,coldinfo*>::iterator it = coldlist.begin(); it != coldlist.end(); it++) {
			auto dataonce = unique_ptr<char[]>(new char[writable.size() + 1]);
			copy(&dataWrite[0], &dataWrite[writable.size()+1], dataonce.get());
			it->second->socket->write(std::move(dataonce), writable.size() + 1);
			printf("block sent to %s, size: %d\n", it->second->socket->peer().ip.c_str(), writable.size() + 1);
		}

		//Get hash of previous block
		CryptoPP::SHA256 hash;
		string digest;
		CryptoPP::StringSource hasher(s, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));


		//block save
		current = new Block(ledger.size(), digest, "");
		printf("Block %d:\t%d Transactions\t%.1lf tps\tBuffer size: %d\n", ledger.size()-1, ledger[ledger.size() - 1]->GetTransactions().size(), (double)ledger[ledger.size() - 1]->GetTransactions().size() / 5., server->recvBufferSize());
	});


	server->on<uvw::ErrorEvent>([](const uvw::ErrorEvent& e, uvw::TCPHandle&) { printf("%s: %s\n", e.name(), e.what()); });
	server->on<uvw::ListenEvent>([&](const uvw::ListenEvent, uvw::TCPHandle& srv) {
		std::shared_ptr<uvw::TCPHandle> client = srv.loop().resource<uvw::TCPHandle>();
		client->once<uvw::EndEvent>([](const uvw::EndEvent&, uvw::TCPHandle& client) {printf("closed: %s, %d\n", client.peer().ip.c_str(), client.peer().port); client.close(); });
		client->on<uvw::DataEvent>([&](const uvw::DataEvent& d, uvw::TCPHandle& t) {
			string tmp_s(d.data.get(), d.length);
			c_buffer[&t] += tmp_s;
			if (c_buffer[&t][0] == 'T') {
				if (c_buffer[&t].size() < 256) {
					printf("Extending transaction...\n");
					return;
				}
				string u(c_buffer[&t]);
				c_buffer.clear();
				//timer initialize
				if (st_time == 0) {
					printf("Starting block generation...\n");
					st_time = clock();
					idle->start((std::chrono::duration < uint64_t, std::milli>)5000, (std::chrono::duration<uint64_t, std::milli>)5000);
				}
				string s(u, 1, u.size() - 2);//except for the final null character
				Transaction* l = Transaction::deserializer(s);
				if (Block::validate_transaction(*l))	current->push_transaction(l);
				delete l;
			}
			else if (c_buffer[&t][0] == 'p') {//proof + key
				if (c_buffer[&t].size() < 2) return;
				int bytes = (char)c_buffer[&t][1] - '0';
				if (c_buffer[&t].size() < 2+bytes) {
					printf("Extending proof and key...(a)\n");
					return;
				}
				char blocksizestr[10];
				for (int i = 0; i < bytes; i++) blocksizestr[i] = c_buffer[&t][2 + i];
				int blocksize = strtol(blocksizestr, NULL, 16);
				if (c_buffer[&t].size() < blocksize) {
					printf("Extending proof and key...(b)\n");
					return;
				}
				string s(c_buffer[&t]);
				c_buffer[&t].clear();
				printf("Received proof and key. Size: %d\n",s.size());
				int cipher;
				char blocknumstr[10];
				byte keybyte[32];
				byte ivbyte[16];
				int blocknum;
				vector<byte> recv_p;

				//deserialize
				cipher = s[2+bytes] - '0';
				for (int i = 0; i < cipher; i++) blocknumstr[i] = s[3 + bytes + i];
				blocknum = strtol(blocknumstr, NULL, 16);
				for (int i = 0; i < 32; i++) keybyte[i] = s[3 + bytes + cipher + i];
				for (int i = 0; i < 16; i++) ivbyte[i] = s[3 + bytes + cipher + 32 + i];
				for (int i = 3 + bytes + cipher + 32 + 16; i < s.size() - 1; i++) recv_p.push_back((byte)s[i]);
				auto pbyte = unique_ptr<byte[]>(new byte[recv_p.size() + 1]);
				copy(recv_p.begin(), recv_p.end(), pbyte.get());

				SecByteBlock key(keybyte, 32);
				SecByteBlock iv(ivbyte, 16);

				claims[blocknum] = EncryptedProof(blocknum, recv_p, key, iv);
			}
		});
		srv.accept(*client);
		client->read();
	});

	server->blocking(true);
	init->start();
	loop->run();

	return 0;

}