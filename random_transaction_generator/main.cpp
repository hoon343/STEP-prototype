#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <string>
#include <map>

#include "uvw.hpp"
#include <boost/serialization/string.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <iostream>
#include <random>
#define LIMITER 2
#define HOTIP "143.248.55.106"
#define HOTPORT 55459
/*
#define UV_HANDLE_WRITABLE 32768
typedef struct {
uv_write_t req;
uv_buf_t buf;
} write_req_t;
void on_send(uv_write_t* req, int status) {
printf("callback\n");
write_req_t* wr = (write_req_t*)req;
free(wr->buf.base);
free(wr);
}
void send_message(uv_tcp_t* socket, char message[], int len) {
char* s_message = (char*)malloc(len);
strcpy_s(s_message, len, message);
uv_buf_t* buf = (uv_buf_t*)malloc(sizeof(uv_buf_t));
*buf = uv_buf_init(s_message, len);
buf->len = len;
buf->base = s_message;

write_req_t* req = (write_req_t*)malloc(sizeof(write_req_t));
req->buf = uv_buf_init(buf->base, len);
uv_write((uv_write_t*)req, (uv_stream_t*)socket, &req->buf, 1, on_send);
printf("message sent\n");
free(buf);
free(s_message);
}
int main() {

//loop
uv_loop_t* loop = uv_default_loop();
uv_tcp_t* socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
uv_tcp_init(loop, socket);

//Connection
uv_connect_t* connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));
struct sockaddr_in dest;
uv_ip4_addr("0.0.0.0", 7000, &dest);
uv_tcp_connect(connect, socket, (const struct sockaddr*) & dest, NULL);
socket->flags |= UV_HANDLE_WRITABLE;


while (1) {
//Message

char message[] = "Hi there";
send_message(socket, message, sizeof(message));

}
return 0;
}*/

std::random_device rd;
std::mt19937 mer(rd());
std::vector<std::string> ids;
class Account {
public:
	Account(std::string account_id, unsigned long long int account_valance) {
		id = account_id;
		valance = account_valance;
	}
	std::string id;
	unsigned long long int valance;
};
std::map <std::string, Account*> accounts;

std::string random_id(const int len)
{
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	std::string s;
	for (int i = 0; i < len; ++i) {
		s += alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	return s;
}

class random_transaction {
public:
	random_transaction() {
		_random_transaction();
	}
	random_transaction(bool newaccount) {
		if (newaccount) {
			from = "init";
			to = random_id(16);
			amount = 10000;
			Account* tmp = new Account(to, amount);
			accounts[to] = tmp;
			ids.push_back(to);
			
		}
		else {
			_random_transaction();
		}
	}
	void _random_transaction() {
		std::uniform_int_distribution<> peer(0, ids.size() - 1);
		from = ids[peer(mer)];
		while (accounts[from]->valance < 10) {
			from = ids[peer(mer)];
		}
		to = ids[peer(mer)];
		amount = 10;
		accounts[from]->valance -= amount;
		accounts[to]->valance += amount;
	}

	std::string getfrom() { return from; }
	std::string getto() { return to; }
	unsigned long long int getamount() { return amount; }
private:
	std::string from;
	std::string to;
	unsigned long long int amount;
	std::string id1;
	std::string id2;
	//private:
	friend class boost::serialization::access;
	template<class Archive> void serialize(Archive& ar, const unsigned int version) {
		//ar& boost::serialization::base_object<something>(*this);
		//boost::serialization::void_cast_register(static_cast<something*>(NULL),static_cast<something *>(NULL));
		ar& from;
		ar& to;
		ar& amount;
		ar& id1;
		ar& id2;
	}
};

int total_user = 0;

std::string tr_serializer(random_transaction* k) {
	std::string serial_str;
	boost::iostreams::back_insert_device<std::string> inserter(serial_str);
	boost::iostreams::stream< boost::iostreams::back_insert_device<std::string> > s(inserter);
	boost::archive::binary_oarchive oa(s);
	oa << k;
	s.flush();
	return serial_str;
}
random_transaction* tr_deserializer(std::string serial_str) {

	random_transaction* l;
	boost::iostreams::basic_array_source<char> device(serial_str.c_str(), serial_str.size());
	boost::iostreams::stream<boost::iostreams::basic_array_source<char> > u(device);
	boost::archive::binary_iarchive ia(u);
	ia >> l;
	return l;
}

int elapsed = 0;
int tx_cnt = 0;
int txx_cnt = 0;
int times = 0;

int main() {

	auto loop = uvw::Loop::getDefault();
	auto tcp = loop->resource<uvw::TCPHandle>();
	tcp->on<uvw::ErrorEvent>([](const uvw::ErrorEvent e, uvw::TCPHandle& t) {
		printf("tcp: %s (%s)\n", e.what(), e.name());
	});

	auto init = loop->resource<uvw::TimerHandle>();
	init->stop();

	auto idle = loop->resource<uvw::TimerHandle>();
	idle->stop();

	init->on<uvw::ErrorEvent>([](const uvw::ErrorEvent e, uvw::TimerHandle& i) {
		printf("init: %s (%s)\n", e.what(), e.name());
	});
	init->on<uvw::TimerEvent>([&](const uvw::TimerEvent&, uvw::TimerHandle& init) {
	
		random_transaction* k;
		k = new random_transaction(true);
		total_user++;

		std::string serialized = tr_serializer(k);

		auto dataWrite = std::unique_ptr<char[]>(new char[256]);

		std::vector<char> writable(serialized.begin(), serialized.end());
		writable.insert(writable.begin(), 'T');
		std::copy(writable.begin(), writable.end(), dataWrite.get());

		auto res = tcp->tryWrite(std::move(dataWrite), 256);
		if (res == 0) printf("init failed: total_user=%d\n",total_user);

		delete k;

		if (total_user >= 100) {
			idle->start((std::chrono::duration < uint64_t, std::milli>)0, (std::chrono::duration<uint64_t, std::milli>)LIMITER);
			init.stop();
		}

	});

	idle->on<uvw::ErrorEvent>([](const uvw::ErrorEvent e, uvw::TimerHandle& i) {
		printf("idle: %s (%s)\n", e.what(), e.name());
	});
	idle->on<uvw::TimerEvent>([&tcp](const uvw::TimerEvent&, uvw::TimerHandle& idle) {

		random_transaction* k;
		k = new random_transaction(false);

		//oa << k;
		//s.flush();
		std::string serialized = tr_serializer(k);
		//std::cout << serialized << std::endl;

		auto dataWrite = std::unique_ptr<char[]>(new char[256]);

		std::vector<char> writable(serialized.begin(), serialized.end());
		writable.insert(writable.begin(), 'T');
		std::copy(writable.begin(), writable.end(), dataWrite.get());
		//dataWrite[serial_str.size()] = '\0';


		auto res = tcp->tryWrite(std::move(dataWrite), 256);
		tx_cnt++;
		if (res != 256) txx_cnt++;
		elapsed++;
		delete k;

		if (elapsed*LIMITER >= 5000) {
			printf("Transactions: %d\nFailed: %d\n", tx_cnt,txx_cnt);
			tx_cnt = 0;
			txx_cnt = 0;
			elapsed = 0;
			times++;
		}

		if (times >= 100) {
			idle.stop();
		}

	});


	tcp->once<uvw::ConnectEvent>([&](const uvw::ConnectEvent&, uvw::TCPHandle& tcp) {
		printf("connected\n");
		init->start((std::chrono::duration < uint64_t, std::milli>)0,(std::chrono::duration<uint64_t, std::milli>)100);
	});


	tcp->noDelay(false);
	tcp->blocking(true);
	tcp->connect(HOTIP, HOTPORT);
	//wait_time = clock();
	//tcp->listen();

	printf("loopgen\n");
	loop->run();

	return 0;

}