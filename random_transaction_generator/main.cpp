#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <string>
#include <map>
#include <fstream>

#include "uvw.hpp"
#include <boost/serialization/string.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <iostream>
#include <random>

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
std::string hotip;
int hotport;
int limiter;

int main() {

	auto loop = uvw::Loop::getDefault();
	auto tcp = loop->resource<uvw::TCPHandle>();
	tcp->on<uvw::ErrorEvent>([](const uvw::ErrorEvent e, uvw::TCPHandle& t) {
		printf("tcp: %s (%s)\n", e.what(), e.name());
	});

	auto setting = loop->resource<uvw::TimerHandle>();

	auto init = loop->resource<uvw::TimerHandle>();
	init->stop();

	auto idle = loop->resource<uvw::TimerHandle>();
	idle->stop();

	//initialization
	setting->on<uvw::TimerEvent>([&](const uvw::TimerEvent&, uvw::TimerHandle& setting) {
		std::ifstream in("setting.txt");
		in >> hotip;
		in >> hotport;
		in >> limiter;
		tcp->connect(hotip, hotport);
		setting.stop();
	});

	init->on<uvw::ErrorEvent>([](const uvw::ErrorEvent e, uvw::TimerHandle& i) {
		printf("init: %s (%s)\n", e.what(), e.name());
	});

	//registering 100 accounts
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
			idle->start((std::chrono::duration < uint64_t, std::milli>)0, (std::chrono::duration<uint64_t, std::milli>)limiter);
			init.stop();
		}

	});

	idle->on<uvw::ErrorEvent>([](const uvw::ErrorEvent e, uvw::TimerHandle& i) {
		printf("idle: %s (%s)\n", e.what(), e.name());
	});
	idle->on<uvw::TimerEvent>([&tcp](const uvw::TimerEvent&, uvw::TimerHandle& idle) {

		random_transaction* k;
		k = new random_transaction(false);

		std::string serialized = tr_serializer(k);

		auto dataWrite = std::unique_ptr<char[]>(new char[256]);

		std::vector<char> writable(serialized.begin(), serialized.end());
		writable.insert(writable.begin(), 'T');
		std::copy(writable.begin(), writable.end(), dataWrite.get());

		auto res = tcp->tryWrite(std::move(dataWrite), 256);
		tx_cnt++;
		if (res != 256) txx_cnt++;
		elapsed++;
		delete k;

		if (elapsed*limiter >= 5000) {
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

	setting->start((std::chrono::duration < uint64_t, std::milli>)0, (std::chrono::duration<uint64_t, std::milli>)100);
	printf("loopgen\n");
	loop->run();

	return 0;

}