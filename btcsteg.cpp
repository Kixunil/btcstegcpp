#include <cstdio>
#include <cstring>
#include <errno.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string>
#include <vector>
#include <stdexcept>

#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

#include <libscrypt.h>

using namespace std;
using namespace CryptoPP;


// Base58 functions shamelessly stolen from Bitcoin core (https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp)
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch)
{
	// Skip leading spaces.
	while (*psz && isspace(*psz))
		psz++;
	// Skip and count leading '1's.
	int zeroes = 0;
	while (*psz == '1') {
		zeroes++;
		psz++;
	}
	// Allocate enough space in big-endian base256 representation.
	std::vector<unsigned char> b256(strlen(psz) * 733 / 1000 + 1); // log(58) / log(256), rounded up.
	// Process the characters.
	while (*psz && !isspace(*psz)) {
		// Decode base58 character
		const char* ch = strchr(pszBase58, *psz);
		if (ch == NULL)
			return false;
		// Apply "b256 = b256 * 58 + ch".
		int carry = ch - pszBase58;
		for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); it != b256.rend(); it++) {
			carry += 58 * (*it);
			*it = carry % 256;
			carry /= 256;
		}
		assert(carry == 0);
		psz++;
	}
	// Skip trailing spaces.
	while (isspace(*psz))
		psz++;
	if (*psz != 0)
		return false;
	// Skip leading zeroes in b256.
	std::vector<unsigned char>::iterator it = b256.begin();
	while (it != b256.end() && *it == 0)
		it++;
	// Copy result into output vector.
	vch.reserve(zeroes + (b256.end() - it));
	vch.assign(zeroes, 0x00);
	while (it != b256.end())
		vch.push_back(*(it++));
	return true;
}

std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
	// Skip & count leading zeroes.
	int zeroes = 0;
	while (pbegin != pend && *pbegin == 0) {
		pbegin++;
		zeroes++;
	}
	// Allocate enough space in big-endian base58 representation.
	std::vector<unsigned char> b58((pend - pbegin) * 138 / 100 + 1); // log(256) / log(58), rounded up.
	// Process the bytes.
	while (pbegin != pend) {
		int carry = *pbegin;
		// Apply "b58 = b58 * 256 + ch".
		for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); it != b58.rend(); it++) {
			carry += 256 * (*it);
			*it = carry % 58;
			carry /= 58;
		}
		assert(carry == 0);
		pbegin++;
	}
	// Skip leading zeroes in base58 result.
	std::vector<unsigned char>::iterator it = b58.begin();
	while (it != b58.end() && *it == 0)
		it++;
	// Translate the result into a string.
	std::string str;
	str.reserve(zeroes + (b58.end() - it));
	str.assign(zeroes, '1');
	while (it != b58.end())
		str += pszBase58[*(it++)];
	return str;
}

// Stores Bitcoin private key and address (as base58 encoded strings)
class BTCKeyPair {
	public:
		string privKey, addr;
};

// If true, written characters are shown in console
void setConsoleEcho(bool enable) {
	struct termios tty;

	tcgetattr(STDIN_FILENO, &tty);

	if( !enable )
		tty.c_lflag &= ~ECHO;
	else
		tty.c_lflag |= ECHO;

	(void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

// Reads password from console
// If confirm is true, it will ask second time
string readPassword(bool confirm) {
	char *pass1 = NULL, *pass2 = NULL;
	size_t pass1len = 0, pass2len = 0;

	string pass;

	setConsoleEcho(false);

	do {
		printf("Enter password: ");
		getline(&pass1, &pass1len, stdin);
		if(!confirm) goto retpass;
		printf("\nRepeat password: ");
		getline(&pass2, &pass2len, stdin);
		if(!strcmp(pass1, pass2)) goto retpass;
		printf("\nPasswords don't match. Try again.\n");
	} while(1);

retpass:
	putchar('\n');
	setConsoleEcho(true);

	pass = pass1;
	pass.erase(pass.size() - 1);

	free(pass1);
	free(pass2);

	return pass;
}

// Reads input from console (stdin), terminated with EOF
string readInput() {
	string input;

	char buf[1024];

	size_t len;

	while((len = read(0, buf, 1024)) > 0) { input += string(buf, len); }
	
	return input;
}

// Runs vanitygen and parses it's output
// prefixes - arguments for vanitygen
// errtodevnull - if true, stderr is redirected to /dev/null
vector<BTCKeyPair> vanitygen(const vector<string> &prefixes, bool errtodevnull = false) {
	// Initializtion of communication pipe
	int pipefd[2];
	if(pipe(pipefd) < 0) {
		throw runtime_error(string("pipe: ") + strerror(errno));
	}

	// fork is needed before execvp
	pid_t pid = fork();
	if(pid) {
		// Parent
		// close unneeded end of pipe
		close(pipefd[1]);

		// Convert fd to FILE * for convenience
		FILE *vp = fdopen(pipefd[0], "r");
		if(!vp) {
			throw runtime_error(string("fdopen: ") + strerror(errno));
		}

		char *line = NULL;
		size_t linelen = 0;
		BTCKeyPair pair;
		vector<BTCKeyPair> results;

		// Read from pipe and parse output
		while(getline(&line, &linelen, vp) > 0) {
			if(!strncmp(line, "Address: ", 9)) {
				pair.addr = line + 9;
				pair.addr.erase(pair.addr.size() - 1);
			}

			if(!strncmp(line, "Privkey: ", 9)) {
				pair.privKey = line + 9;
				pair.privKey.erase(pair.privKey.size() - 1);
				// Private key is last line for each pair
				results.push_back(pair);
			}
		}

		// Clean up
		fclose(vp);
		free(line);
		waitpid(pid, NULL, 0);
		return results;
	} else {
		// Child
		// Redirect stdout to pipe
		dup2(pipefd[1], 1);
		// close unneeded fds
		close(pipefd[0]);
		close(pipefd[1]);

		// Redirect stderr to /dev/null if desired
		int devnull = errtodevnull?open("/dev/null", O_WRONLY):-1;
		if(devnull > -1) {
			dup2(devnull, 2);
			close(devnull);
		}

		// Prepare argument list
		// Const casts should be OK.
		char *args[prefixes.size()+2];
		args[0] = (char *)"vanitygen";
		size_t i;
		for(i = 0; i < prefixes.size(); ++i) args[i+1] = (char *)prefixes[i].c_str();
		args[prefixes.size()+1] = NULL;

		// Run vanitygen
		execvp("vanitygen", args);
		perror("execvp");
		exit(1);
	}
}

// This function runs vanitygen with single argument
vector<BTCKeyPair> vanitygen(const string &prefix, bool errtodevnull = true) {
	vector<string> prefixes;
	prefixes.push_back(prefix);
	return vanitygen(prefixes, errtodevnull);
}

const size_t prefixlen = 3;

// Encrypts message given on stdin and hides it into Bitcoin addresses
void encrypt() {
	// Read password
	string pass(readPassword(true));

	printf("Type your secret message (end with Ctrl-D):\n");

	// Read message
	string msg(readInput());

	// Generate one random Bitcoin address using vanitygen to simplify coding
	vector<BTCKeyPair> pairs(vanitygen("1"));
	if(pairs.size() < 1) {
		fprintf(stderr, "Error\n");
		return;
	}

	// Buffer holds IV for AES and salt for scrypt generated as SHA256 hash of Bitcoin address
	char buf[256/8];
	SHA256 sha;

	// Generate IV/slat
	sha.CalculateDigest((byte *)buf, (byte *)pairs[0].addr.c_str(), pairs[0].addr.size());

	// Encryption key is generated using password and salt (second half of buf)
	char enckey[128/8];
	libscrypt_scrypt((const uint8_t *)pass.c_str(), pass.size(), (const uint8_t *)buf + 128/8, 128/8, 16384, 8, 16, (uint8_t *)enckey, 128/8);

	// Setup encryption
	AES::Encryption encryption((byte *)enckey, 128/8);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(encryption, (byte *)buf);
	string ciphertext;
	CryptoPP::StreamTransformationFilter filter(cbcEncryption, new CryptoPP::StringSink(ciphertext));

	// Encrypt message
	filter.Put((byte *)msg.c_str(), msg.size());
	filter.MessageEnd();

	// Encode to base58
	string b58ciphertext(EncodeBase58((unsigned char *)ciphertext.c_str(), (unsigned char *)ciphertext.c_str() + ciphertext.size()));

	// Length % prefixlen is encoded as first char chosen randomly from specific set
	unsigned char rnd;
	AutoSeededRandomPool rng;
	rng.GenerateBlock(&rnd, 1);

	// Calculate Length % prefixlen
	size_t ml = (b58ciphertext.size() + 1) % prefixlen;

	// Calculate set length
	size_t ccount = 58 / prefixlen;

	// Choose first char and prepend it
	// TODO: better rng
	b58ciphertext = pszBase58[57 - (ml * ccount + rnd % ccount)] + b58ciphertext;

	// Split string into parts
	vector<string> prefixes;
	size_t i, j;
	for(i = 0; i < b58ciphertext.size(); i += prefixlen) {
		// Every Bitcoin address starts with '1'
		prefixes.push_back("1" + b58ciphertext.substr(i, prefixlen));
	}
	
	// Generate addresses
	vector<BTCKeyPair> tmppairs(vanitygen(prefixes));

	// Output isn't correctly sorted - we have to do it manually
	// This is kind of inefficient but it's ok for short messages
	for(i = 0; i < prefixes.size(); ++i) {
		for(j = 0; j < tmppairs.size(); ++j) {
			if(tmppairs[j].addr.substr(0, prefixes[i].size()) == prefixes[i]) {
				pairs.push_back(tmppairs[j]);
				break;
			}
		}
	}

	// Output result
	printf("Addresses:\n");
	for(i = 0; i < pairs.size(); ++i) {
		puts(pairs[i].addr.c_str());
	}

	printf("Private keys:\n");
	for(i = 0; i < pairs.size(); ++i) {
		puts(pairs[i].privKey.c_str());
	}
}

// Decrypts message hidden in Bitcoin addresses given on stdin
void decrypt() {
	// Read password
	string pass(readPassword(false));

	printf("Enter addresses (end with Ctrl-D):\n");

	// Read addresses
	string msg(readInput());

	// Extract first address
	size_t lb = msg.find('\n');
	string b58ciphertext;
	string firstaddr(msg.substr(0, lb));
	msg.erase(0, lb + 1);

	// Extract relevant parts of addresses and concat them
	while(msg.size()) {
		b58ciphertext += msg.substr(1, prefixlen);
		lb = msg.find('\n');
		msg.erase(0, lb + 1);
	}

	// Calculate SHA256 of first address
	char buf[256/8];
	SHA256 sha;
	sha.CalculateDigest((byte *)buf, (byte *)firstaddr.c_str(), firstaddr.size());

	// Calculate decryption key
	char enckey[128/8];
	libscrypt_scrypt((const uint8_t *)pass.c_str(), pass.size(), (const uint8_t *)buf + 128/8, 128/8, 16384, 8, 16, (uint8_t *)enckey, 128/8);

	// Take first character
	char lc = b58ciphertext[0];

	// Find position of char
	size_t i;
	for(i = 0; i < 58; ++i) {
		if(pszBase58[i] == lc) break;
	}

	// Calculate length % prefixlen
	size_t ccount = 58 / prefixlen;
	i = (57 - i);
	i -= i % ccount;
	i /= ccount;

	// Remove first and some last characters
	b58ciphertext = b58ciphertext.substr(1, b58ciphertext.size() - 1 - (prefixlen - i) % prefixlen);

	// Setup ciphers
	string plaintext;
	vector<unsigned char> ciphertext;
	DecodeBase58(b58ciphertext.c_str(), ciphertext);
	AES::Decryption decryption((byte *)enckey, 128/8);
	CBC_Mode_ExternalCipher::Decryption cbcDecryption(decryption, (byte *)buf);
	CryptoPP::StreamTransformationFilter filter(cbcDecryption, new CryptoPP::StringSink(plaintext));

	// Decrypt message
	filter.Put((byte *)&ciphertext[0], ciphertext.size() - ciphertext.size() % (128/8));
	filter.MessageEnd();

	// Print message
	printf("Message:\n%s", plaintext.c_str());
}

// Just parses arguments
int main(int argc, char **argv) {
	if(argc > 1) {
		if(string(argv[1]) == "-h") {
			printf("Usage: %s [-d]\n", argv[0]);
			return 0;
		}

		if(string(argv[1]) == "-d") {
			decrypt();
			return 0;
		}
	}

	encrypt();
	return 0;
}
