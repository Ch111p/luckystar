#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <process.h>
#include <subauth.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#pragma warning(disable:4996)

char image[] = {
	"MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWX0OOOO0KXWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWN0kdc;,,,',,:lld0WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKko:clodkOOkxdl;'',lONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNkc:cxKWMMMMMMMMWX0ko;,dNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMKo;:dXMWMMMMMMMMMMMMWW0l,dWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMXl'cOWWWMMMMMMMMMMMMMMMWNl;0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMx'cKMMMMMMMMMMMMMMMMMMMWMO;dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMNlcXMMMWWMMMW0kNMWNNXXXXKKO;c0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMWXO:lkxxxxxxkkklcodddddodddoollodxkkO0XNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMWNX0Odl:;cloddxxxxddodxdxxxxkddxxxxxxxxxddddxxk0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMWWX0kxdlcclodxxxxxxxxxdloxxxxxxxo:lxxxxxxxxxxxxxxdooxOXMMMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMWXOxolloxkxxxxxxxxxxddxl:lxxxxxxxd::ddodxxxxxxxddxxxxdookNWWMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMNOolc;lk000OdodxxxxxdcodllclxxxxxddclxxlcoxxxxxxdoloxxxxdodKWMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMXo:lc:dkkkkdddkOOkkkxlcdldxccdxxxdoocckOdc;cdddxxxolcldxxxOkdOWMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMXl:dlcdxxdl;;lxkkkxxxocoooO0ocokkkkxdllkKOdlcloxxxkxdoooxOO0KOoOWMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMNoo0ocdxdl;',cdxxxoodclolldKXdcodkxxko::xXX0dldooxxxxxl::cldk00ko0MMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMNXXxcdxo:'.';lxxxocolcxd:lOXNxlxodxxko;,dXXX0ocxxooodxd:,;;;lxO0dxNMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMM0coxc;,''':dxxl;cocdOl,o0KNOoOkodxkd:,lKNXXKdlkkolloxd:',,;oxxdlOMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMWdcdc,:c,.'lxxl;;lc;oo,.';,cOdkXxldkxc,c0NNXXKxoO0d::lxo;'',;oxd:kMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMXoc:'lk:;:;oxo;,;c,.''.....,O0kNXxlodl,;kNX0Okdcco:,,;:do;';:;ld:xMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMM0c;,lKd'dx;od:,,;;;ccl;',,,;kNXNWNkooc;';:,..,:cll;,,',;lc;:oc;;;kMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMO;'lXXccXO:ll;,',,'ldxkxoccckNNNNNNN0l;';ddc:;;:ll;,;,,;oOOOOkl,'xMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMO,:KMk:kMKc::,,'',':kKKOxddoxNWWWWWWNXk:;OWWNKkl;,,:ollONXK00kl;.lXMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMx;OMWxlXMWd;;,,'',,;xWNd:lookNWWWWWWWWWKdxXNXXX0x;;odokNNXK0kc:,ldkWMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMKOWMM0OWMM0;',,,,;;,dXNOdk0XWWWWWWWWWWWWNXKKKK0kl:odo:dNWNX0l,,;kWNWMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMWMMMMWd,';lc:;'lKXXNNNWWWWWWWWWWWWWWXKXK00Ododl:,lKNXKk;'':KMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMXc':doc,'c0NXXXNNWWWWNNNXNNNXXNXKKKK00kddddk000Kk;'.oNMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMO:lxo:,''ckKXNNWWWWNXXXXXXXXNNNXKK0K00XNWWNNK00Oc''kMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMXooko:,'..';ldk0KNNNNNNNNNNNXX0Oxl:dOKXXXNNNXKK0o''xWMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMKdxko;''.'''...,;:clooddddxkxdl;'..:x0KXXXX00KKKd,;OWMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMWOlxkl;,'.'''...',,;;;;;,,,l0K0x:''.'dXNNWWNXKKKKx;oWMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMNdcdo:,''''''.,codxdooolcoOXN0d:;,'',d0KXNWNXKKKKOlxWMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMKccdl;'''',;cdxddxkOxolod0WW0olllc,':xOKKXK00KKKK0kxKMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMWk:cl:,',ldOXNNXkloxkkkodOXNOddlcolll:oKNNNNXKKKKO00x0MMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMXl,cc;':ONNWMMWNKkdooooox0KOooc:lo;;k0xxOXNNXK0OkOOk0NMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMO;,::,,lOKXXNNXKOkkxl:::okxlcc;:l:'cONNKOxdodkkxdl:kWMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMNo;c:;,;dkxxkkO0Okxddol:;;;;coc;cc,;kXXXNNX0kdol;,':KMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMM0:;c;,,dXNN0kkOOOkxdolokkoccc:::c;'oXNXXKOxo:;::;;;lXMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMWd;c;,,cOWWXOOOO0kxkOOKWN0kdolc:c:':0WXXNOc',,cxd:::dNMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMM0ccc,,,dXXkdxOOkxO0NWWWN0OOkdcc:;,,dNWNX0l',,,lxo;;:xWMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMNl;l:,,;dkolxxxxOXWMWWNNKOOOOxlcc;':OWWNXd,',,,cdl;;:kMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMNd;cl:,,,collddk0X0xddxOK0OOO0kdlc;':KWWNXx;',,,cdl,,:kMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMNxcccl;';cll:;cxkkxl,',,;:oO0OOOkxl;':xKXXNKl',,,cdc'';kMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMNxldlll,':lc;,',coxo,,,,,,':oddddddl;,cl:cok0k:',,:o:.';kMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMXxldxol:';c:,,,,,,;cc;,,,;,,,;;;;;,,;,';::;,;:c:,,,:l:..,xMMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMXdldxxo:,,;,.,,,,,;lollcc::,,;,,,,,,,;,'',,'..,,;,,',:;..'xWMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMXdcodxdc,';l,.,,,,;;:llooooc;clccc:;,;:;,',;;,''',,,,,;,''.oNMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMWKdccdxdc,,lKO;';:ccc::looool:cloool:;;llll:,;cc:,,,,,,;;,,;'cXMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMWKxl:oxdc;,:kOl:cloolloolooll::loool:,,,coooc,,:ll:;;;,,,,,':;;0MMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMWKxocoxoc;''colcldxkkxdddolc:;:lololc;,,,coooc;,,;:c:,;:;,,,';l;xWMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMKdc,lOxl::ccodo:;cloddxxxdlccoxddxdoc:;,,:lll:,'',,;::,,;:;,,,dllNMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMKo:;:ddc:;;;;,,;,'..',,;:ccclxOOO0Okxxdlccoddolllccllloolcclc;'dOcOMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMXo:clodc,'.'''''''''''',''';cdxxdddolllc;:cloolloolclooodxdoodo;cKddWMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMXd;lxodl;,';,''''''''''',,'';x0OOOkxxdoc'..''':oooolloool::::;;::,dKKWMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMNx;c0xlo;,';Ox:,''',,,,,,'''''oKKKKKKKKKO:.'''':kKKKKKKKKOc''....'.lNMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMM0c;OKolc,,'dWWN0kc'';,'''''''.cKXXXXXXKK0o,'''''l0KKKKKKKKx;''',''':0MMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMWx;xW0lc;,':KMMMMWd.:OOdoool:;';OWWWWWWNNXxc;',,';kNXNNXXXX0o,,,,..',lNMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMWolXMOc:;,'xWMMMMNo.oNMWWMMW0l:,dNWWWWWWWNOdc,,,,,lKWWWWWWNXOc,,,..',,kWMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMWloWMO:;,'cKMMMMMWd,kWWMMMMMNkc,c0WWWWWWWNKOl,,,,,;xNWWWWWWNXk:,,..;;'cKMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMWO0WM0;','dWMMMMMMO:kMMMMMMMMNx;;xWWWWWWWWXKd;,,,,,:0WWWWWWWNKd;','co,'dWMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMWWMMXc',;OMMMMMMMNxOMMMMMMMMMXd,lXWWWWWWWNXk:,,,,,'lXWWWWWWWN0o'cd:xd';OMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMWk;.cXMMMMMMMMWWMMMMMMMMMWXo:OWWWWWWWNX0l,,,,,.'kNWWWWWWNNO;cKdl0o.lNMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMNd'lNMMMMMMMMMMMMMMMMMMMMMNdxNNNNNWWNXKd;,,,'..:0WNNXNNWNXolXKoOXc,OMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMNlcXMMMMMMMMMMMMMMMMMMMMMM0xKNXXNWWNXXk;,,,..'okXNXXNNWWNOd0WNNM0;oWMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMXOXMMMMMMMMMMMMMMMMMMMMMMNkkKKKXKKOkdc,,,,'.cKOkXXXXXKKOo;oNMMMWdcXMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWkcoooollc:,'',':c,xMKoldooollc:',kWMMM0lOMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM0cclcccccc;''',xocXMWOcllllcclc,.cKMMMWXNMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMXoclcccccc:,''o0dkMMMNd:llcclcc;''dWMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNo:lcllccc:,.;0WNWMMMMKlclcclcc:,';OMMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWx:lclclll:,',OMMMMMMMWO:clcclcc;,'lXMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMk:clcccll:,''dWMMMMMMMNd:llcccl:,',xWMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM0:;c:ccll:,,.:KMMMMMMMM0::lccccc;'':0MMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMWWWMMMMMMMMMMMMMMMMMMMMMMMM0:,;;;;;;,,'.'kMMMMMMMMWd;:::::;,''.cXMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMWWWWWWWWWMMMMWMMMMMMMMMMMMMWWO:::;;,'''''''xMMMMMMMMMXl',',;;,''.'lKWWMMMMMMMMMMMMMMMMM\n\
MMMMMWWWWWWWWWWWWWWWWWWWWNNWMMMMMMMMMMMMMNd;:;;,'','',,;kMMMMMMMMMMOc::::;;'',,:o0NWWWMMMMMMMMMMMMMM\n\
MMMMMMWWWWWWWWWWWWWWWWWWWWWWMMMMMMMMMMMMMWxclc:;,,,,,;ckNMMMMMMMMMMNxllcc::::;;clkXWXXWMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWXxlc:;,,,:oONMMMMMMMMMMMMMNkolllllc;,;lOKKKNWMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWMWKkdddkOKWMMMMMMMMMMMMMMMMMXkxoollodkXXXNWMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNNNWMMMMMMMMMMMMMMMMMMMMMM\n\
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
};


/*
md5 code from https://github.com/MrRoLiG/CBaseServer/blob/6c31bf0f691d31b2847b1122a5c3a0cc803460b8/Server/C%2B%2B_Server/MD5.cpp
*/
// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

// r specifies the per-round shift amounts
const uint32_t r[] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void to_bytes(uint32_t val, uint8_t *bytes)
{
	bytes[0] = (uint8_t)val;
	bytes[1] = (uint8_t)(val >> 8);
	bytes[2] = (uint8_t)(val >> 16);
	bytes[3] = (uint8_t)(val >> 24);
}

uint32_t to_int32(const uint8_t *bytes)
{
	return (uint32_t)bytes[0]
		| ((uint32_t)bytes[1] << 8)
		| ((uint32_t)bytes[2] << 16)
		| ((uint32_t)bytes[3] << 24);
}

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {

	// These vars will contain the hash
	uint32_t h0, h1, h2, h3;

	// Message (to prepare)
	uint8_t *msg = NULL;

	size_t new_len, offset;
	uint32_t w[16];
	uint32_t a, b, c, d, i, f, g, temp;

	// Initialize variables - simple count in nibbles:
	h0 = 0x67452301;
	h1 = 0xefcdab89;
	h2 = 0x98badcfe;
	h3 = 0x10325476;

	//Pre-processing:
	//append "1" bit to message    
	//append "0" bits until message length in bits �� 448 (mod 512)
	//append length mod (2^64) to message

	for (new_len = initial_len + 1; new_len % (512 / 8) != 448 / 8; new_len++)
		;

	msg = (uint8_t*)malloc(new_len + 8);
	memcpy(msg, initial_msg, initial_len);
	msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
	for (offset = initial_len + 1; offset < new_len; offset++)
		msg[offset] = 0; // append "0" bits

						 // append the len in bits at the end of the buffer.
	to_bytes(initial_len * 8, msg + new_len);
	// initial_len>>29 == initial_len*8>>32, but avoids overflow.
	to_bytes(initial_len >> 29, msg + new_len + 4);

	// Process the message in successive 512-bit chunks:
	//for each 512-bit chunk of message:
	for (offset = 0; offset<new_len; offset += (512 / 8)) {

		// break chunk into sixteen 32-bit words w[j], 0 �� j �� 15
		for (i = 0; i < 16; i++)
			w[i] = to_int32(msg + offset + i * 4);

		// Initialize hash value for this chunk:
		a = h0;
		b = h1;
		c = h2;
		d = h3;

		// Main loop:
		for (i = 0; i<64; i++) {

			if (i < 16) {
				f = (b & c) | ((~b) & d);
				g = i;
			}
			else if (i < 32) {
				f = (d & b) | ((~d) & c);
				g = (5 * i + 1) % 16;
			}
			else if (i < 48) {
				f = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			}
			else {
				f = c ^ (b | (~d));
				g = (7 * i) % 16;
			}

			temp = d;
			d = c;
			c = b;
			b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
			a = temp;

		}

		// Add this chunk's hash to result so far:
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;

	}

	// cleanup
	free(msg);

	//var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
	to_bytes(h0, digest);
	to_bytes(h1, digest + 4);
	to_bytes(h2, digest + 8);
	to_bytes(h3, digest + 12);
}

char b64_table[] = {
	'a', 'b', 'c', 'd', 'e', 'f','g', 'h',
	'i', 'j', 'k', 'l', 'm', 'n','o', 'p',
	'q', 'r', 's', 't', 'u', 'v','w', 'x',
	'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z',
	'0', '1', '2', '3','4', '5', '6', '7',
	'8', '9',
	'+', '/'
};

const WCHAR* Debugger[] = { L"idaq.exe",L"OllyDbg.exe",L"x32dbg",L"x64dbg",L"x96dbg",L"ida.exe" };

typedef LONG NTSTATUS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _VM_COUNTERS
{
	ULONG PeakVirtualSize;
	ULONG VirtualSize;
	ULONG PageFaultCount;
	ULONG PeakWorkingSetSize;
	ULONG WorkingSetSize;
	ULONG QuotaPeakPagedPoolUsage;
	ULONG QuotaPagedPoolUsage;
	ULONG QuotaPeakNonPagedPoolUsage;
	ULONG QuotaNonPagedPoolUsage;
	ULONG PagefileUsage;
	ULONG PeakPagefileUsage;
}VM_COUNTERS, *PVM_COUNTERS;


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI *PFZWQUERYSYSTEMINFORMATION)
(SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

enum THREAD_INFO_CLASS { ThreadHideFromDebugger = 17 };

typedef NTSTATUS(NTAPI *ZW_SET_INFORMATION_THREAD)(IN HANDLE ThreadHandle, IN DWORD ThreadInformationClass, IN PVOID ThreadInformation, IN ULONG ThreadInformationLength);

FARPROC ZwSetInformationThread = NULL;
FARPROC pFunc = NULL;
FARPROC pFunc2 = NULL;

#pragma comment(lib,"winmm.lib")

#pragma section("music",read,write)
__declspec(allocate("music"))
char a[0x7fffff] = { 2, };

int isProcessOut = 0;

/*void printConsole(const char* szMsg) {
HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
SetConsoleTextAttribute(hStdout, FOREGROUND_GREEN);
WriteConsole(hStdout, szMsg, strlen(szMsg), NULL, NULL);
}*/


ULONG_PTR MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {

	uint8_t result[16];
	char subChar[33];

	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS pImageNtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

	pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
	pImageNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + pImageDosHeader->e_lfanew);
	pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD dwExportRVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD dwExportSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	DWORD *pAddressOfFunction = (DWORD*)(pImageExportDirectory->AddressOfFunctions + (ULONG_PTR)hModule);
	DWORD *pAddressOfNames = (DWORD*)(pImageExportDirectory->AddressOfNames + (ULONG_PTR)hModule);
	DWORD dwNumberOfNames = (DWORD)(pImageExportDirectory->NumberOfNames);
	WORD *pAddressOfNameOrdinals = (WORD*)(pImageExportDirectory->AddressOfNameOrdinals + (ULONG_PTR)hModule);

	for (int i = 0; i < (int)dwNumberOfNames; i++) {
		md5((uint8_t*)pAddressOfNames[i] + (ULONG_PTR)hModule, strlen((const char*)(pAddressOfNames[i] + (ULONG_PTR)hModule)), result);
		for (int i = 0; i < 16; i++) {
			sprintf(subChar + 2 * i, "%02x", result[i]);
		}
		subChar[32] = '\x00';
		if (!strcmp(subChar, lpProcName)) {
			char* pRet = (char *)(pAddressOfFunction[pAddressOfNameOrdinals[i]] + (ULONG_PTR)hModule);
			return (ULONG_PTR)pRet;
		}
	}
	return NULL;
}

bool judgeBeDebugger() {

	NTSTATUS status;
	ULONG retLength;
	PVOID pProcInfo;
	PSYSTEM_PROCESS_INFORMATION pCur;
	pFunc = (FARPROC)MyGetProcAddress(GetModuleHandleA("ntdll.dll"), "a7d7bcc95a86a6df3b0a1ccb3c69d440");
	ZwSetInformationThread = (FARPROC)MyGetProcAddress(GetModuleHandleA("ntdll.dll"), "8eb35a28209979fe6a9983cff0d23c5a");
	pFunc2 = (FARPROC)MyGetProcAddress(GetModuleHandleA("kernel32.dll"), "05577e1568efa10b8166728bfb414c59");
	if (pFunc == NULL || ZwSetInformationThread == NULL || pFunc2 == NULL) {
		return 1;
	}
	((PFZWQUERYSYSTEMINFORMATION)pFunc)(SystemProcessInformation, NULL, 0, &retLength);
	pProcInfo = (PVOID)malloc(retLength);
	status = ((PFZWQUERYSYSTEMINFORMATION)pFunc)(SystemProcessInformation, pProcInfo, retLength, &retLength);
	if (status != STATUS_SUCCESS) {
		return 1;
	}
	pCur = (PSYSTEM_PROCESS_INFORMATION)pProcInfo;
	do {
		for (int i = 0; i < sizeof(Debugger) / 4; i++) {
			if (!lstrcmpW((LPCWSTR)Debugger[i], (LPCWSTR)pCur->Reserved2[1])) {
				return 1;
			}
		}
		pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pCur + pCur->NextEntryOffset);
	} while (pCur->NextEntryOffset != 0);
	return 0;

}

void NTAPI __stdcall TLS_CALLBACK1(PVOID DllHandle, DWORD Reason, PVOID Reserved) {

	if (Reason == DLL_PROCESS_ATTACH) {
		if (judgeBeDebugger()) {
			printf("LuckyStar!");
			exit(0);
		}
		((ZW_SET_INFORMATION_THREAD)ZwSetInformationThread)((HANDLE)GetCurrentThread(), 0x11, NULL, 0);
		char* startAddr = (char*)0x400000;
		int length = 0x400;
		srand(0x61616161);
		for (int i = 0; i < length; i++) {
			startAddr[i] ^= a[(rand() % 0x2018) + 0xf000];
		}
	}

	if (Reason == DLL_THREAD_DETACH) {
		((ZW_SET_INFORMATION_THREAD)ZwSetInformationThread)((HANDLE)GetCurrentThread(), 0x11, NULL, 0);
	}

}

#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif

EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif

PIMAGE_TLS_CALLBACK _tls_callback[] = { TLS_CALLBACK1, 0 };
#pragma data_seg ()
#pragma const_seg ()

void changeBits(char* input, char* encrypt) {

	int j = 0;
	int length = strlen(input) * 4 / 3;
	for (int i = 0; i < length; i++) {
		if (i % 4 == 0) {
			encrypt[i] = b64_table[input[j++] >> 2];
		}
		else if (i % 4 == 1) {
			encrypt[i] = b64_table[((input[j - 1] & 0b11) << 4) | (input[j++] >> 4)];
		}
		else if (i % 4 == 2) {
			encrypt[i] = b64_table[((input[j - 1] & 0b1111) << 2) | (input[j++] >> 6)];
		}
		else {
			encrypt[i] = b64_table[input[j - 1] & 0b111111];
		}
	}
	if (strlen(input) % 3 == 1) {
		encrypt[length] = b64_table[(input[j - 1] & 0b11) << 4];
		encrypt[length + 1] = '=';
		encrypt[length + 2] = '=';
	}
	else if (strlen(input) % 3 == 2) {
		encrypt[length] = b64_table[(input[j - 1] & 0b1111) << 2];
		encrypt[length + 1] = '=';
	}
	encrypt[strlen(encrypt)] = '\x00';

	length = strlen(encrypt);
	for (int i = 0; i < length; i++) {
		for (int j = 0; j < 4; j++) {
			encrypt[i] ^= ((rand() % 4) << (2 * (3 - j)));
		}
	}
}

DWORD WINAPI ThreadFunc(LPVOID lparam) {
	PlaySoundA(a, 0, SND_SYNC | SND_MEMORY);
	isProcessOut = 1;
	return 0;
}

int main() {

	int length = 0x192;
	CreateThread(0, 0, ThreadFunc, 0, 0, 0);
	char *start = (char*)changeBits;
	printf("%s\n", image);
	while (1) {
		if (isProcessOut)
		{
			printf("\n");
			for (int i = 0; i < length; i++) {
				start[i] ^= a[(rand() % 0x2018) + 0xf000];
			}
			printf("Shining!\n");
			system("cls");
			break;
		}
		else {
			Sleep(2000);
			printf(">");
		}
	}

	char input[30];
	char encrypt[70];
	memset(input, 0, 30);
	memset(encrypt, 0, 70);
	printf("My Darling Darling Please!\ninput your key!\n");
	scanf("%29s", input);
	changeBits(input, encrypt);
	char encryptedStr[70] = { 0x41,0xf3,0x4f,0x7d,0x75,0x67,0xd2,0x1b,0x4b,0x5d,0xdf,0x54,0x6f,0x6a,0x25,0x94,0x4,0xe0,0x8a,0xb1,0x69,0x42,0x98,0x3e,0x89,0xe8,0x66,0xc9,0x6,0xf9,0xc1,0xd3,0x00 };
	if (!strcmp(encrypt, encryptedStr)) {
		printf("Nice Job~");
	}
	else {
		printf("Maybe next year");
	}
	system("pause");
	return 0;
}