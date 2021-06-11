#include <iostream>
#include "KISA_SHA256.h"

struct blockheader {
	BYTE previousBlockHash[257];    // 전 블록의 거래내역을 해쉬 한 값
};

struct block {
	int blockSize;    // 거래내역 크기
	blockheader header;    // 위에 있는 블록헤더 (이전 블록의 해쉬 값 저장)
	int transactionCount ;    // 몇 번째 거래인지
	BYTE transaction[100];    // 거래내역
	BYTE BlockHash[257];
	long long nonce;
};

void convert2array(BYTE* nonce, ULONG a) {
	int i = 0;

	for (i = 0; i < 8; ++i)
	{
		nonce[i] = (unsigned char)((((unsigned long long) a) >> (56 - (8 * i))) & 0xFFu);
	}
}

int main()
{
	block Block[100];
	int select = 0;
	int total = 0;
	printf("=============================================================================================================");
	printf("\n         Proof Of Work(Pow) Simulator  \n");
	printf("=============================================================================================================");

	
	int num = 0;
	while (1) {
		printf("\n\n***1.[Mining]Input Transaction(Data)   2.Block Data Check   3.Block Data Tampering   4.Print All Blocks   0. Quit***\n");
		scanf("%d", &select);

		if (select == 0) {
			return 0;
		}
		else if (select == 1) {
			if (total == 0) {
				printf("1st Block_Input Transaction(Data) : ");
				scanf("%s", Block[0].transaction);
				Block[0].transactionCount++;
				Block[0].blockSize = strlen((char*)Block[0].transaction);
				Block[0].nonce = 0;
				BYTE tmp[257] = { 0, };
				memcpy(tmp, Block[total].transaction, sizeof(BYTE) * Block[total].blockSize);

				BYTE nonce[8] = { 0, };
				while (Block[0].BlockHash[0] >= 16) {
					convert2array(nonce, Block[0].nonce);
					
					memcpy(tmp, nonce, sizeof(BYTE) * 8);
					SHA256_Encrpyt(tmp, sizeof(BYTE) * 257, Block[0].BlockHash);
					Block[0].nonce++;
					printf("finding nonce..: %llu\n", Block[0].nonce);
				}
				total++;
			}
			else {
				printf("%dth Block_Input Transaction(Data) : ", total + 1);
				scanf("%s", Block[total].transaction);
				Block[total].transactionCount = Block[total - 1].transactionCount + 1;
				Block[total].blockSize = strlen((char*)Block[total].transaction);
				memcpy(Block[total].header.previousBlockHash, Block[total - 1].BlockHash, sizeof(BYTE) * 257);
				Block[total].nonce = 0;
				//1. 이전 해쉬 값 + 데이터 + nobce
				
				BYTE tmp[257] = { 0, };
				memcpy(tmp, Block[total].header.previousBlockHash, sizeof(BYTE) * 257);
				memcpy(tmp, Block[total].transaction, sizeof(BYTE) * Block[total].blockSize);
				//2. HASH(이전 해쉬 값 + 데이터+nonce)
				
				BYTE nonce[8] = { 0, };
				while (Block[total].BlockHash[0] >= 16) {
					convert2array(nonce, Block[total].nonce);
					memcpy(tmp, nonce, sizeof(BYTE) * 8);
					SHA256_Encrpyt(tmp, sizeof(BYTE) * 257, Block[total].BlockHash);
					Block[total].nonce++;
					printf("finding nonce..: %llu\n", Block[total].nonce);
				}
				total++;
			}
			printf("\n현재 블록의 해쉬값 :");
			for (int j = 0; j < 32; j++) {
				printf("%02X", Block[total - 1].BlockHash[j]);
			};
			printf("\n현재 블록의 nonce : %llu", Block[total - 1].nonce);

		}
		else if (select == 2) {
			int i;
			
			printf("Block number(1~%d): ",total-1);  // 반드시 갯수가 2개 이상일때부터 가능함.
			scanf("%d", &num);
			if ( num > total )  continue;
			BYTE EncryptCheck[257];
			BYTE tmp[257] = { 0, };
			if (num == 1) {
				SHA256_Encrpyt(Block[num-1].transaction, Block[num-1].blockSize, EncryptCheck);
			}
			else {
				memcpy(tmp, Block[num - 1].header.previousBlockHash, sizeof(BYTE) * 257);
				memcpy(tmp, Block[num - 1].transaction, sizeof(BYTE) * Block[num - 1].blockSize);
				SHA256_Encrpyt(tmp, sizeof(BYTE) * 257, EncryptCheck);
			}
			for (i = 0; i < 256; i++) {
				if (Block[num].header.previousBlockHash[i] != EncryptCheck[i]) {
					break;
				}
			}
			if (i != 256) {
				printf("\nERROR :Tampered Data; ");
				printf("거래기록이 변조되었습니다\n");
			}
			else {
				printf("\n=============================================================================================================");
				printf("\nBlock number: %d ", num);
				printf("\n거래 내용: %s ", Block[num-1].transaction);
				printf("\n거래 내용 크키 : %d ", Block[num-1].blockSize);
				printf("\n이전 블록의 해쉬값 :");
				if (num == 1) printf(" ");
				else {
					for (int j = 0; j < 1; j++) {
						printf("%d", Block[num - 1].header.previousBlockHash[j]);
					};
				}
				printf("\n현재 블록의 해쉬값 :");
				for (int j = 0; j < 32; j++) {
					printf("%02X", Block[num-1].BlockHash[j]);
				};
				printf("\n=============================================================================================================\n");
			}
		}
		else if (select == 3) {
			printf("Block number(1~%d) : ",total);
			scanf("%d", &num);

			Block[num - 1].transaction[0] = (BYTE)"\0";
			printf("Tamper Data : ");
			scanf("%s", Block[num - 1].transaction);
			printf("\nTampering is completed.\n");
		}
		else if (select == 4) {
			int i;
			for (i = 0; i < total-1; i++){
				printf("\n==========================================================================================================================================");
				printf("\nBlock number: %d ", i + 1);
				printf("\n거래 내용: %s ",Block[i].transaction);
				printf("\n거래 내용 크키 : %d ", Block[i].blockSize);
				printf("\n이전 블록의 해쉬값 :"); 
				if (i == 0) printf(" ");
				else{
					for (int j = 0; j < 32; j++){
						printf("%02X", Block[i].header.previousBlockHash[j]);
					};
				}
				printf("\n현재 블록의 해쉬값 :");
				for (int j = 0; j < 32; j++){
					printf("%02X", Block[i].BlockHash[j]);
				};
				printf("\n==========================================================================================================================================");
			}
		}
	}
	return 0;
}