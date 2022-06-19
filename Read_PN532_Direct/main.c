#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>


#define PN532_PREAMBLE                      (0x00)
#define PN532_STARTCODE1                    (0x00)
#define PN532_STARTCODE2                    (0xFF)
#define PN532_POSTAMBLE                     (0x00)

#define PN532_HOSTTOPN532                   (0xD4)
#define PN532_PN532TOHOST                   (0xD5)

// PN532 Commands
#define PN532_COMMAND_DIAGNOSE              (0x00)
#define PN532_COMMAND_GETFIRMWAREVERSION    (0x02)
#define PN532_COMMAND_GETGENERALSTATUS      (0x04)
#define PN532_COMMAND_READREGISTER          (0x06)
#define PN532_COMMAND_WRITEREGISTER         (0x08)
#define PN532_COMMAND_READGPIO              (0x0C)
#define PN532_COMMAND_WRITEGPIO             (0x0E)
#define PN532_COMMAND_SETSERIALBAUDRATE     (0x10)
#define PN532_COMMAND_SETPARAMETERS         (0x12)
#define PN532_COMMAND_SAMCONFIGURATION      (0x14)
#define PN532_COMMAND_POWERDOWN             (0x16)
#define PN532_COMMAND_RFCONFIGURATION       (0x32)
#define PN532_COMMAND_RFREGULATIONTEST      (0x58)
#define PN532_COMMAND_INJUMPFORDEP          (0x56)
#define PN532_COMMAND_INJUMPFORPSL          (0x46)
#define PN532_COMMAND_INLISTPASSIVETARGET   (0x4A)
#define PN532_COMMAND_INATR                 (0x50)
#define PN532_COMMAND_INPSL                 (0x4E)
#define PN532_COMMAND_INDATAEXCHANGE        (0x40)
#define PN532_COMMAND_INCOMMUNICATETHRU     (0x42)
#define PN532_COMMAND_INDESELECT            (0x44)
#define PN532_COMMAND_INRELEASE             (0x52)
#define PN532_COMMAND_INSELECT              (0x54)
#define PN532_COMMAND_INAUTOPOLL            (0x60)
#define PN532_COMMAND_TGINITASTARGET        (0x8C)
#define PN532_COMMAND_TGSETGENERALBYTES     (0x92)
#define PN532_COMMAND_TGGETDATA             (0x86)
#define PN532_COMMAND_TGSETDATA             (0x8E)
#define PN532_COMMAND_TGSETMETADATA         (0x94)
#define PN532_COMMAND_TGGETINITIATORCOMMAND (0x88)
#define PN532_COMMAND_TGRESPONSETOINITIATOR (0x90)
#define PN532_COMMAND_TGGETTARGETSTATUS     (0x8A)

#define PN532_RESPONSE_INDATAEXCHANGE       (0x41)
#define PN532_RESPONSE_INLISTPASSIVETARGET  (0x4B)

#define PN532_WAKEUP                        (0x55)

#define PN532_MIFARE_ISO14443A              (0x00)
#define PN532_RFCONFIG_RETURN_DELAY         (0x05)
#define PN532_RFCONFIG_ACTIVE_MODE         	(0xFF)

// Other Error Definitions
#define PN532_STATUS_ERROR                                              (-1)
#define PN532_STATUS_OK                                                 (0)

#define PACKET 			1
#define ACK 			2

#define PASSIVE_COMMAND_CYCLE_MS	1000



#define PN532_RF_REGULATION_STATE		0
#define PN532_READ_VERSION_STATE		1
#define PN532_GET_STATUS_STATE			2
#define PN532_SET_SCANNING_STATE		3
#define PN532_DONE_INIT_STATE			4


int pn532_address;


void pn532_init(void)
{
    char *portname = "/dev/ttyS0";
    pn532_address = open (portname, O_RDWR | O_NOCTTY | O_SYNC);
    if (pn532_address < 0)
    {
            printf("error %d opening %s: %s", errno, portname, strerror (errno));
        exit(-1);
    }

	struct termios tty;
	memset (&tty, 0, sizeof tty);
	if (tcgetattr (pn532_address, &tty) != 0)
	{
			printf("error %d from tcgetattr(%s)\n", errno,strerror(errno));
	exit(-1);
	}

	cfsetospeed (&tty, B115200);
	cfsetispeed (&tty, B115200);

	tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
	// disable IGNBRK for mismatched speed tests; otherwise receive break
	// as \000 chars
	tty.c_iflag &= ~IGNBRK;         // disable break processing
	tty.c_lflag = 0;                // no signaling chars, no echo,
									// no canonical processing
	tty.c_oflag = 0;                // no remapping, no delays
	tty.c_cc[VMIN]  = 0;            // read doesn't block
	tty.c_cc[VTIME] = 0;            // 0.5 seconds read timeout

	tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

	tty.c_cflag |= (CLOCAL | CREAD);// ignore modem controls,
									// enable reading
	tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
	tty.c_cflag |= 0;   //This was parity
	tty.c_cflag &= ~CSTOPB;
	tty.c_cflag &= ~CRTSCTS;

	if (tcsetattr (pn532_address, TCSANOW, &tty) != 0)
	{
		printf("error %d from tcsetattr(%s)\n", errno,strerror(errno));
		exit(-1);
	}
}

void sendpacket(unsigned char * payload, int len)
{

	unsigned char data[66000];
    int count;
    unsigned char checksum;

    //HEADER WAKE UP
    for(count=0; count<=8;count++){
    	data[count] = 0xFF;
    }

    data[count++]=0x00;
    data[count++]=0xFF;

    //BEGIN LENGTH
    data[count++] = len+1;
    data[count++] = -(len+1);

    //TARGET ID
    data[count++] = 0xD4;
    checksum = 0xD4;
    for(int counts = 0; counts < len; counts++){
    	data[count++] = payload[counts];
    	checksum = checksum + payload[counts];
    }
    data[count++] = (-checksum);
	usleep(10);
    write(pn532_address,data,count);
	usleep(10);

//    printf("Sent %d bytes\n",count);
//    printf("Whole packet: ");
//    for(int counts = 0; counts <= count; counts++){
//    	printf("0x%02X ",data[counts]);
//    }
//    printf("\n");

}

void callbackstatus(){
	int callbacktimeout = 0, callbackresposnse, callbackcase = 0, countcallback = 0, callbackdone = 0;
	unsigned char buf[1], bufin[PASSIVE_COMMAND_CYCLE_MS], lastbuf, lengthbuf, lengthchecksum, endchecksum = 0, targetcallback;
	while((callbacktimeout <= PASSIVE_COMMAND_CYCLE_MS) && (callbackdone == 0)){
		lastbuf = buf[0];
		int n = read(pn532_address,buf,sizeof(buf));
		switch(callbackcase){
			case 0 : if((lastbuf == 0x00) && (buf[0] == 0xFF)) callbackcase = 1; break;
			case 1 : lengthbuf = buf[0]; callbackcase = 2;  break;
			case 2 :
//				if((lengthbuf == 0xFF) && (buf[0] == 0xFF)){printf("ERROR: BIG PACKET. Bye.\n");}
				if(((lengthbuf == 0x00) && (buf[0] == 0xFF)) || ((lengthbuf == 0xFF) && (buf[0] == 0x00))){callbackcase = 3;}
				else
				{
					lengthchecksum = buf[0] + lengthbuf;
//					printf(" lcs : 0x%02X | 0x%02X ", buf[0],lengthchecksum);
//					if(lengthchecksum){printf("ERROR: len checksum failed! 0x%02X\n",buf[0]);}
					callbackcase = 4;
				}
				break;
			case 3 :
				callbackcase = 0;
//				if((buf[0] == 0x00) && (lastbuf == 0xFF))
//				{
//					printf("ACK!\n");
//				}else{
//					printf("ERROR: Invalid length, or ack/nack missing postamble...\n");
//				}
				break;
			case 4 :
				targetcallback = buf[0];
//				printf("targetcallback=0x%02X\n",targetcallback);
				endchecksum = targetcallback;
				callbackcase = 5;
				countcallback = 0;
				break;

			case 5 :
//				printf("Saving payload byte 0x%02X\n",buf[0]);
				bufin[countcallback++] = buf[0];
				endchecksum = endchecksum + buf[0];
				if(countcallback >= lengthbuf){callbackcase = 6;}
				break;

			case 6 :
				callbackdone = 1;
				endchecksum = endchecksum + buf[0];
//				printf("CS : 0x%02X | 0x%02X\n",buf[0],endchecksum);
				if(endchecksum)
				{
//					printf("ERROR: Data Checksum Failed! (0x%02X)\n",endchecksum);
				} else {
					if(targetcallback == 0xD5)
					{
						if(bufin[0]==0x03){printf("PN532 Version: %d.%d, features:%d\n",bufin[2],bufin[3],bufin[4]);}
						if(bufin[0]==0x05)
						{

							printf("Status: Last Error:%d, Field:%d, Targets:%d, SAM Status:0x%02X\n",bufin[1],bufin[2],bufin[3],bufin[lengthchecksum-2]);
							static char bitrates[255][10]={"106kbps","212kbps","424kbps"};
							static char modtypes[255][100];
							strcpy(modtypes[0x00],"Mifare, ISO/IEC14443-3 Type A, ISO/IEC14443-3 Type B, ISO/IEC18092 passive 106 kbps");
							strcpy(modtypes[0x10],"FeliCa, ISO/IEC18092 passive 212/424 kbps");
							strcpy(modtypes[0x01],"ISO/IEC18092 Active mode");
							strcpy(modtypes[0x02],"Innovision Jewel tag");
							if(bufin[3]==1){printf("Target %d: rx bps:%s, tx bps:%s, modulation type: %s.\n",bufin[4],bitrates[bufin[5]],bitrates[bufin[6]],modtypes[bufin[7]]);}
							if(bufin[3]==2){printf("Target %d: rx bps:%s, tx bps:%s, modulation type: %s.\n",bufin[8],bitrates[bufin[9]],bitrates[bufin[10]],modtypes[bufin[11]]);}
						}
						if(bufin[0]==0x4B)
						{
							for(int countcard = 0; countcard < bufin[1]; countcard++){
								printf("%02X:%02X:%02X:%02X \n",bufin[7 + (countcard * 9)],bufin[8 + (countcard * 9)],bufin[9 + (countcard * 9)],bufin[10 + (countcard * 9)]);
							}
//							printf("FOUND %d CARDS!\n",bufin[1]);
							//ONLY VALID FOR Mifare/ ISO type A 106KBPS:
//							int i,ii,iii;
//							i=0;ii=2;
//							while(i<bufin[1])
//							{
//								printf("Target # %d |%d|:", bufin[ii++],ii);
//								printf("SENS_RES=0x%02X%02X |%d|, ",bufin[ii],bufin[ii+1],ii);ii++;ii++;
//								printf("SEL_RES=0x%02X |%d|, ",bufin[ii++],ii);
//								printf("NFCIDLength=%d |%d|, ",bufin[ii++],ii);
//								printf("NFCID= ");
//								iii=0;
//								while(iii<bufin[ii-1])
//								{
//									printf("%02X |%d|",bufin[ii+iii], ii+iii);
//									iii++;
//									if(iii<bufin[ii-1]){printf(":");}
//								}
//								ii=ii+iii;
//								printf("\n");
//								i++;
//							}

						}
						//Just a debugging thing for printing out the contents of valid packets.
						//int i=0;while(i<(len-1)){printf("0x%02X, ",buffin[i++]);}printf("\n");
					}
					else if(targetcallback==0x7F)
					{
//						printf("Received error packet 0x7F with zero size.\n");
					}else{
//						printf("ERROR: Got unknown %d byte packet with tfi=0x%02X!\n",lengthchecksum-1,targetcallback);
					}

				}
				break;
		}
		callbacktimeout++;
		usleep(0.001);
	}
}


void sendpassivecommand(int cycle_ms){
	static int cycle_tick;
	cycle_tick++;
	if(cycle_tick >= cycle_ms){
		unsigned char PssvTg[] = {PN532_COMMAND_INLISTPASSIVETARGET, 0x02, 0x00};
		sendpacket(PssvTg,sizeof PssvTg / sizeof *PssvTg); //InListPassiveTarget -- The goal of this command is to detect as many targets (maximum MaxTg) as possible (max two) in passive mode.
		cycle_tick = 0;
		callbackstatus();
	}
}

void sendrfregulationtest(){
	unsigned char RFreg[] = {PN532_COMMAND_RFREGULATIONTEST, PN532_MIFARE_ISO14443A};
    sendpacket(RFreg,sizeof RFreg / sizeof *RFreg);
    callbackstatus();
}

void sendreadversion(){
	unsigned char Vers[] = {PN532_COMMAND_GETFIRMWAREVERSION};
	sendpacket(Vers,sizeof Vers / sizeof *Vers);//Read the version out of the PN532 chip.
	callbackstatus();
}

void sendgetstatus(){
	unsigned char Stts[] = {PN532_COMMAND_GETGENERALSTATUS};
	sendpacket(Stts,sizeof Stts / sizeof *Stts); //Get current status.
	callbackstatus();
}

void sendsetscanning(){
	unsigned char WaitPgk[] = {PN532_COMMAND_RFCONFIGURATION, PN532_RFCONFIG_RETURN_DELAY, PN532_RFCONFIG_ACTIVE_MODE, 0x01, 0x10};
	sendpacket(WaitPgk,sizeof WaitPgk / sizeof *WaitPgk);
	//Max retries - last byte is for passive: 0=1 try, 1=2 tries, 254=255 tries, 0xFF=infinite retries.
	//If last byte is 0xFF, then unit starts scanning for cards indefinitely. As soon as it detects a card, it stops scanning and returns info.
	//If last byte is less than 0xFF, it tries scans and as soon as it finds a card returns info on it and stops trying, but
	//if it never finds a card in the specified number of retries, it gives up and returns 0x4B, 0x00 (Cards found: Zero.)
	callbackstatus();
}

void pn532_begin(){
	static int initcase;
	while(initcase != PN532_DONE_INIT_STATE){
		switch (initcase){
			case PN532_RF_REGULATION_STATE:	sendrfregulationtest(); initcase = PN532_READ_VERSION_STATE; break;
			case PN532_READ_VERSION_STATE:	sendreadversion(); initcase = PN532_GET_STATUS_STATE; break;
			case PN532_GET_STATUS_STATE:	sendgetstatus(); initcase = PN532_SET_SCANNING_STATE; break;
			case PN532_SET_SCANNING_STATE:	sendsetscanning(); initcase = PN532_DONE_INIT_STATE; break;
		}
	}
}

int main(void)
{
	pn532_init();
    pn532_begin();

    while(1)
    {
        //LOOP CYCLE PN532
    	sendpassivecommand(PASSIVE_COMMAND_CYCLE_MS);
        usleep(1);
    }



    return(0);
}

