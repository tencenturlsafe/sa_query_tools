#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sstream>
#include <openssl/md5.h>
#include <stdio.h>

#include "inc/json.h"
#include "WXBizMsgCrypt.h"
#include "http_proto.h"
#include "Comm.h"
#include <iostream>

#define MAX_KEY_LEN 128
using namespace std;
static std::string getSignFromTimeStampKey(unsigned int uiTimeStamp, std::string strKey)
{
	char comkey[MAX_KEY_LEN] = {0};
	snprintf(comkey, MAX_KEY_LEN, "%u%s", uiTimeStamp, strKey.c_str());

	MD5_CTX ctx;
	unsigned char md[16] = {0};
	MD5_Init(&ctx);
	MD5_Update(&ctx, comkey, strlen(comkey));
	MD5_Final(md, &ctx);

	char buf[33]={'\0'};
	char tmp[3]={'\0'};
	for(int i = 8; i < 16; i++ )
	{
		snprintf(tmp, 3, "%02x", md[i]);
		strncat(buf, tmp, 3);
	}

	return buf;
}


struct in_addr* GetIpByHost(const char* pszHost, char *pszIp, int iMaxLen)
{
	struct hostent * host_addr = gethostbyname(pszHost);
	if (host_addr == NULL)
	{
		return 0;
	}

	struct in_addr *in = (struct in_addr *) host_addr->h_addr;

	if (pszIp != NULL)
	{
		char *sIp = inet_ntoa(*in);
		strncpy(pszIp, sIp, iMaxLen);
	}
	return in;
}
static int isValidIPAddr(char *sIP)
{
	u_int32_t uiIpAddress;
	if (NULL == sIP)
		return 0;

	if (strlen(sIP) < 7 || strlen(sIP) > 15)
		return 0;

	uiIpAddress = inet_addr(sIP);
	if (uiIpAddress == INADDR_NONE || uiIpAddress == INADDR_ANY)
		return 0;
	return 1;
}


int main(int argc, char *argv[])
{
	if(argc < 10)
	{
		fprintf(stderr,"Usage:%s version(1.0) host appid key port country province city type time\n", argv[0]);
		exit(1);
	}


	// get param
	std::string ip;
	// ip check and get
	if (0 == isValidIPAddr(argv[2]))
	{
		char szDestIp[20] =	{ 0 };
		GetIpByHost(argv[2], szDestIp, sizeof(szDestIp));
		ip = szDestIp;
	}
	else
	{
		ip = argv[2];
	}

	std::string version =  argv[1];
	int appid = atoi(argv[3]);
	string country = argv[6];
	string province = argv[7];
	string city = argv[8];
	int type = atoi(argv[9]);
	int time_long = atoi(argv[10]);
	time_t tnow = time(NULL);
	unsigned int startTime = tnow-time_long*60; 
	unsigned int endTime = tnow-5*60; 
	std::string strKey =  argv[4];
	// pack request
	std::string reqstr;
	Json::Value req;

	req["header"]["appid"] = Json::Value(appid);
	unsigned int uinow = tnow; // todo
	req["header"]["timeStamp"] = Json::Value(uinow);
	req["header"]["version"] = Json::Value(version);
	req["header"]["echostr"] = Json::Value("1234567890");
	req["header"]["reqid"] = Json::Value(12);
	std::string sign = getSignFromTimeStampKey(uinow, strKey);
	//printf("sign: %s\n", sign.c_str());
	req["header"]["sign"] = Json::Value(sign);


	Json::Value urllist;
	Json::Value urlattr;
	urlattr["type"] = Json::Value(type);
	urlattr["country"] = Json::Value(country);
	urlattr["province"] = Json::Value(province);
	urlattr["city"] = Json::Value(city);
	urlattr["startTime"] = Json::Value(startTime);
	urlattr["endTime"] = Json::Value(endTime);
	urllist.append(urlattr);

	Json::FastWriter fast_writer;
	std::string reqinfo = fast_writer.write(urllist);
	EncryptAndDecrypt::WXBizMsgCrypt crypt(strKey);
	std::string encrypt_reqinfo;
	crypt.EncryptMsg(reqinfo, encrypt_reqinfo);
	
	req["reqinfo"] = Json::Value(encrypt_reqinfo);

	reqstr = fast_writer.write(req);

	printf("request:\n%s\n", reqstr.c_str());
	cout<<"req:"<<"\n"<<req<<endl;

	// pack http, send request and recv response
	std::string strRespHeader;
	std::string strRespBody;
	//	    for(int i=0;i<20000;i++)
	{

		int ii = HttpPostRequest ( argv[2], atoi(argv[5]), "POST /", reqstr.c_str(), strRespHeader, strRespBody);
		if(ii !=0)
		{
			std::cout<<"tcp failed! continue..."<<std::endl;
			//continue;
		}
		
		Json::Reader reader;
		Json::Value value;
		std::string decrypt;
		if(!reader.parse(strRespBody.c_str(), value))
		{
			cout<<"reader.parse.error!"<<endl;
			return 0;
		}
		cout<<"value:\n"<<value<<endl;
		std::string echostr = value["echostr"].asString();
		std::string msg = value["msg"].asString();
		int status = value["status"].asUInt();
		printf("status: %d\n", status);
		printf("msg: %s\n", msg.c_str());
		for(int i = 0; i < value["rsp"].size(); i++)
		{
			string rsp = value["rsp"][i].asString();
			crypt.DecryptMsg(rsp,decrypt);
			Json::Value body;
			reader.parse(decrypt.c_str(),body);
			cout<<"miwen:\n"<<rsp<<endl;
			cout<<"body:\n"<<body<<endl;
			string country,province,city;
			int type = body["type"].asUInt();
			country = body["country"].asString();
			province = body["province"].asString();
			city = body["city"].asString();
			string tableName = body["tableName"].asString();
			cout<<"table:"<<tableName<<endl;
			if(type == CITY_URL)
			{
				int ii=0;
				for(ii=0;ii<body["body"].size();ii++)
				{
					string ts = body["body"][ii]["time"].asString();
					string county = body["body"][ii]["county"].asString();
					int cnt = body["body"][ii]["cnt"].asUInt();
					cout<<country<<"\t"<<province<<"\t"<<city<<"\t"<<county<<"\t"<<cnt<<"\t"<<ts<<endl;
				}	
			
			}
			if(type == CITY_URL_TYPE)
			{
				int ii=0;
				for(ii=0;ii<body["body"].size();ii++)
				{
					string county = body["body"][ii]["county"].asString();
					string ts = body["body"][ii]["time"].asString();
					int cnt = body["body"][ii]["cnt"].asUInt();
					int eviltype = body["body"][ii]["eviltype"].asUInt();
					int evilclass = body["body"][ii]["evilclass"].asUInt();
					cout<<country<<"\t"<<province<<"\t"<<city<<"\t"<<county<<"\t"<<evilclass<<"\t"<<eviltype<<"\t"<<cnt<<"\t"<<ts<<endl;
				}	

			}
			if(type == CITY_MOBILE_VIRUS)
			{
				int ii=0;
				for(ii=0;ii<body["body"].size();ii++)
				{
					string county = body["body"][ii]["county"].asString();
					string ts = body["body"][ii]["time"].asString();
					
					string virustype = body["body"][ii]["virustype"].asString();
					int cnt = body["body"][ii]["cnt"].asUInt();
					cout<<country<<"\t"<<province<<"\t"<<city<<"\t"<<county<<"\t"<<virustype<<"\t"<<cnt<<"\t"<<ts<<endl;
				}	

			}
			if(type == CITY_PC_VIRUS)
			{
				int ii=0;
				for(ii=0;ii<body["body"].size();ii++)
				{
					string county = body["body"][ii]["county"].asString();
					string ts = body["body"][ii]["time"].asString();
					
					string virustype = body["body"][ii]["virustype"].asString();
					int cnt = body["body"][ii]["cnt"].asUInt();
					cout<<country<<"\t"<<province<<"\t"<<city<<"\t"<<county<<"\t"<<virustype<<"\t"<<cnt<<"\t"<<ts<<endl;
				}	

			}
			if(type == CITY_DDOS)
			{
				int ii=0;
				for(ii=0;ii<body["body"].size();ii++)
				{
					string county = body["body"][ii]["county"].asString();
					string ts = body["body"][ii]["time"].asString();
					
					int cnt = body["body"][ii]["cnt"].asUInt();
					cout<<country<<"\t"<<province<<"\t"<<city<<"\t"<<county<<"\t"<<cnt<<"\t"<<ts<<endl;
				}
			}
			if(type == CITY_DDOS_NEW)
			{
				int ii=0;
				for(ii=0;ii<body["body"].size();ii++)
				{
					string county = body["body"][ii]["county"].asString();
					string ts = body["body"][ii]["time"].asString();
					
					int cnt = body["body"][ii]["cnt"].asUInt();
					cout<<country<<"\t"<<province<<"\t"<<city<<"\t"<<county<<"\t"<<cnt<<"\t"<<ts<<endl;
				}
			}
			if(type == CITY_DDOS_IP)
			{
				int ii=0;
				for(ii=0;ii<body["body"].size();ii++)
				{
					string county = body["body"][ii]["county"].asString();
					string ts = body["body"][ii]["time"].asString();
					string ip = body["body"][ii]["ip"].asString();
					
					cout<<country<<"\t"<<province<<"\t"<<city<<"\t"<<county<<"\t"<<ip<<"\t"<<ts<<endl;
				}

			}
			if(type == CITY_DDOS_NEW_IP)
			{
				int ii=0;
				for(ii=0;ii<body["body"].size();ii++)
				{
					string county = body["body"][ii]["county"].asString();
					string ts = body["body"][ii]["time"].asString();
					string ip = body["body"][ii]["ip"].asString();
					
					cout<<country<<"\t"<<province<<"\t"<<city<<"\t"<<county<<"\t"<<ip<<"\t"<<ts<<endl;
				}

			}
			if(type == CITY_GOV_URL)
			{
				int ii=0;
				for(ii=0;ii<body["body"].size();ii++)
				{
					string host = body["body"][ii]["host"].asString();
					string title = body["body"][ii]["title"].asString();
					string ip = body["body"][ii]["ip"].asString();
					int evilclass = body["body"][ii]["evilclass"].asUInt();
					int eviltype = body["body"][ii]["eviltype"].asUInt();
					string url = body["body"][ii]["url"].asString();
					string ts = body["body"][ii]["time"].asString();
					
					cout<<country<<"\t"<<province<<"\t"<<city<<"\t"<<host<<"\t"<<title<<"\t"<<evilclass<<"\t"<<evilclass<<"\t"<<url<<"\t"<<ts<<endl;
				}
	
			}
			
		}

	}
	return 0;

}
