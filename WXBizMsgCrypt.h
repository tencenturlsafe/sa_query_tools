
#pragma once

#include <string>
#include <stdint.h>
//#include "tinyxml2/tinyxml2.h"

namespace EncryptAndDecrypt {

static const unsigned int kAesKeySize = 32;
static const unsigned int kAesIVSize = 16;
static const unsigned int kEncodingKeySize = 16;//43;
static const unsigned int kRandEncryptStrLen = 16;
static const unsigned int kMsgLen = 4;
static const unsigned int kMaxBase64Size = 1000000000;
enum  WXBizMsgCryptErrorCode
{
    WXBizMsgCrypt_OK = 0,
    WXBizMsgCrypt_ValidateSignature_Error = -40001,
    WXBizMsgCrypt_ParseXml_Error = -40002,
    WXBizMsgCrypt_ComputeSignature_Error = -40003,
    WXBizMsgCrypt_IllegalAesKey = -40004,
    WXBizMsgCrypt_ValidateAppid_Error = -40005,
    WXBizMsgCrypt_EncryptAES_Error = -40006,
    WXBizMsgCrypt_DecryptAES_Error = -40007,
    WXBizMsgCrypt_IllegalBuffer = -40008,
    WXBizMsgCrypt_EncodeBase64_Error = -40009,
    WXBizMsgCrypt_DecodeBase64_Error = -40010,
    WXBizMsgCrypt_GenReturnXml_Error = -40011,
};

class WXBizMsgCrypt
{
public:
    //���캯��
    // @param sEncodingAESKey: ���õ�EncodingAESKey
    WXBizMsgCrypt(const std::string &sEncodingAESKey)
                    :m_sEncodingAESKey(sEncodingAESKey)
                    {   }
    
    // @param sEncryptData: ���ģ���ӦPOST���������
    // @param sMsg: ���ܺ��ԭ�ģ���return����0ʱ��Ч
    // @return: �ɹ�0��ʧ�ܷ��ض�Ӧ�Ĵ�����
    int DecryptMsg(const std::string &sPostData,
                    std::string &sMsg);
            
            
    //�����ںŻظ��û�����Ϣ���ܴ��
    // @param sOrgMsg:�������ַ���
    // @param sEncryptMsg: ���ܺ�Ŀ���ֱ�ӻظ��û������ģ�����msg_signature, timestamp, nonce, encrypt��xml��ʽ���ַ���,
    //                      ��return����0ʱ��Ч
    // return���ɹ�0��ʧ�ܷ��ض�Ӧ�Ĵ�����
    int EncryptMsg(const std::string &sOrgMsg,
                    std::string &sEncryptMsg);
private:
    std::string m_sEncodingAESKey;

private:
    // AES CBC
    int AES_CBCEncrypt( const char * sSource, const uint32_t iSize,
            const char * sKey, unsigned int iKeySize, std::string * poResult );
    
    int AES_CBCEncrypt( const std::string & objSource,
            const std::string & objKey, std::string * poResult );
    
    int AES_CBCDecrypt( const char * sSource, const uint32_t iSize,
            const char * sKey, uint32_t iKeySize, std::string * poResult );
    
    int AES_CBCDecrypt( const std::string & objSource,
            const std::string & objKey, std::string * poResult );
    
    //base64
    int EncodeBase64(const std::string sSrc, std::string & sTarget);
    
    int DecodeBase64(const std::string sSrc, std::string & sTarget);

};

}

