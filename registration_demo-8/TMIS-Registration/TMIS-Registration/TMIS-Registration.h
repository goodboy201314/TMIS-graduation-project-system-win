
// TMIS-Registration.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������
#include "mysql.h"
#include <winsock.h>
#include <stdlib.h>
//#pragma comment(lib,"libmysql.lib") 

// QR code ��Ҫ������ͷ�ļ�
#include "qrencode/qrencode.h"
#pragma warning(disable:4099)
#pragma comment(lib,"qrencode/qrencode.lib")

#include "gmp.h"
#pragma comment(lib,"libgmp.dll.lib")

// �������ܽ��ܿ�
//#include <openssl/aes.h>
//#include "tmis_enc_denc.h"
#pragma comment(lib,"libeay32.lib")
//#pragma comment(lib,"ssleay32.lib")
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

// CTMISRegistrationApp: 
// �йش����ʵ�֣������ TMIS-Registration.cpp
//

class CTMISRegistrationApp : public CWinApp
{
public:
	CTMISRegistrationApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CTMISRegistrationApp theApp;