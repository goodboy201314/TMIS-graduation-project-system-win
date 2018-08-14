
// TMIS-Registration.h : PROJECT_NAME 应用程序的主头文件
//

#pragma once

#ifndef __AFXWIN_H__
	#error "在包含此文件之前包含“stdafx.h”以生成 PCH 文件"
#endif

#include "resource.h"		// 主符号
#include "mysql.h"
#include <winsock.h>
#include <stdlib.h>
//#pragma comment(lib,"libmysql.lib") 

// QR code 需要包含的头文件
#include "qrencode/qrencode.h"
#pragma warning(disable:4099)
#pragma comment(lib,"qrencode/qrencode.lib")

#include "gmp.h"
#pragma comment(lib,"libgmp.dll.lib")

// 包含加密解密库
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
// 有关此类的实现，请参阅 TMIS-Registration.cpp
//

class CTMISRegistrationApp : public CWinApp
{
public:
	CTMISRegistrationApp();

// 重写
public:
	virtual BOOL InitInstance();

// 实现

	DECLARE_MESSAGE_MAP()
};

extern CTMISRegistrationApp theApp;