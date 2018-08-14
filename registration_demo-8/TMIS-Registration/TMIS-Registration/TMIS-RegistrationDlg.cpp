
// TMIS-RegistrationDlg.cpp : 实现文件
//


#include "stdafx.h"
#include "TMIS-Registration.h"
#include "TMIS-RegistrationDlg.h"
#include "afxdialogex.h"
#pragma warning(disable:4996)

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

////// 相关参数
const char split_char_key_agreement[10] = "tmis"; // "BB";//
#define len_split_char_key_agreement strlen(split_char_key_agreement)
char secret_key[1024] = "[1431701601476568613993916354570581999234296492200903722689435064403093647543786410908775082711468637043556899660242354405958838182001143332963964057164995, 2090155367049341967001403718508984758041491186470976194749112114432660174858545929700501744055058603817941671083836419094294404012587185432039026958345540]";
char public_key[1024] = "[8779246804865256595845410635551148521227644044548861627285453536743878386166265446937141101008408588690674901331738586548621281816777149434943936565852561, 5462710688655103662240594520449922001027729122965123487994410536107298056563228514615559984791707466524546778752823276552092115399599325705605166751646997]";
char str_back_user[4096];



// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CTMISRegistrationDlg 对话框



CTMISRegistrationDlg::CTMISRegistrationDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_TMISREGISTRATION_DIALOG, pParent)
	, text_ip(_T(""))
	, text_port(_T(""))
	, text_trans(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CTMISRegistrationDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	//DDX_Control(pDX, IDC_PicQRCode, m_qrPicture);
	//DDX_Control(pDX, IDC_qrPicture, m_picture);
	DDX_Text(pDX, IDC_EDIT1, text_ip);
	DDX_Text(pDX, IDC_EDIT2, text_port);
	DDX_Text(pDX, IDC_EDIT3, text_trans);
}

BEGIN_MESSAGE_MAP(CTMISRegistrationDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BtnFinish, &CTMISRegistrationDlg::OnBnClickedBtnfinish)
	ON_BN_CLICKED(IDC_BtnGenInfo, &CTMISRegistrationDlg::OnBnClickedBtngeninfo)
	ON_BN_CLICKED(IDC_BtnCkUser, &CTMISRegistrationDlg::OnBnClickedBtnckuser)
END_MESSAGE_MAP()


// CTMISRegistrationDlg 消息处理程序

BOOL CTMISRegistrationDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CTMISRegistrationDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CTMISRegistrationDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CTMISRegistrationDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


/*******************************************************************
 * 函数名称：insert2db
 * 传入参数：uid，此次要插入db_tmis数据库tmis_userinof表中的数据
 *           ip，数据库的ip地址
 *           db,数据库的名字
 * 主要功能：将传入的参数uid插入到数据库中
 * 返回值： 0， 插入成功
 *         -1,  插入失败，该用户数据库已经存在
 *         -2， 插入失败，数据库初始化失败
 *         -3,  插入失败，数据库连接失败
 *         -4,  插入失败，其他原因
 *******************************************************************/
int insert2db(char *uid,char *ip,char *db)
{
	MYSQL    *con;
	char     dbuser[30] = "xiangbin";
	char     dbpasswd[30] = "xb921207"; 
	
	char     dbname[50] = { 0 }; // "db_tmis";
	char     dbip[30] = { 0 };  // "192.168.2.8";

	char     sql[300];
	int      ret = -4;

	strcpy(dbname, db);
	strcpy(dbip, ip);

	// 0.此次插入语句
	sprintf_s(sql, "insert into tmis_userinfo (hashid) values (\'%s\')", uid);

	// 1.初始化
	con = mysql_init(NULL);
	if (NULL == con)
	{
		//MessageBoxA(NULL, "mysql_init is failed!", "提示", MB_OK);
		ret = -2;
		goto end_of_insert2db;
	}

	// 2.连接数据
	if (NULL == mysql_real_connect(con, dbip, dbuser, dbpasswd, dbname, 0, NULL, 0))
	{
		//MessageBoxA(NULL, "mysql_real_connect is failed!", "提示", MB_OK);
		ret = -3;
		goto end_of_insert2db;
	}
	
	// 3.插入数据
	mysql_query(con, "set names utf8");
	if (0 == mysql_query(con, sql))
	{  // 用户不存在，可以插入
		//MessageBoxA(NULL, "insert is successfull!", "提示", MB_OK);
		ret = 0;
		goto end_of_insert2db;
	}
	
	// 插入失败
	int errornum = mysql_errno(con);
	if (1062 == errornum)
	{
		//MessageBoxA(NULL, "该用户名已经存在！", "提示", MB_OK);
		ret = -1;
		goto end_of_insert2db;
	}
	

end_of_insert2db:
	// 4.关闭数据库
	mysql_close(con);
	return ret;
}

void CTMISRegistrationDlg::OnBnClickedBtnfinish()
{
	// TODO: 在此添加控件通知处理程序代码
	//insert2db("1234567890");
	//insert2db("0123456789");
	exit(0);
}

/*******************************************************************
* 函数名称：genqrcode
* 传入参数：szSourceSring，字符串
* 主要功能：将传入的字符串生成二维码
* 返回值： 0， 成功
*         -1,  失败
*******************************************************************/
int genqrcode(char *szSourceSring)
{
	// char*           szSourceSring = "12553355fdfdfdddddddd哈喽你好这个是二维码";
	unsigned int    unWidth, x, y, l, n, unWidthAdjusted, unDataBytes;
	unsigned char*  pRGBData, *pSourceData, *pDestData;
	QRcode*         pQRC;
	FILE*           f;

	// 生成二维码
	if (pQRC = QRcode_encodeString(szSourceSring, 1, QR_ECLEVEL_L, QR_MODE_8, 1))
	{
		unWidth = pQRC->width;
		unWidthAdjusted = unWidth * 8 * 3;
		if (unWidthAdjusted % 4)
			unWidthAdjusted = (unWidthAdjusted / 4 + 1) * 4;
		unDataBytes = unWidthAdjusted * unWidth * 8;
		// Allocate pixels buffer
		if (!(pRGBData = (unsigned char*)malloc(unDataBytes)))
		{
			MessageBoxA(NULL, "二维码生成失败!", "提示", MB_OK);
			return -1;
			// exit(-1);
		}
		// Preset to white
		memset(pRGBData, 0xff, unDataBytes);
		// Prepare bmp headers
		BITMAPFILEHEADER kFileHeader;
		kFileHeader.bfType = 0x4d42;  // "BM"
		kFileHeader.bfSize = sizeof(BITMAPFILEHEADER) +
			sizeof(BITMAPINFOHEADER) +
			unDataBytes;
		kFileHeader.bfReserved1 = 0;
		kFileHeader.bfReserved2 = 0;
		kFileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) +
			sizeof(BITMAPINFOHEADER);
		BITMAPINFOHEADER kInfoHeader;
		kInfoHeader.biSize = sizeof(BITMAPINFOHEADER);
		kInfoHeader.biWidth = unWidth * 8;
		kInfoHeader.biHeight = -((int)unWidth * 8);
		kInfoHeader.biPlanes = 1;
		kInfoHeader.biBitCount = 24;
		kInfoHeader.biCompression = BI_RGB;
		kInfoHeader.biSizeImage = 0;
		kInfoHeader.biXPelsPerMeter = 0;
		kInfoHeader.biYPelsPerMeter = 0;
		kInfoHeader.biClrUsed = 0;
		kInfoHeader.biClrImportant = 0;
		// Convert QrCode bits to bmp pixels
		pSourceData = pQRC->data;
		for (y = 0; y < unWidth; y++)
		{
			pDestData = pRGBData + unWidthAdjusted * y * 8;
			for (x = 0; x < unWidth; x++)
			{
				if (*pSourceData & 1)
				{
					for (l = 0; l < 8; l++)
					{
						for (n = 0; n < 8; n++)
						{
							//this is qrcode color default black
							*(pDestData + n * 3 + unWidthAdjusted * l) = 0x00;
							*(pDestData + 1 + n * 3 + unWidthAdjusted * l) = 0;
							*(pDestData + 2 + n * 3 + unWidthAdjusted * l) = 0;
						}
					}
				}
				pDestData += 3 * 8;
				pSourceData++;
			}
		}
		//把图片字节数据copy到字节数组中
		int dwSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + unDataBytes * sizeof(unsigned char);
		unsigned char* imgbytes = new unsigned char[dwSize] {0};
		memcpy(imgbytes, &kFileHeader, sizeof(BITMAPFILEHEADER));
		memcpy(imgbytes + sizeof(BITMAPFILEHEADER), &kInfoHeader, sizeof(BITMAPINFOHEADER));
		memcpy(imgbytes + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER), pRGBData, sizeof(unsigned char)*unDataBytes);
		//记得释放
		delete[] imgbytes;
		// Output the bmp file
		if (!(fopen_s(&f, "temp.bmp", "wb")))
		{
			fwrite(&kFileHeader, sizeof(BITMAPFILEHEADER), 1, f);
			fwrite(&kInfoHeader, sizeof(BITMAPINFOHEADER), 1, f);
			fwrite(pRGBData, sizeof(unsigned char), unDataBytes, f);
			fclose(f);
		}
		else
		{
			//printf("Unable to open file");
			MessageBoxA(NULL, "二维码生成失败!", "提示", MB_OK);
			return -1;
			//exit(-1);
		}
		// Free data
		free(pRGBData);
		QRcode_free(pQRC);
	}
	else
	{
		//printf("NULL returned");
		MessageBoxA(NULL, "二维码生成失败!", "提示", MB_OK);
		return -1;
		//exit(-1);
	}

	MessageBoxA(NULL, "二维码生成成功!", "提示", MB_OK);

	return 0;
}

/*********************************************************************
 * 函数名称：OnBnClickedBtngeninfo 
 * 传入参数：无
 * 主要功能：生成用户注册的返回参数，并且以二维码的方式显示在界面上
 * 返回值：  无
 **********************************************************************/
float leftMargin = 355;   // 二维码图片距离左端的距离
float topMargin = 100;    // 二维码图片距离上端的距离
float wh = 200;         // 二维码图片的长度和宽度
void CTMISRegistrationDlg::OnBnClickedBtngeninfo()
{
	// TODO: 在此添加控件通知处理程序代码
	int ret = genqrcode(str_back_user);
	if (0 == ret)
	{ // 二维码生成成功，载入二维码
		CDC      *cDC = this->GetDC();   //获得当前窗口的DC  
		CImage   image;
		image.Load(_T("temp.bmp"));

		//image.Draw(*cDC, leftMargin, topMargin, image.GetWidth(), image.GetHeight());
		image.Draw(*cDC, leftMargin, topMargin, wh, wh);
		image.Destroy();
	}
	else
	{
		MessageBoxA(NULL, "二维码生成失败，请重新尝试!!!", "提示", MB_OK);
	}
	
}



char* BigMul(char* m, char* n)
{
	int i, j;
	char* pt = NULL;
	mpz_t s, p, q;
	mpz_init(s);
	i = mpz_init_set_str(p, m, 10);//get number from m
	j = mpz_init_set_str(q, n, 10);
	//printf("i,j:%d,%d\n",i,j);
	gmp_printf("%Zd\n%Zd\n", p, q);
	mpz_addmul(s, p, q);//calculate result
						//gmp_printf("the result is %Zd\n",s);
	pt = mpz_get_str(pt, 10, s);//get string from s
								//printf("%s\n",pt);
	mpz_clear(s);
	return pt;
}
void test()
{
	char* p = NULL;
	char *a = "123";
	char *b = "234";
	p = BigMul(a, b);
	//printf("the result is %s.\n", p);
	char ss[1024] = { 0 };
	sprintf_s(ss,"the result is %s.\n", p);
	MessageBoxA(NULL, ss, "提示", MB_OK);

}

////////////////////////////////////////////////////////////////////////////////////
/**
* @brief 获取p指向的数组的长度
* @param p  传入参数，字符数组
* @return    返回>=0，数组长度；-1，失败
* @note   p指向的数组以\0\0\0结尾
*/
int get_length(const unsigned char *p)
{
	if (!p) return -1;
	int len = 0;
	while (1)
	{
		if (p[len] == 0 && p[len + 1] == 0 && p[len + 2] == 0)  return len;

		len++;
	}

	return -1;
}


/**
* @brief aes加密--aes128
* @param in  传入参数，带加密的字符串
* @param key 传入参数，密钥
* @param out 传出参数，加密后的结果
* @return    返回0，表示加密成功；否则，加密失败
*/
int aes_encrypt(const unsigned char* in, const unsigned char* key, unsigned char* out)
{
	if (!in || !key || !out) return -1;

	int i;
	unsigned char iv[AES_BLOCK_SIZE]; //加密的初始化向量
	for (i = 0; i < AES_BLOCK_SIZE; ++i) //iv一般设置为全0,可以设置其他，但是加密解密要一样就行
		iv[i] = 0;

	AES_KEY aes;
	if (AES_set_encrypt_key(key, 128, &aes) < 0)
	{
		return 0;
	}
	int len = strlen((char *)in); //这里的长度是char*in的长度，但是如果in中间包含'\0'字符的话

								  //那么就只会加密前面'\0'前面的一段，所以，这个len可以作为参数传进来，记录in的长度

								  //至于解密也是一个道理，光以'\0'来判断字符串长度，确有不妥，后面都是一个道理。
	AES_cbc_encrypt(in, out, len, &aes, iv,
		AES_ENCRYPT);


	return 0;
}


/**
* @brief aes加密--aes128
* @param in  传入参数，带解密的字符串
* @param key 传入参数，密钥(128bits)
* @param out 传出参数，解密后的结果
* @return    返回0，表示解密成功；否则，解密失败
*/
int aes_decrypt(const unsigned char* in, const unsigned char* key, unsigned char* out)
{
	if (!in || !key || !out) return -1;

	int i;
	unsigned char iv[AES_BLOCK_SIZE]; //加密的初始化向量
	for (i = 0; i < AES_BLOCK_SIZE; ++i) //iv一般设置为全0,可以设置其他，但是加密解密要一样就行
		iv[i] = 0;


	AES_KEY aes;
	if (AES_set_decrypt_key(key, 128, &aes) < 0)
	{
		return 0;
	}
	int len = strlen((char *)in);
	AES_cbc_encrypt(in, out, len, &aes, iv,
		AES_DECRYPT);

	return 0;
}


/*******************************************************************************
打开/usr/include/openssl/md5.h这个文件我们可以看到一些函数:

1.初始化 MD5 Contex, 成功返回1,失败返回0
int MD5_Init(MD5_CTX *c);

2.循环调用此函数,可以将不同的数据加在一起计算MD5,成功返回1,失败返回0
int MD5_Update(MD5_CTX *c, const void *data, size_t len);

3.输出MD5结果数据,成功返回1,失败返回0
int MD5_Final(unsigned char *md, MD5_CTX *c);

=====> MD5_Init,MD5_Update,MD5_Final三个函数的组合,直接计算出MD5的值

unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);

内部函数,不需要调用
void MD5_Transform(MD5_CTX *c, const unsigned char *b);
******************************************************************************/

/**
* @brief md5生成报文（结果是128bits,也就是16bytes）
* @param in  传入参数，生成报文摘要的字符串
* @param out 传出参数，结果(传入之前先初始化好)
* @return    返回0，表示成功；否则，失败
*/
int md5(const  unsigned char* in, unsigned char* out)
{
	if (!in || !out) return -1;  // 参数检查

	MD5_CTX ctx;
	//    unsigned char outmd[16];
	//    memset(outmd,0,sizeof(outmd));
	//	  memset(out,0,outlen);  
	int len = strlen((char *)in);

	MD5_Init(&ctx);
	MD5_Update(&ctx, in, len);
	MD5_Final(out, &ctx);

	return 0;
}


/*******************************************************************************
SHA1算法是对MD5算法的升级,计算结果为20字节(160位)，使用方法如下：
打开/usr/include/openssl/sha.h这个文件我们可以看到一些函数

1.初始化 SHA Contex, 成功返回1,失败返回0
int SHA_Init(SHA_CTX *c);

2.循环调用此函数,可以将不同的数据加在一起计算SHA1,成功返回1,失败返回0
int SHA_Update(SHA_CTX *c, const void *data, size_t len);

3.输出SHA1结果数据,成功返回1,失败返回0
int SHA_Final(unsigned char *md, SHA_CTX *c);

====> SHA_Init,SHA_Update,SHA_Final三个函数的组合,直接计算出SHA1的值

unsigned char *SHA(const unsigned char *d, size_t n, unsigned char *md);

内部函数,不需要调用
void SHA_Transform(SHA_CTX *c, const unsigned char *data);

另外：上面的SHA可以改为SHA1，SHA224，SHA256，SHA384，SHA512就可以实现多种加密了
*********************************************************************************/

/**
* @brief sha1生成报文（结果是128bits,也就是16bytes）
* @param in  传入参数，生成报文摘要的字符串
* @param out 传出参数，结果(传入之前先初始化好)
* @return    返回0，表示成功；否则，失败
*/
int sha1(const  unsigned char* in, unsigned char* out)
{
	if (!in || !out) return -1;	// 参数检查

	SHA_CTX stx;
	//unsigned char outmd[20];//注意这里的字符个数为20

	int len = strlen((char *)in);
	// memset(out,0,outlen));

	SHA1_Init(&stx);
	SHA1_Update(&stx, in, len);
	SHA1_Final(out, &stx);


	return 0;
}

/**
* @brief 将字符数组转化成16进制输出
* @param in  传入参数，字符数组
* @param len 字符数组长度
* @return    返回0，表示成功；否则，失败
*/
int printhex(const unsigned char* in, const int len)
{
	if (!in) return -1;	// 参数检查

	int i;
	for (i = 0; i<len; i++)
	{
		printf("%02X", in[i]);
	}
	printf("\n");

	return 0;
}

/**
* @brief 将字节流转化成16进制输出到数组中
* @param in  传入参数，字符数组
* @param out 传出的字符数组
* @param len 输入字符数组长度
* @return    返回0，表示成功；否则，失败
*/
int bytes2hex(const unsigned char* in, const int len, char *out)
{
	if (!in || !out) return -1;

	int i;
	unsigned char highByte, lowByte;
	for (i = 0; i < len; i++)
	{
		highByte = in[i] >> 4;
		lowByte = in[i] & 0x0f;


		highByte += 0x30;


		if (highByte > 0x39)
			out[i * 2] = highByte + 0x07;
		else
			out[i * 2] = highByte;


		lowByte += 0x30;
		if (lowByte > 0x39)
			out[i * 2 + 1] = lowByte + 0x07;
		else
			out[i * 2 + 1] = lowByte;
	}


	return 0;

}


/**
* @brief 将16进制转化成字节流
* @param in  传入参数，字符数组
* @param out 传出的字符数组
* @param len 输入字符数组长度
* @return    返回0，表示成功；否则，失败
*/
int hex2bytes(const char* in, int len, unsigned char* out)
{
	if (!in || !out) return -1;

	int i;
	unsigned char highByte, lowByte;
	//memset(out,0,outlen);

	for (i = 0; i < len; i += 2)
	{
		highByte = toupper(in[i]);
		lowByte = toupper(in[i + 1]);


		if (highByte > 0x39)
			highByte -= 0x37;
		else
			highByte -= 0x30;


		if (lowByte > 0x39)
			lowByte -= 0x37;
		else
			lowByte -= 0x30;


		out[i / 2] = (highByte << 4) | lowByte;
	}

	return 0;
}




/////////////////////////////////////////////////////////////////////////////////////
void test2()
{
	char ss[1024] = { 0 };

	unsigned char in[30] = "xiangbin is a good boy!";
	unsigned char key[17] = "0123456789123456";
	unsigned char out[100];
	unsigned char out2[100];
	unsigned char out3[100];
	char outStr[100] = { 0 };

	//int aes_decrypt(const char* in, const char* key, char* out)
	//int aes_decrypt(const char* in, const char* key, char* out)
	sprintf_s(ss,"测试aes....\n");
	MessageBoxA(NULL, ss, "提示", MB_OK);
	memset(out, 0, sizeof(out));
	memset(out2, 0, sizeof(out2));
	aes_encrypt(in, key, out);
	// int bytes2hex(const unsigned char* in, const int len, char *out);
	bytes2hex(out, strlen((char *)out), outStr);
	sprintf_s(ss,"aes加密输出1：%s\n", outStr);
	MessageBoxA(NULL, ss, "提示", MB_OK);
	

	// int hex2bytes(const char* in, int len,unsigned char* out);
	memset(out3, 0, sizeof(out3));
	hex2bytes(outStr, strlen(outStr), out3);

	aes_decrypt(out3, key, out2);
	sprintf_s(ss,"aes解密输出：%s\n", out2);


	MessageBoxA(NULL, ss, "提示", MB_OK);

}

void test3()
{
	char ss[1024] = { 0 };
	char outStr[100] = { 0 };

	unsigned char in[30] = "xiangbin is a good boy!";
	unsigned char out[100];
	
	sprintf_s(ss,"\n测试md5....\n");
	MessageBoxA(NULL, ss, "提示", MB_OK);
	memset(out, 0, sizeof(out));
	md5(in, out);
	bytes2hex(out, strlen((char *)out), outStr);
	sprintf_s(ss,"md5加密输出：%s\n",outStr);
	MessageBoxA(NULL, ss, "提示", MB_OK);

	//int sha1(const unsigned char* in, unsigned char* out);
	sprintf_s(ss,"\n测试sha1...\n");
	MessageBoxA(NULL, ss, "提示", MB_OK);
	memset(out, 0, sizeof(out));
	sha1(in, out);
	memset(outStr, 0, sizeof(outStr));
	bytes2hex(out, strlen((char *)out), outStr);

	sprintf_s(ss,"sha1加密输出：%s\n",outStr);
	MessageBoxA(NULL, ss, "提示", MB_OK);
	
}

/// 检测用户是否是注册过的
void CTMISRegistrationDlg::OnBnClickedBtnckuser()
{// text_ip,text_port,text_trans
	// 192.168.2.8     db_tmis
	char str_ip[50] = { 0 };   //192.168.2.8:8888
	char str_db[30] = { 0 };
	char trans[1024] = { 0 };
	
	// 获取界面上的值
	UpdateData(true);
	CStringA ip_a(text_ip);       //将宽码转化为ascii
	CStringA port_a(text_port);
	CStringA trans_a(text_trans);
	
	// 拷贝到数组中
	strcpy(str_ip, ip_a);
	strcpy(str_db, port_a);
	strcpy(trans, trans_a);

 
	//MessageBoxA(NULL, ip, "ip", MB_OK);
	//MessageBoxA(NULL, str_db, "数据库", MB_OK);
	//MessageBoxA(NULL, trans, "二维码信息", MB_OK);

/////// 将二维码分割
	char str_id[100] = { 0 };
	char str_HPWi[1024] = { 0 };

	char *p = strtok(trans, split_char_key_agreement);
	if (p) strcpy(str_id, p);
	p = strtok(NULL, split_char_key_agreement);
	if (p) strcpy(str_HPWi, p);
	//MessageBoxA(NULL, str_id, "提示", MB_OK);
	//MessageBoxA(NULL, str_HPWi, "提示", MB_OK);

///// 插入用户名之前，将用户名sha1一下
	unsigned char bytes_insert_user_id[1024] = { 0 };
	sha1((unsigned char *)str_id, bytes_insert_user_id);

	int l1 = get_length(bytes_insert_user_id);
	char str_insert_user_id[1024] = { 0 };
	bytes2hex(bytes_insert_user_id, l1,str_insert_user_id);


///// 连接数据库，插入该用户，根据返回值判断该用户名是否注册过
	int ret = insert2db(str_insert_user_id, str_ip, str_db);
	if (ret == 0)
	{
		MessageBoxA(NULL, "该用户名可用，并且已经插入用户数据库", "用户检测", MB_OK);
	}
	else if (ret == -1)
	{
		MessageBoxA(NULL, "失败，该用户数据库已经存在", "用户检测", MB_OK);
		return;
	}
	else if (ret == -3)
	{
		MessageBoxA(NULL, "失败，数据库连接失败", "用户检测", MB_OK);
		return;
	}
	else
	{
		MessageBoxA(NULL, "失败，其他原因", "用户检测", MB_OK);
		return;
	}


//// 生成二维码信息，返回给用户
////  1. 生成随机数m，这里要生成一个随机数种子，否则的话，每一次的随机数都是相同的	
	mpz_t m;
	mpz_init(m);
// void mpz_urandomb (mpz_t rop, gmp_randstate_t state, mp_bitcnt_t n)
//****** Generate a uniformly distributed random integer in the range 0 to 2n − 1, inclusive
// void gmp_randinit_mt (gmp randstate t state)
//***** Initialize state
// void gmp_randseed_ui (gmp randstate t state, unsigned long int seed)
	unsigned long int seed = (unsigned long int)time(NULL);
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, seed);
	mpz_urandomb(m, state, 100); 	// 产生小于2^100的随机数

// char * mpz_get_str (char *str, int base, mpz_t op)
	char str_m[1024] = { 0 };
	mpz_get_str(str_m, -16, m);  	// 将随机数m转化为16进制字符串，保存
	//printf("m = %s\n", str_m);
	//printf("m_len = %ld\n", strlen(str_m));
	//MessageBoxA(NULL, str_m, "str_m", MB_OK);

//// 2. 计算Ai
	int len1 = strlen(str_id);
	int len2 = strlen(secret_key);
	char *CONSTR1 = (char *)malloc(sizeof(char) * (len1 + len2) + 1); // ID || KS
	memset(CONSTR1, 0, len1 + len2 + 1);
	strncpy(CONSTR1, str_id, len1);
	strncpy(CONSTR1 + len1, secret_key, len2);
	//printf("CONSTR1 = %s\n", CONSTR1);
	unsigned char bytes_Ai[100] = { 0 };
	sha1((unsigned char *)CONSTR1, bytes_Ai);

//// 3. 计算	Bi
	// 	IDi || HPWi
	len1 = strlen(str_id);

	unsigned char bytes_HPWi[1024] = { 0 };
	hex2bytes(str_HPWi, strlen(str_HPWi), bytes_HPWi);
	len2 = strlen((char *)bytes_HPWi);
	char *CONSTR2 = (char *)malloc(sizeof(char) * (len1 + len2) + 1);
	memset(CONSTR2, 0, len1 + len2 + 1);
	memcpy(CONSTR2, str_id, len1);
	memcpy(CONSTR2 + len1, bytes_HPWi, len2);

	unsigned char bytes_temp1[1024] = { 0 };
	sha1((unsigned char*)CONSTR2, bytes_temp1);   // h( IDi || HPWi  )
												  // 转化成mpz_t类型，然后mod
	char str_temp1[1024] = { 0 };
	bytes2hex(bytes_temp1, strlen((char *)bytes_temp1), str_temp1);
	//printf("str_temp1 = %s\n", str_temp1);
	mpz_t mpz_temp1;
	mpz_init_set_str(mpz_temp1, str_temp1, 16);
	//gmp_printf("mpz_temp1 = %Zd\n", mpz_temp1);

	mpz_t mpz_res;
	mpz_init(mpz_res);
	//	void mpz_mod (mpz t r, mpz t n, mpz t d) [Function]
	//**** Set r to n mod d.
	mpz_mod(mpz_res, mpz_temp1, m);
	//gmp_printf("mpz_res = %Zd\n", mpz_res);  // h( IDi || HPWi  ) mod m
// 将mpz_res转化为字符串
//  char * mpz_get_str (char *str, int base, mpz t op);	
	char str_res[1024] = { 0 };
	mpz_get_str(str_res, -16, mpz_res);
	//printf("str_res = %s\n", str_res);
	unsigned char bytes_Bi[100] = { 0 };
	sha1((unsigned char *)str_res, bytes_Bi);   //  h ( h( IDi || HPWi  ) mod m )

//// 4. 计算Ci
//  unsigned char bytes_Ai[100]={0};    unsigned char bytes_HPWi[100]={0};  unsigned char bytes_Bi[100]={0};
/// 先将字节流数组转化为mpz_t,然后异或操作
	mpz_t mpz_Ai, mpz_HPWi, mpz_Bi;
	char str_temp2[1024] = { 0 };
	bytes2hex(bytes_Ai, strlen((char *)bytes_Ai), str_temp2);
	mpz_init_set_str(mpz_Ai, str_temp2, 16);  // mpz_Ai
	memset(str_temp2, 0, sizeof(str_temp2));
	bytes2hex(bytes_HPWi, strlen((char *)bytes_HPWi), str_temp2);
	mpz_init_set_str(mpz_HPWi, str_temp2, 16);  // mpz_HPWi
	memset(str_temp2, 0, sizeof(str_temp2));
	bytes2hex(bytes_Bi, strlen((char *)bytes_Bi), str_temp2);
	//printf("str_Bi = %s\n", str_temp2);
	char str_Bi[1024] = { 0 };
	strcpy(str_Bi, str_temp2);
	//MessageBoxA(NULL, str_Bi, "str_Bi", MB_OK);
	mpz_init_set_str(mpz_Bi, str_temp2, 16);  // mpz_Bi
//	void mpz_xor (mpz t rop, mpz t op1, mpz t op2)
//**** Set rop to op1 bitwise exclusive-or op2.
	mpz_t mpz_Ci;
	mpz_init(mpz_Ci);
	mpz_xor(mpz_Ci, mpz_Ai, mpz_HPWi);
	mpz_xor(mpz_Ci, mpz_Ci, mpz_Bi);
	char str_Ci[1024] = { 0 };
	mpz_get_str(str_Ci, -16, mpz_Ci);
	//printf("str_Ci = %s\n", str_Ci);
	//MessageBoxA(NULL, str_Ci, "str_Ci", MB_OK);

///// 连接字符串，并且返回给用户
	memset(str_back_user, 0, sizeof(str_back_user));
	strcat(str_back_user, str_Bi);
	strcat(str_back_user, split_char_key_agreement);
	strcat(str_back_user, str_Ci);
	strcat(str_back_user, split_char_key_agreement);
	strcat(str_back_user, str_m);
	strcat(str_back_user, split_char_key_agreement);
	strcat(str_back_user, public_key);
	strcat(str_back_user, split_char_key_agreement);

	MessageBoxA(NULL, str_back_user, "back_user", MB_OK);

	//// 清理使用到的变量
	mpz_clear(m);
	mpz_clear(mpz_temp1);
	mpz_clear(mpz_res);
	mpz_clear(mpz_Ai);
	mpz_clear(mpz_Bi);
	mpz_clear(mpz_HPWi);
	mpz_clear(mpz_Ci);
	free(CONSTR1);
	free(CONSTR2);



    //test();
	//test2();
	//test3();
}

