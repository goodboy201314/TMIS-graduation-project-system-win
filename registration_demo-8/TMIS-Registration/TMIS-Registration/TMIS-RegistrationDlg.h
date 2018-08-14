
// TMIS-RegistrationDlg.h : 头文件
//

#pragma once
#include "afxwin.h"


// CTMISRegistrationDlg 对话框
class CTMISRegistrationDlg : public CDialogEx
{
// 构造
public:
	CTMISRegistrationDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TMISREGISTRATION_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedBtnfinish();
	afx_msg void OnBnClickedBtngeninfo();
	afx_msg void OnBnClickedBtnckuser();
	CStatic m_qrPicture;
	CStatic m_picture;
	CString text_ip;
	CString text_port;
	CString text_trans;
};
