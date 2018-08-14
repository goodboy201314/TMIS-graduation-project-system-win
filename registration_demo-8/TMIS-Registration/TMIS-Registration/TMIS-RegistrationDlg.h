
// TMIS-RegistrationDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"


// CTMISRegistrationDlg �Ի���
class CTMISRegistrationDlg : public CDialogEx
{
// ����
public:
	CTMISRegistrationDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TMISREGISTRATION_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
