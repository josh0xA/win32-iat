#pragma once
#ifndef __DUMPER_H
#define __DUMPER_H

#include "includes.h"

#define PE_DEFAULT_IMAGE_BASE 0x400000

namespace DMP {

	class Handler { // offset handler (RVA -> DWORD value)

	private:
		int m_nTotalSections;
		WORD m_wSections;
		PIMAGE_SECTION_HEADER m_pSectionHeader; 

	public:
		DWORD Win32SetRvaToDwordOffset(IMAGE_NT_HEADERS32* m_pNtHeader, DWORD m_dwRVA);
	};

	class Win32Dumper {

	private:
		DWORD* m_lpdwAddr;
		DWORD m_dwName, m_dwTest;
		BOOL m_isIATFound = FALSE;
		LPVOID m_lpMap;

	public:
		BOOL Win32DumpExecutableInformation();
	};



}








#endif 
