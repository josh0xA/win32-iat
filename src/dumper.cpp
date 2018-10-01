#include "dumper.h"

DWORD DMP::Handler::Win32SetRvaToDwordOffset(IMAGE_NT_HEADERS32* m_pNtHeader, DWORD m_dwRVA)
{
	m_pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	m_wSections = m_pNtHeader->FileHeader.NumberOfSections;

	for (m_nTotalSections = 0; m_nTotalSections < m_wSections; m_nTotalSections++)
	{
		if (m_pSectionHeader->VirtualAddress <= m_dwRVA)
			if ((m_pSectionHeader->VirtualAddress + m_pSectionHeader->Misc.VirtualSize) > m_dwRVA)
			{
				m_dwRVA -= m_pSectionHeader->VirtualAddress;
				m_dwRVA += m_pSectionHeader->PointerToRawData;

				return (m_dwRVA);
			}
		m_pSectionHeader++;
	}

	return 0;
}

BOOL DMP::Win32Dumper::Win32DumpExecutableInformation()
{
	DMP::Handler hd;
	PIMAGE_DOS_HEADER m_pDosHeader;
	PIMAGE_NT_HEADERS m_pImageHeader;

	PIMAGE_DATA_DIRECTORY m_pDataDirectory;
	PIMAGE_IMPORT_DESCRIPTOR m_pImportDescriptor;

	PIMAGE_THUNK_DATA32 m_pFirstThunk;
	PIMAGE_THUNK_DATA32 m_pOriginalFirstThunk;

	PIMAGE_IMPORT_BY_NAME m_pNameImg;
	PIMAGE_SECTION_HEADER m_pSectionHdr;

	char szFileName[MAX_PATH];
	std::cout << "File: ";
	std::cin >> szFileName;

	HANDLE m_hFile = CreateFile(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (m_hFile == INVALID_HANDLE_VALUE)
	{
		std::cerr << "CreateFile()\n"; 
		return FALSE;
	}

	HANDLE m_hFileMapper = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!m_hFileMapper)
	{
		std::cerr << "CreateFileMapping()\n";
		return FALSE;
	}

	HANDLE m_hViewMap = MapViewOfFile(m_hFileMapper, FILE_MAP_READ, 0, 0, 0);
	if (!m_hViewMap)
	{
		std::cerr << "MapViewOfFile()\n"; 
		return FALSE;
	}

	m_pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_hViewMap);
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cerr << "m_pDosHeader->e_magic\n";
		return FALSE;
	} else {
		std::cout << m_pDosHeader->e_magic << " (MZ-DOS) found, valid PE\nPE Header offset: 0x" << std::hex 
			<< m_pDosHeader->e_lfanew;

	}
	m_pImageHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)m_pDosHeader + m_pDosHeader->e_lfanew);
	if (m_pImageHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cerr << "m_pImageHeader->Signature\n";
		return FALSE;

	} else {
		std::cout << m_pImageHeader->Signature << " (PE00) signature found\nImageBase: 0x"
			<< std::hex << m_pImageHeader->OptionalHeader.ImageBase << '\n';
		if (m_pImageHeader->OptionalHeader.ImageBase != PE_DEFAULT_IMAGE_BASE) // 0x400000
			return FALSE;
		// CHECK THE SUBSYSTEMS(CLI, GUI)
		if (m_pImageHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
			std::cout << szFileName << " is CLI Based\n";
		else if (m_pImageHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI)
			std::cout << szFileName << " is GUI Based\n";
		else
			std::cout << szFileName << ": Unidentified\n";
	}
	std::cout << "Address of Entry Point-> 0x" << std::hex << m_pImageHeader->OptionalHeader.AddressOfEntryPoint;

	// GET THE ADDRESS OF THE DATA DIRECTORY OF THE FIRST IMAGE HEADER SEGMENT
	m_pDataDirectory = &m_pImageHeader->OptionalHeader.DataDirectory[1];
	m_pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((char*)m_pDosHeader + hd.Win32SetRvaToDwordOffset(
		m_pImageHeader, m_pDataDirectory->VirtualAddress));
	
	// HANDLE THUNK 32-BIT DATA
	m_pOriginalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>((char*)m_pDosHeader
		+ hd.Win32SetRvaToDwordOffset(m_pImageHeader, m_pImportDescriptor->OriginalFirstThunk)); 

	m_pSectionHdr = IMAGE_FIRST_SECTION(m_pImageHeader);
	// DUMP/OPT THE ENTRY POINT
	std::cout << "\nIAT Entrypoint: 0x" << std::hex << (m_pDataDirectory - m_pSectionHdr->VirtualAddress)
		+ m_pSectionHdr->PointerToRawData << '\n';

	while (m_pImportDescriptor->OriginalFirstThunk != 0x00 && !m_isIATFound)
	{
		m_dwName = reinterpret_cast<DWORD>((char*)m_lpMap + hd.Win32SetRvaToDwordOffset(m_pImageHeader, m_pImportDescriptor->Name));
		m_pOriginalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>((char*)m_pDosHeader + hd.Win32SetRvaToDwordOffset(
			m_pImageHeader, m_pImportDescriptor->OriginalFirstThunk));

		m_pFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>((char*)m_pDosHeader + hd.Win32SetRvaToDwordOffset(m_pImageHeader,
			m_pImportDescriptor->FirstThunk));

		while (m_pOriginalFirstThunk->u1.AddressOfData != 0x00 && !m_isIATFound)
		{
			m_pNameImg = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((char*)m_pDosHeader + hd.Win32SetRvaToDwordOffset(m_pImageHeader,
				m_pOriginalFirstThunk->u1.AddressOfData));
			m_dwTest = (DWORD)m_pOriginalFirstThunk->u1.Function & (DWORD)IMAGE_ORDINAL_FLAG32;
			// OUTPUT THE IAT FUNCTIONS
			std::cout << "\nAddr: 0x" << std::hex << m_pOriginalFirstThunk->u1.Function << " (0x" << std::hex <<
				m_pFirstThunk->u1.AddressOfData << ")" << "- Name: " << (const char *)m_pNameImg->Name << '\n';
			
			/* 
			if (m_dwTest == 0)
				if (strcmp("IsDebuggerPresent", (const char *)m_pNameImg->Name) == 0)
				{ 
					m_lpdwAddr = reinterpret_cast<LPDWORD>(m_pFirstThunk->u1.Function);

					m_isIATFound = TRUE;
				}
			*/
			m_pOriginalFirstThunk++;
			m_pFirstThunk++;
		}
		m_pImportDescriptor++;
	}

	CloseHandle(m_hFile);

	return 0;

}
