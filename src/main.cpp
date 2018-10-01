#include "dumper.h"

int main()
{
	DMP::Win32Dumper dmp32;

	dmp32.Win32DumpExecutableInformation();

	system("PAUSE");

	return 0x00;
}