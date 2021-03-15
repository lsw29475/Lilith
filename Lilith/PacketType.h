#pragma once

#ifndef PACKETTYPE_H
#define PACKETTYPE_H

enum class PacketType
{
	Instruction,
	CMDCommand,
	Warning,
	FileTransferRequestFile,	   //Sent to request a file
	FileTransfer_EndOfFile,		   //Sent for when file transfer is complete
	FileTransferByteBuffer,		   //Sent before sending a byte buffer for file transfer
	FileTransferRequestNextBuffer, //Sent to request the next buffer for file
	SystemInfo = 8,
	ProcessInfo = 9,
	ScreenShot = 10,
	TargetUp = 11
};

#endif // !PACKETTYPE_H
