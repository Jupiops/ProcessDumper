#pragma once
#include <cstdint>

constexpr auto packet_magic = 0xDEAD1337;
constexpr auto server_ip = 0x7F000001; // 127.0.0.1
constexpr auto server_port = 7000; // 7331;

enum class PacketType
{
	packet_copy_memory,
	packet_get_base_address,
	packet_get_pid,
	packet_get_peb_address,
	packet_completed,
	packet_get_process_list,
	packet_get_req_plist_buf_size
};

struct PacketGetReqPListBufSize
{
	uint32_t magic;
};

struct PacketGetProcessList
{
	uintptr_t buffer_address;
	uint32_t buffer_size;
	uint32_t process_id;
};

struct PacketCopyMemory
{
	uint32_t destination_process_id;
	uintptr_t destination_address;

	uint32_t source_process_id;
	uintptr_t source_address;

	size_t size;
};

struct PacketGetBaseAddress
{
	uint32_t process_id;
};

struct PacketGetPid
{
	size_t process_name_length;
	wchar_t process_name[32];
};

struct PacketGetPebAddress
{
	uint32_t process_id;
};

struct PacketCompleted
{
	uint32_t status;
	size_t value;
};

struct PacketHeader
{
	uint32_t magic;
	PacketType type;
};

struct Packet
{
	PacketHeader header;
	union
	{
		PacketCopyMemory copy_memory;
		PacketGetBaseAddress get_base_address;
		PacketGetPid get_pid;
		PacketGetPebAddress get_peb;
		PacketGetProcessList get_process_list;
		PacketGetReqPListBufSize get_req_plist_buf_size;
		PacketCompleted completed;
	} data;
};