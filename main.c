#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS 1024
#define MAX_SERVERS 4
#define MASTER_PORT 27950

#define PROXY_TIME 10

#define BUFLEN 2048 //Must be more than enough

struct sockaddr_in masters[MAX_SERVERS];
int masters_count = 0;

int proxy_sockets_count = 0;

struct proxy_socket {
	struct sockaddr_in addr;
	int socket;
	time_t spawned;
};

struct proxy_socket proxy_sockets[MAX_CLIENTS];

void master_add(const char *addr)
{
	if (masters_count >= MAX_SERVERS - 1)
		return;

    memset(&masters[masters_count], 0, sizeof(struct sockaddr_in));
     
    masters[masters_count].sin_family = AF_INET;
    masters[masters_count].sin_port = htons(MASTER_PORT);

	if (!inet_aton(addr, &masters[masters_count].sin_addr))
	{
		return;
	}

	printf("Added master %s\n", addr);
	masters_count++;
}

void proxy_sockets_clean()
{
	int i;
	for (i = 0; i < proxy_sockets_count; i++)
	{
		if (time(NULL) - proxy_sockets[i].spawned > PROXY_TIME)
		{
			close(proxy_sockets[i].socket);
			memcpy(&proxy_sockets[i], &proxy_sockets[i + 1], proxy_sockets_count - i - 1);
			i--;
			proxy_sockets_count--;
		}
	}
}

int proxy_sockets_get_for(struct sockaddr_in *addr)
{
	int i;
	for (i = 0; i < proxy_sockets_count; i++)
	{
		if (!memcmp(&proxy_sockets[i].addr, addr, sizeof(struct sockaddr)))
			break;
	}
	if (i == proxy_sockets_count && i < MAX_CLIENTS)
	{
		memcpy(&proxy_sockets[i].addr, addr, sizeof(struct sockaddr));
		proxy_sockets[i].socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if ((proxy_sockets[i].socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
			goto finish;
		proxy_sockets_count++;
	}
	proxy_sockets[i].spawned = time(NULL);
	return i;

finish:

	return -1;
}

void proxy_socket_message(int index, void *data, int len)
{
	int i;
	char *vecxis;
	for (i = 0; i < masters_count; i++)
	{
		vecxis = memmem(data, len, "Vecxis", 6);
		if (vecxis)
		{
			strncpy(vecxis, "Nexuiz", 6);
		}
		sendto(proxy_sockets[index].socket, data, len, 0, (struct sockaddr *)&masters[i], sizeof(struct sockaddr_in));
	}
}

void proxy_socket_message_back(int index, void *data, int len, int socket)
{
	sendto(socket, data, len, 0, (struct sockaddr *)&proxy_sockets[index].addr, sizeof(struct sockaddr_in));
}

int main(int argc, char **argv) {
	struct sockaddr_in si_me, si_other;
    int i;
	socklen_t slen = sizeof(si_other);
	ssize_t recv_len;
	int proxy_connection;
    char buf[BUFLEN];
	struct pollfd fds[MAX_CLIENTS + 1];

	master_add("107.161.23.68");

	for (i = 0; i <= MAX_CLIENTS; i++)
		fds[i].fd = -1;

    if ((fds[0].fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		goto finish;
     
    memset(&si_me, 0, sizeof(si_me));
     
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(MASTER_PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

     
    if (bind(fds[0].fd, (struct sockaddr*)&si_me, sizeof(si_me)) == -1)
		goto finish;

	for(;;)
    {
		fds[0].revents = 0;
		fds[0].events = POLLIN;
		for (i = 1; i <= proxy_sockets_count; i++)
		{
			fds[i].fd = proxy_sockets[i - 1].socket;
			fds[i].events = POLLIN;
			fds[i].revents = 0;
		}

        if (poll(fds, proxy_sockets_count + 1, -1) < 0)
			goto finish;

		if (fds[0].revents & POLLIN)
		{
			if ((recv_len = recvfrom(fds[0].fd, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) < 0)
				goto finish;

			if (!memcmp(buf, "\377\377\377\377heartbeat DarkPlaces", 23)) //Ignore heartbeats from servers
			{
				//printf("Heartbeat skipped\n");
			}
			else if ((proxy_connection = proxy_sockets_get_for(&si_other)) >= 0)
				proxy_socket_message(proxy_connection, buf, recv_len);
		}

		for (i = 1; i <= proxy_sockets_count; i++)
		{
			if (!(fds[i].revents & POLLIN))
				continue;

			if ((recv_len = recvfrom(fds[i].fd, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) < 0)
				goto finish;
			
			proxy_connection = i - 1;
			proxy_socket_message_back(proxy_connection, buf, recv_len, fds[0].fd);
		}
		proxy_sockets_clean();
    }

finish:
	if (errno)
		perror("Vex2Nex");

	for (i = 0; i <= proxy_sockets_count; i++)
		close(fds[i].fd);
 
    return 0;
}
