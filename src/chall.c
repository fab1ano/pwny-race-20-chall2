#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#include <stdint.h>
#include <err.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>


#define PORT 4444

char *pwny = 
"            .''\n"
"  ._.-.___.' (`\\\n"
" //(        ( `'\n"
"'/ )\\ ).__. ) \n"
"' <' `\\ ._/'\\\n"
"   `   \\     \\\n";

void bake_cookie() {
	uint64_t fresh_cookie, old_cookie;
	uint64_t *cookie_ptr;
	time_t now;

	now = time(NULL);
	if (now == -1) {
		err(-1, "time");
	}
	srand(now);
	fresh_cookie = rand();
	((uint32_t *)&fresh_cookie)[1] = rand();
	((uint8_t *)&fresh_cookie)[7] = 0;

	__asm__ __volatile__ (
			".intel_syntax noprefix;"
			"mov %0, QWORD PTR fs:0x28;"
			".att_syntax;"
			: "=r"(old_cookie) ::);

	cookie_ptr = &old_cookie;
	while (1) {
		cookie_ptr++;
		if (*cookie_ptr == old_cookie) {
			*cookie_ptr = fresh_cookie;
			break;
		}
	}

	__asm__ __volatile__ (
			".intel_syntax noprefix;"
			"mov rax, %0;"
			"mov QWORD PTR fs:0x28, rax;"
			".att_syntax;"
			:: "r"(fresh_cookie) : "%rax");

	fresh_cookie = 0;
	return;
}

void where_do_you_go() {
	char buf[1024];
	uint32_t len;

	puts("How far do you wanna ride?");
	if (fgets(buf, 1024, stdin) == NULL) {
		err(-1, "fgets");
	}
	len = atoi(buf);
	if (len > 2020) {
		puts("Really?");
		return;
	}

	puts("Where do you ride to?");
	if (read(0, buf, len) < 0) {
		err(-1, "read failed");
	}

	puts("Whatever!");
}

void handle() {
	alarm(15);
	bake_cookie();

	puts(pwny);
	where_do_you_go();
	puts("Bye.");
	sleep(5);
	exit(0);
}

int main(void) {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		err(-1, "signal");
	}

	int sockfd, connfd; 
	struct sockaddr_in servaddr; 

	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (-1 == sockfd) { 
		err(-1, "socket creation"); 
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
		err(-1, "setsockopt SO_REUSEADDR");
	}

	bzero(&servaddr, sizeof(servaddr)); 
	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(PORT); 
	if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) { 
		err(-1, "socket bind"); 
	}

	if ((listen(sockfd, 10)) != 0) { 
		err(-1, "listen"); 
	} 

	while (1) {
		connfd = accept(sockfd, NULL, NULL); 
		if (connfd < 0) { 
			puts("server acccept failed..."); 
			continue; 
		} 

		pid_t pid = fork();
		if (pid < 0) {
			err(-1, "fork");
		} else if (!pid) {
			if (dup2(connfd, 0) < 0) err(-1, "dup2");
			if (dup2(connfd, 1) < 0) err(-1, "dup2");
			if (dup2(connfd, 2) < 0) err(-1, "dup2");
			handle();
			break;
		} else {
			close(connfd);
		}
	}
}
