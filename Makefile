CC:=cc
CFLAGS:=-Wall -Wextra -O3 -static -std=c18
CPPFLAGS:=
LDFLAGS:=

SRC=ftp_client.c
EXE=ftp_client

.PHONY: all clean

all: ${EXE}

${EXE}: ${SRC}
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} $^ -o $@

clean:
	@rm -f ${EXE}
