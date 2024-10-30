
# 网络编程基础 API

## 创建 socket

socket 是：可读 可写 可控制 可关闭的**文件描述符**

#socket

```c
#include<sys/socket.h>
int socket(int domain, int type, int protocol)
```

成功时返回文件描述符，失败时返回-1 并设置`errno`

- domain: 套接字中使用的协议族信息
- type : 套接字数据传输类型信息，主要有`SOCK_STREAM` 流服务 `SOCK_DGRAM` 数据报
- protocol : 在前两个参数构成的协议集合下，再选择一个具体的协议，大部分情况可以向第三个参数传输 0，除非**同一协议族中存在多个数据传输方式相同的协议**

#### 协议族信息

| 协议族       | 含义             |
| --------- | -------------- |
| PF_INET   | IPv4           |
| PF_INET6  | IPv6           |
| PF_LOCAL  | 本地通信的 UNIX 协议族 |
| PF_PACKET | 底层套接字的协议族      |
| PF_IPX    | IPX Novell 协议族 |

```c
int tcp_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
//tcp套接字
int udp_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
//udp套接字
```

## 地址信息的表示

### 通用 socket 地址

```c
struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
}
```

### 专用 socket 地址

通用 socket 地址在设置/获取 ip 地址和端口号的时候要进行位操作，很不方便。Linux 为各个协议族提供了专用的结构体：

#### TCP/IP：ipv4

```c
struct sockaddr_in{
	sa_family_t sin_family; //地址族
	uint16_t sin_port; //16位TCP/UDP端口号，以网络字节序保存
	struct in_addr sin_addr; //32位IPv4地址，以网络字节序保存
}

struct in_addr{
	uin32_t s_addr; //32位IPv4地址
}
```

#### TCP/IP：ipv6

```c
struct sockaddr_in6{
	sa_family_t sin6_family; //地址族
	uint16_t sin6_port; //16位TCP/UDP端口号，以网络字节序保存
	uint32_t sin6_flowinfo; // 流信息 应设置为0
	struct in6_addr sin6_addr; //ipv6地址结构体
	uint32_t sin6_scope_id; // scope ID 尚处于试验阶段
}

struct in6_addr{
	unsigned char sa_addr[16]; //ipv6地址
}
```

#### 协议族 地址族

| 地址族   | 对应协议族 |               含义               |
| -------- | :--------: | :------------------------------: |
| AF_INET  |  PF_INET   |        IPv4 使用的地址族         |
| AF_INET6 |  PF_INET6  |        IPv6 使用的地址族         |
| AF_UNIX  |  PF_UNIX   | 本地通信中采用 UNIX 协议的地址族 |

### 字节序转换

> [!Note] 网络字节序
> TCP/IP 中规定好的一种数据表示格式，它与具体的 CPU 类型、操作系统等无关，从而可以保证数据在不同主机之间传输时能够被正确解释。**网络字节序采用大端排序方式。**

> [!Note] 主机字节序
> 不同的机器主机字节序不相同，与 CPU 设计有关，数据的顺序是由 cpu 决定的，而与操作系统无关。我们把某个给定系统所用的字节序称为主机字节序（_host byte order_）
> 比如 x86 系列 CPU 都是小端的字节序。
> 由于这个原因不同体系结构的机器之间无法通信,所以要转换成一种约定的数序,也就是网络字节顺序。
> 同一个机器上两个进程通信也要考虑字节序的问题。

```c
unsigned short htons(unsigned short);
unsigned short ntohs(unsigned short);
unsigned long htonl(unsigned long);
unsigned long ntohl(unsigned long);
```

h 代表主机字节序，n 代表网络字节序，长整型用于 IP 地址，短整型用于端口

## 网络地址的初始化与分配

ipv4 地址是点分十进制字符串，ipv6 地址是十六进制字符串，编程中先转换为整数（二进制数），
记录日志时把整数 ip 地址转换为字符串

### ipv4 字符串信息转换为网络字节序整数型

#inet_addr

点分十进制字符串转换为网络字节序的 ipv4 地址

```c
#include<arpa/inet.h>
in_addr_t inet_addr(const char* string);
```

成功时返回 32 位大端序整数值，失败时返回`INADDR_NONE`

> [!Attention] 检测无效的 IP 地址
> 传入参数为"a.b.c.d"格式时，检查 abcd 每个字段是否>255，如果>255 了就返回`INADDR_NONE`

#inet_aton

与`inet_addr`相同，但储存在指针中

```c
#include<arpa/inet.h>
int inet_aton(const char* string, struct in_addr* addr);
```

成功时返回 1，失败时返回 0

- string：含需转换的 IP 地址信息的字符串地址值
- addr：将保存转换结果的 in_addr 结构体变量的地址值

#inet_ntoa

将网络字节序表示的 ipv4 地址转换为点分十进制字符串表示，用静态变量存储，不可重入

```c
#include<arpa/inet.h>
char* inet_ntoa(struct in_addr addr);
```

成功时返回转换的字符串地址值，失败时返回-1

> [!Attention]
> 若需要长期保存，调用完该函数后应立即将字符串信息复制到其他的内存空间

### 同时适用于 ipv4 和 ipv6 的函数

#inet_pton

将字符串表示的 IP 地址 src 转换成网络字节序整数表示的 IP 地址，结果储存于`dst`指向的内存中

```c
#include <arpa/inet.h>
int inet_pton(int af, const char* src, void* dst);
```

成功时返回 1，失败时返回 0 并设置`errno`

- af：地址族

#inet_ntop

```c
#include <arpa/inet.h>
const char* inet_ntop(int af, const void* src, char* dst, socklen_t cnt)
```

成功时返回目标存储单元地址，失败返回`NULL`并设置`errno`

- cnt：指定目标存储单元的大小

#### 自动获取运行服务器端的 IP 地址

> [!Note] `INADDR_ANY`
> 自动获取运行服务器端的 IP 地址，若同一计算机中已分配多个 IP 地址（多宿主计算机，例如路由器），只要端口号一致就可以从不同 IP 地址接收数据，服务器端优先考虑这种方式

#### 向 socket 分配网络地址

#bind

```c
#include<sys/socket.h>
int bind(int sockfd, struct sockaddr* myaddr, socklen_t addrlen);
```

成功时返回 0，失败时返回-1

- sockfd：要分配地址信息的 socket 文件描述符
- myaddr：存有地址信息的结构体变量地址
- addrlen：该结构体变量的长度

## 监听 socket

#listen

创建一个监听队列来存放待处理的客户连接

```c
#include<sys/socket.h>
int listen(int sock, int backlog);
```

成功时返回 0，失败时返回-1 并设置`errno`

- sock：希望进入等待连接请求状态的 socket 文件描述符
- backlog：连接监听队列的长度，表示最多使几个连接请求进入队列，与服务器端的特性有关，典型参数为 5，频繁接收的 web 服务器端至少要 15。超过长度服务器不受理新的客户端连接，客户端收到`ECONNREFUSED`信息。内核 2.2 之前指半连接状态和完全连接状态的 socket 的上限，2.2 之后只表示完全连接状态的 socket 上限。

> [!hint]
> 客户端连接请求也是一种数据，等待与服务端连接

## 服务器接受连接

#accept

从监听队列中接受一个连接（不论连接处于什么状态，不关心网络状态变化）

```c
#include<sys/socket.h>
int accept(int sock, struct sockaddr* addr, socklen_t *addrlen);
```

成功时返回创建的套接字文件符，失败时返回-1 并设置`errno`

- sock：执行`listen`调用的监听 socket
- addr：获取被接受连接的远端 socket 地址，长度由 addrlen 指出

## 客户端主动连接

#connect

```c
#include <sys/types.h>
#include <sys/socket.h>
int connect(int sockfd, const struct sockaddr* serv_addr, socklen_t addrlen);
```

成功时返回 0，`sockfd`唯一的标识这个连接失败时返回-1 并设置`errno`，常见的有：

- `ECONNREFUSED`：目标端口不存在，连接被拒绝
- `ETIMEOUT`：连接超时

## 关闭连接

#close
并非立即关闭，而是将`fd`的引用次数-1，当引用次数为 0 时才是真正关闭连接

```c
#include<unistd.h>
int close(int fd);
```

成功时返回 0，失败时返回-1

- fd：需要关闭的文件或套接字的文件描述符

#shutdown

如果需要立即关闭终止连接而不是引用次数-1 可以使用`shutdown`

```c
#include<sys/socket.h>
int shutdown(int sock, int howto)
```

成功时返回 0，失败时返回-1(Win：SOCKET_ERROR)

- sock:需要断开的 socket 文件描述符
- howto：传递断开方式信息

howto 的可选值

| 可选值    | 含义                                                       |
| --------- | ---------------------------------------------------------- |
| SHUT_RD   | 断开输入流，输入缓冲收到数据也会被消除                     |
| SHUT_WR   | 断开输出流，输出缓冲如果还有未传输的数据，则传递至目标主机 |
| SHUT_RDWR | 同时断开 I/O 流，等于调用`SHUT_RD，SHUT_WR`各一次          |

## TCP 数据读写

#send #recv

```c
#include <sys/socket.h>
ssize_t send(int sockfd, const void *buf, size_t nbytes, int flags);
```

成功时返回发送的字节数, 失败时返回-1 并设置`errno`

- sockfd: 表示与数据传输对象的连接的套接字文件描述符
- buf: 保存待传输数据的缓冲地址值
- nbytes: 待传输的字节数
- **flags: 指定的可选项信息**

```c
#include <sys/socket.h>
ssize_t recv(int sockfd, const void *buf, size_t nbytes, int flags);
```

成功时返回接收的字节数, 收到 EOF 返回 0, 失败时返回-1 并设置`errno`

- sockfd: 表示数据接收对象的连接的套接字文件描述符
- buf: 保存接收数据的缓冲地址值
- nbytes: 能接收的最大字节数
- **flags: 指定的可选项信息**

flags(可选项)可利用位或(_bit OR_)运算同时传递多个信息, 不同操作系统对可选项的支持有不同, 不受操作系统影响的:

| 选项           | 含义                                           | send | recv |
| -------------- | ---------------------------------------------- | ---- | ---- |
| `MSG_OOB`      | 发送/接受紧急数据                              | Y    | Y    |
| `MSG_PEEK`     | 窥探读缓存中的数据，此次操作不会导致数据被清除 | N    | Y    |
| `MSG_DONTWAIT` | 对 socket 的此次操作是非阻塞的                 | Y    | Y    |

### 紧急模式工作原理

`MSG_OOB`的意义在督促数据接收对象尽快处理数据, TCP"保持传输顺序"的传输特性仍然成立.

#### `MSG_OOB`:发送/接受紧急数据

用于创建特殊发送方法和通道, 来发送优先级更高的紧急消息(带外数据, _out-of-band data_: 通过完全不同的通信路径传输的数据)

```shell
./oob_recv.out 9190
./oob_send.out 127.0.0.1 9190

Urgent message: 0
12356789
```

通过`MSG_OOB`, `urge_handler`读取数据只能读 1 字节, 剩下的用普通输入读取, 因为 TCP 不存在真正意义上的带外数据, oob 应该要用单独的通信路径高速传输,但是 TCP 不提供, 只能用紧急模式传输

#### 输出缓冲

`send(sock, "890", strlen("890"), MSG_OOB)`
偏移量 3 的位置存着紧急指针, 指向紧急消息的下一位置, 向对方主机传送消息: 紧急指针指向偏移量 3, 之前的部分是紧急消息

| 偏移量 | 0   | 1   | 2   | 3        | ... |
| ------ | --- | --- | --- | -------- | --- |
|        | 8   | 9   | 0   | 紧急指针 |     |

实际只用 1 个字节表示紧急消息信息.

| TCP 头                | 数据 |
| --------------------- | ---- |
| URG = 1, URG 指针 = 3 | 890  |

- URG=1: 载有紧急消息的数据包
- URG 指针: 紧急指针位于偏移量 3 的位置
    我们无法得知具体消息内容, 紧急消息的意义在于督促消息处理, 而不是紧急传输形式受限的消息.

#### `MSG_PEEK`和`MSG_DONTWAIT`：检查输入缓冲

同时设置`MSG_PEEK`和`MSG_DONTWAIT`来验证输入缓冲中是否存在接收的数据.

- 设置`MSG_PEEK`并调用`recv()`, 即使读取了输入缓冲的数据也不会删除, 所以通常和`MSG_DONTWAIT`一起用, 以非阻塞方式验证待读数据存在与否.

```bash
./peek_recv.out 8190
./peek_send.out 127.0.0.1 8190

Buffering 3 bytes: 123
Read again: 123 # 设置MSG_PEEK 数据被读取2次
```

## UDP 数据读写

UDP 通信没有连接的概念，每次读取数据都要获取发送端的 socket 地址。
这两个函数也可以用于面向连接的数据读写，只要把最后两个参数都设置`NULL`以忽略发送端/接收端 socket 地址

#sendto #recvfrom

```c
#include<sys/socket.h>
ssize_t sendto(int sock, void *buf, size_t nbytes, int flags, struct sockaddr *to, socklen_t addrlen);

```

成功时返回传输字节数，失败时返回-1

- sock：传输数据的 UDP 套接字文件描述符
- buf：保存待传输数据的缓冲地址值
- nbytes：待传输的数据长度，以字节为单位
- flags：可选参数，默认 0
- to：存有目标地址信息的 sockaddr 结构体变量的地址值
- addrlen：传输给参数 to 的结构体变量长度的变量地址值

```c
#include<sys/socket.h>
ssize_t recvfrom(int sock, void* buf, size_t nbytes, int flags, struct sockaddr* from, socklen_t* addrlen);
```

成功时返回传输字节数，失败时返回-1

- sock：接收数据的 UDP 套接字文件描述符
- buf：保存数据的缓冲地址值
- nbytes：可接收的最大字节数，无法超过参数 buff 所指的缓冲大小
- flags：可选参数，默认 0
- from：存有发送端地址信息的 sockaddr 结构体变量的地址值
- addrlen：保存参数 from 的结构体变量长度的变量地址值

## 通用数据读写

不仅用于 TCP，也可以用于 UDP

#recvmsg #sendmsg

```c
#include <sys/socket.h>
ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags);
ssize_t sendmsg(int sockfd, struct msghdr* msg, int flags);
```

```c
struct msghdr {
	void* msg_name; // socket地址
	socklen_t msg_namelen; // socket地址长度
	struct iovec* msg_iov; // 分散的内存块
	int msg_iovlen; // 分散内存块数量
	void* msg_control; // 指向辅助数据的起始位置
	socklen_t msg_controllen; // 辅助数据大小
	int msg_flags; // 复制函数中的flag参数 调用过程中更新
};

struct iovec {
	void* iov_base; // 内存起始地址
	size_t iov_len; // 内存长度
}
```

成功时返回发送的字节数, 失败时返回-1 并设置`errno`

`recvmsg` 时数据将被读取，存放在`msg_iovlen`块分散的内存中，位置和长度由`msg_iov`指向的数组指定，这是分散读(_scatter read_)

`sendmsg`时`msg_iovlen`块分散内存中的数据将被一并发送，称为集中写(_gather write_)

- sockfd: 被操作目标 socket
- msg：指针
- flags：可选参数，默认

## 带外标记

Linux 内核检测到 TCP 紧急标志的时候，先通知应用程序：有带外数据需要接受
有两种方式：

1. I/O 复用产生的异常事件
2. `SIGURG`信号
   还需要知道带外数据在数据流中的具体位置：

#sockatmark

判断`sockfd`是否处于带外标记（下一个被读取到的数据是否是带外数据）

```c
#include <sys/socket.h>
int sockatmark(int sockfd);
```

如果是则返回 1，此时可以利用带`MSG_OOB`的`recv`来接受，不是则返回 0

## 地址信息函数

#getsockname #getpeername

获取`sockfd`对应的本端 socket 地址，将其存储于`address`参数指定的内存中，该 socket 地址的长度则存储于`address_len`指向的变量中（实际 socket 地址长度比`address`所指内存大的时候，地址会被截断）

```c
#include <sys/socket.h>
int getsockname(int sockfd, struct sockaddr* address, socklen_t* address_len);
```

```c
int getpeername(int sockfd, struct sockaddr* address, socklen_t* address_len);
```

成功时返回 0，失败时返回-1 并设置 `errno`

## socket 的可选项

```c
#include <sys/socket.h>
int getsockopt(int sock, int level, int optname,  void *optval, socklen_t *optlen );
```

成功时返回 0，失败时返回-1

- sock:查看选项的 socket 文件描述符
- level：查看选项的协议层
- optname：查看的可选项名
- optval：保存查看结果的缓冲地址值
- optlen：向 optval 传递的缓冲大小，调用函数后，该变量保存通过 optval 返回的可选项的字节数

对可选项修改：

```c
#include <sys/socket.h>
int setsockopt(int sock, int level, int optname,  const void *optval, socklen_t optlen );
```

成功时返回 0，失败时返回-1

- sock:更改选项的 socket 文件描述符
- level：更改选项的协议层
- optname：更改的可选项名
- optval：保存更改结果的缓冲地址值
- optlen：向 optval 传递的可选项的字节数

![[socket选项.png]]

> [!attention]
> 部分选项只能在调用`listen`前针对监听 socket 设置才有效，因为连接 socket 只能由`accept`调用返回。而它从监听队列中接受的连接至少已经完成 TCP 三次握手的前两次（`listen`监听队列的连接至少已经进入`SYN_RCVD`状态），服务器已经往被接受连接上发送了 TCP 同步报文段

### `SO_REUSEADDR`

[[TIME_WAIT]]
服务器可以通过设置 socket 选项 `SO_REUSEADDR` 来强制使用被处于 TIME_WAIT 状态的连接占用的 socket 地址

```c
int sock = socket(PF_INET, SOCK_STREAM, 0);
int reuse = 1;
setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
```

> [!hint]
> 也可以通过修改内核参数`/proc/sys/net/ipv4/tcp_tw_recycle` 来快速回收被关闭的 socket，使得 TCP 连接根本就不进入 TIME_WAIT 状态，允许应用程序立即重用本地 socket 地址

### `SO_RCVBUF` 和 `SO_SNDBUF`

修改 TCP 缓冲区大小。使用`setsockopt` 设置 TCP 发送和接收的缓冲区大小时，系统会将其加倍且不得小于某个最小值，来确保一个 TCP 连接有足够的空闲缓冲区来处理拥塞（比如快速重传期望 TCP 接收缓冲区至少容纳 4 个大小为 SMSS 的 TCP 报文段）

`SO_RCVBUF`：接收缓冲区大小(min:256byte 不同系统可能不同)
`SO_SNDBUF`：发送缓冲区大小(max:2048byte)

> [!hint]
> 也可以通过修改内核参数`/proc/sys/net/ipv4/tcp_wmem` 来解除 TCP 接收缓冲区和发送缓冲区的最小值

### `SO_RCVLOWAT` 和 `SO_SNDLOWAT`

`SO_RCVLOWAT`：接收缓冲区的低水位标记 (1byte)
`SO_SNDLOWAT`：发送缓冲区的低水位标记 (1byte)

一般被 I/O 复用系统调用来判断 socket 是否可读或者可写：

TCP 接收缓冲区中可读数据的总数大于其低水位标记时，I/O 复用系统调用将通知应用程序可以从对应的 socket 上读取。
TCP 发送缓冲区中可读数据的总数大于其低水位标记时，I/O 复用系统调用将通知应用程序可以往对应的 socket 上写入。

### `SO_LINGER`

控制`close`在关闭 TCP 连接的行为

设置`SO_LINGER`时我们给`setsockopt` / `getsockopt` 调用传递一个`linegr` 类型结构体：

```c
#include <sys/socket.h>
struct linger {
	int l_onoff; // 开启/关闭
	int l_linger; // 滞留时间
}
```

- `l_oneoff = 0` 时 `SO_LINGER`不起作用，`close` 默认关闭 socket
- `l_oneoff != 0 l_linger = 0`，`close`立即返回，TCP 模块丢弃关闭的 socket 对应的 TCP 发送缓冲区中残留的数据，给对方发一个复位报文，提供了异常终止一个连接的方法
- `l_oneoff != 0, l_linegr > 0`，`close` 行为取决于：被关闭的 socket 对应的 TCP 发送缓冲区是否有残留数据， 该 socket 是否非阻塞。阻塞 socket 等待时间为`l_linger`直到 TCP 模块发送完所有残留数据并得到对方确认，如果没有成功就返回-1 并设置`errno`，非阻塞则立即返回

阻塞和非阻塞：

## 网络信息 API

### 获取主机完整信息

#gethostbyname #gethostbyaddr

根据主机名称获取主机完整信息，先在本地`/etc/hosts`配置文件寻找主机，找不到就访问 DNS 服务器

```c
#include<netdb.h>
struct hostent* gethostbyname(const char* hostname)
```

- hostname: 域名字符串

根据 IP 地址获取主机完整信息

```c
#include<netdb.h>
struct hostent* gethostbyaddr(const char* addr, socklen_t len, int family)
```

- addr:含有 ip 地址信息的 in_addr 结构体指针，为了同时传递 IPv4 地址以外的信息，应该声明为 char 指针
- len：向第一个参数传递的地址信息的字节数，IPv4：4 IPv6：16
- family：地址族信息

都返回`hostent`结构体类型的指针：

```c
struct hostent {
	char* h_name; //官方域名
	char** h_aliases;//同一IP绑定的其他域名
	int h_addrtype; //地址族信息(eg. IPv4:AF_INET)
	int h_length; // IP地址长度(byte)(IPv4:4 IPv6:16)
	char** h_addr_list //以整数形式保存域名对应的IP地址，用户较多的网站有可能分配多个IP给同一域名，利用多个服务器进行负载均衡。
}
```

### 获取某个服务完整信息

#getservbyname #getservbyport

```c
#include <netdb.h>
struct servent* getservbyname(const char* name, const char* proto);
struct servent* getservbyport(int port, const char* proto);
```

- name: 指定服务名字
- port：指定服务的端口号
- proto：服务类型(`"tcp"`：流服务 `"udp"`：数据报服务`NULL`：所有类型)

```c
struct servent {
  char* s_name; // 服务名
  char** s_aliases; // 服务别名
  short s_port; // 端口号
  char* s_proto; // 服务类型 tcp/udp
};
```

> [!warning]
> 这四个函数都不可重入，即非线程安全，可重入版本的命名规则是原名加上`_r`

### `getaddrinfo`

既能通过主机名获得 ip 地址，也能通过服务名获取端口号

```c
#include <netdb.h>
int getaddrinfo(const char* hostname, const char* service, const struct addrinfo* hints, struct addrinfo** result);
```

- hostname：主机名/字符串 ip 地址
- service：服务名/字符串端口
- hints：应用程序给这个函数的一个提示，可设`NULL`
- result：指向存储`getaddrinfo`反馈结果的链表

```c
typedef struct addrinfo {
	int ai_flags;  //AI_PASSIVE,AI_CANONNAME,AI_NUMERICHOST
	int ai_family;        //AF_INET,AF_INET6
	int ai_socktype;    //SOCK_STREAM,SOCK_DGRAM
	int ai_protocol;    //IPPROTO_IP, IPPROTO_IPV4,IPPROTO_IPV6 etc.
	size_t ai_addrlen;            //must be zero or a null pointer
	char* ai_canonname;            //must be zero or a null pointer
	struct sockaddr* ai_addr;    //must be zero or a null pointer
	struct addrinfo* ai_next;    //must be zero or a null pointer
}
```

我们使用`hints`时只设置前四个字段，后面设`NULL`

该函数隐式地分配堆内存，因为`res`原本没有指向一块合法内存，所以调用结束我们要用配对的函数释放这块内存

#freeaddrinfo

```c
#include <netdb.h>
void freeaddrinfo(struct addrinfo* res);
```

### `getnameinfo`

通过 socket 地址同时获得以字符串表示的主机名和服务名

```c
#include <netdb.h>
int getnameinfo (const struct sockaddr* sockaddr, socklen_t addrlen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags);
```

将返回的主机名存储在`host`指向的缓存中，将服务名存储在`serv`指向的缓存中

- hostlen servlen：指定两块缓存的长度
- flag: 指定行为
