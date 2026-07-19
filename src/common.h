typedef enum {
  // a socket was bound to a port
  EVENT_BIND,
  // a socket was released
  EVENT_RELEASE,
  // a connection was accepted
  EVENT_ACCEPT,
  // a socket was connected
  EVENT_CONNECT,
} EventTag;

struct sock_evt {
  uint16_t port;
  __u64 cookie;    // socket cookie
  __u64 ns_cookie; // netns cookie
};

struct jolt_event {
  EventTag tag;
  uint32_t pid;

  union {
    struct sock_evt socket;    /* used by BIND and RELEASE */
    struct {
      struct sock_evt listening; /* the listening socket */
      uint16_t rport;            /* remote port of the connecting client */
      uint32_t client_pid;       /* PID of the connecting client */
    } accept;                    /* a connection was accepted */

    struct {
      struct sock_evt socket; /* socket connecting */
      uint16_t rport;
    } connect; /* socket attempting to connect */
  } data;
};
