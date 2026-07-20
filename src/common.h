typedef enum {
  // a socket was bound to a port
  EVENT_BIND,
  // a listening socket was released
  EVENT_RELEASE,
  // a connection was accepted
  EVENT_ACCEPT,
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
    struct sock_evt socket; /* used by BIND and RELEASE */
    struct {
      struct sock_evt listening; /* the listening socket */
      uint16_t peer_port;        /* local port of the connecting socket */
      uint32_t client_pid;       /* PID of the connecting client */
    } accept;                    /* a connection was accepted */
  } data;
};

/* uniquely identify an endpoint in the system */
struct endpoint_id {
  uint16_t port;
  __be32 addr;
  uint64_t ns_cookie;
} __attribute__((packed));
