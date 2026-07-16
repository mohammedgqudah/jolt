struct bind_event {
  uint32_t pid;
  uint16_t port;
  int is_release;
  __u64 cookie;    // socket cookie
  __u64 ns_cookie; // netns cookie
};
