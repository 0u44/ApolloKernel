#include "tcp_stack.h"
#include "heap_allocator.h"
#include "terminal.h"
#include "string_utils.h"
#include "time_keeper.h"

#define TCP_OPTION_MSS 2
#define TCP_OPTION_MSS_LENGTH 4
#define TCP_SYN_HEADER_SIZE 24
#define EPHEMERAL_BASE 49152
#define EPHEMERAL_RANGE 16384
#define WINDOW_UPDATE_THRESHOLD 2048

struct tcp_socket {
    bool in_use;
    bool app_closed;
    tcp_state_t state;
    ip_address_t local_ip;
    ip_address_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;

    uint32_t iss;
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t snd_wnd;
    uint16_t mss;
    uint32_t rcv_nxt;
    uint32_t last_window;

    uint8_t* tx;
    uint32_t tx_len;            // Bytes from snd_una onward, unacked plus unsent
    uint8_t* rx;
    uint32_t rx_head;
    uint32_t rx_len;

    bool fin_queued;
    bool fin_sent;
    bool fin_received;
    bool reset;

    uint32_t rto;
    uint32_t retransmit_at;
    uint32_t retries;
    uint32_t time_wait_until;

    tcp_socket_t* parent;
    tcp_socket_t* backlog[TCP_MAX_BACKLOG];
    uint8_t backlog_count;
    uint8_t backlog_max;

    void (*on_connect)(tcp_socket_t*, bool);
    void (*on_data)(tcp_socket_t*, const void*, uint32_t);
    void (*on_close)(tcp_socket_t*);
};

static tcp_socket_t sockets[TCP_MAX_CONNECTIONS];
static tcp_statistics_t tcp_stats;
static bool tcp_initialized = false;
static uint16_t next_ephemeral = 0;

static uint16_t be16(uint16_t v) { return __builtin_bswap16(v); }
static uint32_t be32(uint32_t v) { return __builtin_bswap32(v); }

static bool seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static bool seq_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }

static void copy_bytes(void* dest, const void* src, uint32_t size) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < size; i++) d[i] = s[i];
}

static uint32_t initial_sequence(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return lo ^ (hi << 16);
}

bool tcp_initialize(void) {
    if (tcp_initialized) return true;
    for (uint32_t i = 0; i < TCP_MAX_CONNECTIONS; i++) sockets[i].in_use = false;
    tcp_stats = (tcp_statistics_t){0};
    next_ephemeral = (uint16_t)(initial_sequence() % EPHEMERAL_RANGE);
    tcp_initialized = true;
    return true;
}

static void release(tcp_socket_t* s) {
    if (s->tx) apollo_free_memory(s->tx);
    if (s->rx) apollo_free_memory(s->rx);
    s->in_use = false;
}

void tcp_shutdown(void) {
    for (uint32_t i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        if (sockets[i].in_use) release(&sockets[i]);
    }
    tcp_initialized = false;
}

tcp_socket_t* tcp_create_socket(void) {
    tcp_initialize();
    for (uint32_t i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_socket_t* s = &sockets[i];
        if (s->in_use) continue;
        uint8_t* bytes = (uint8_t*)s;
        for (uint32_t b = 0; b < sizeof(*s); b++) bytes[b] = 0;
        s->tx = apollo_allocate_memory(TCP_TX_BUFFER_SIZE);
        s->rx = apollo_allocate_memory(TCP_RX_BUFFER_SIZE);
        if (!s->tx || !s->rx) {
            release(s);
            return NULL;
        }
        s->in_use = true;
        s->state = TCP_CLOSED;
        s->mss = TCP_MSS;
        s->rto = TCP_INITIAL_RTO;
        return s;
    }
    return NULL;
}

static bool port_taken(uint16_t port) {
    for (uint32_t i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        if (sockets[i].in_use && sockets[i].local_port == port && sockets[i].state == TCP_LISTEN) return true;
        if (sockets[i].in_use && sockets[i].local_port == port && !sockets[i].parent && sockets[i].state != TCP_CLOSED) return true;
    }
    return false;
}

bool tcp_bind(tcp_socket_t* socket, uint16_t port) {
    if (!socket || !socket->in_use || socket->local_port) return false;
    if (port == 0) {
        for (uint32_t tries = 0; tries < EPHEMERAL_RANGE && port == 0; tries++) {
            uint16_t candidate = (uint16_t)(EPHEMERAL_BASE + next_ephemeral++ % EPHEMERAL_RANGE);
            if (!port_taken(candidate)) port = candidate;
        }
    }
    if (port == 0 || port_taken(port)) return false;
    socket->local_port = port;
    return true;
}

bool tcp_listen(tcp_socket_t* socket, uint8_t backlog) {
    if (!socket || !socket->local_port || socket->state != TCP_CLOSED) return false;
    socket->backlog_max = backlog == 0 || backlog > TCP_MAX_BACKLOG ? TCP_MAX_BACKLOG : backlog;
    socket->state = TCP_LISTEN;
    return true;
}

tcp_socket_t* tcp_accept(tcp_socket_t* listening_socket) {
    if (!listening_socket || listening_socket->state != TCP_LISTEN || listening_socket->backlog_count == 0) return NULL;
    tcp_socket_t* child = listening_socket->backlog[0];
    for (uint8_t i = 1; i < listening_socket->backlog_count; i++) {
        listening_socket->backlog[i - 1] = listening_socket->backlog[i];
    }
    listening_socket->backlog_count--;
    child->parent = NULL;
    return child;
}

/* output */

static uint32_t receive_window(const tcp_socket_t* s) {
    return TCP_RX_BUFFER_SIZE - s->rx_len;
}

static bool send_segment(tcp_socket_t* s, uint32_t seq, uint8_t flags, const uint8_t* data, uint32_t length) {
    uint8_t buffer[TCP_SYN_HEADER_SIZE + TCP_MSS];
    uint32_t header = (flags & TCP_FLAG_SYN) ? TCP_SYN_HEADER_SIZE : TCP_HEADER_MIN_SIZE;
    tcp_header_t* h = (tcp_header_t*)buffer;
    h->source_port = be16(s->local_port);
    h->dest_port = be16(s->remote_port);
    h->sequence_number = be32(seq);
    h->acknowledgment_number = (flags & TCP_FLAG_ACK) ? be32(s->rcv_nxt) : 0;
    h->header_length_reserved = (uint8_t)((header / 4) << 4);
    h->flags = flags;
    s->last_window = receive_window(s);
    h->window_size = be16((uint16_t)s->last_window);
    h->checksum = 0;
    h->urgent_pointer = 0;
    if (flags & TCP_FLAG_SYN) {
        buffer[20] = TCP_OPTION_MSS;
        buffer[21] = TCP_OPTION_MSS_LENGTH;
        buffer[22] = (uint8_t)(TCP_MSS >> 8);
        buffer[23] = (uint8_t)TCP_MSS;
    }
    if (length) copy_bytes(buffer + header, data, length);
    uint16_t total = (uint16_t)(header + length);
    h->checksum = ip_finish_checksum(ip_pseudo_header_sum(&s->local_ip, &s->remote_ip, IP_PROTOCOL_TCP, total),
                                     buffer, total);
    tcp_stats.segments_sent++;
    return ip_send_packet(NULL, &s->remote_ip, IP_PROTOCOL_TCP, buffer, total);
}

static void arm_timer(tcp_socket_t* s) {
    if (s->snd_nxt != s->snd_una && s->retransmit_at == 0) s->retransmit_at = get_system_time() + s->rto;
    if (s->snd_nxt == s->snd_una) s->retransmit_at = 0;
}

static bool can_send_data(const tcp_socket_t* s) {
    return s->state == TCP_ESTABLISHED || s->state == TCP_CLOSE_WAIT ||
           ((s->state == TCP_FIN_WAIT_1 || s->state == TCP_LAST_ACK) && !s->fin_sent);
}

// Sends unsent data within the peer window, then the FIN once the queue is empty
static void output(tcp_socket_t* s) {
    if (s->state == TCP_SYN_SENT || s->state == TCP_SYN_RECEIVED) {
        if (s->snd_nxt == s->iss) {
            send_segment(s, s->iss, TCP_FLAG_SYN | (s->state == TCP_SYN_RECEIVED ? TCP_FLAG_ACK : 0), NULL, 0);
            s->snd_nxt = s->iss + 1;
        }
        arm_timer(s);
        return;
    }
    while (can_send_data(s)) {
        uint32_t in_flight = s->snd_nxt - s->snd_una;
        uint32_t window = s->snd_wnd ? s->snd_wnd : 1;
        if (in_flight >= s->tx_len || in_flight >= window) break;
        uint32_t length = s->tx_len - in_flight;
        if (length > window - in_flight) length = window - in_flight;
        if (length > s->mss) length = s->mss;
        send_segment(s, s->snd_nxt, TCP_FLAG_ACK | TCP_FLAG_PSH, s->tx + in_flight, length);
        s->snd_nxt += length;
    }
    if (s->fin_queued && !s->fin_sent && s->snd_nxt - s->snd_una == s->tx_len && can_send_data(s)) {
        send_segment(s, s->snd_nxt, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
        s->snd_nxt++;
        s->fin_sent = true;
        if (s->state == TCP_ESTABLISHED) s->state = TCP_FIN_WAIT_1;
        else if (s->state == TCP_CLOSE_WAIT) s->state = TCP_LAST_ACK;
    }
    arm_timer(s);
}

static void send_ack(tcp_socket_t* s) {
    send_segment(s, s->snd_nxt, TCP_FLAG_ACK, NULL, 0);
}

static void send_reset_reply(const ip_header_t* ip, const tcp_header_t* in, uint32_t segment_length) {
    if (in->flags & TCP_FLAG_RST) return;
    tcp_socket_t temp;
    temp.local_ip = ip->dest_ip;
    temp.remote_ip = ip->source_ip;
    temp.local_port = be16(in->dest_port);
    temp.remote_port = be16(in->source_port);
    temp.rx_len = TCP_RX_BUFFER_SIZE;
    if (in->flags & TCP_FLAG_ACK) {
        temp.rcv_nxt = 0;
        send_segment(&temp, be32(in->acknowledgment_number), TCP_FLAG_RST, NULL, 0);
    } else {
        temp.rcv_nxt = be32(in->sequence_number) + segment_length;
        send_segment(&temp, 0, TCP_FLAG_RST | TCP_FLAG_ACK, NULL, 0);
    }
    tcp_stats.resets_sent++;
}

/* state changes */

static void detach_from_parent(tcp_socket_t* s) {
    tcp_socket_t* parent = s->parent;
    if (!parent) return;
    for (uint8_t i = 0; i < parent->backlog_count; i++) {
        if (parent->backlog[i] != s) continue;
        for (uint8_t j = i + 1; j < parent->backlog_count; j++) parent->backlog[j - 1] = parent->backlog[j];
        parent->backlog_count--;
        break;
    }
}

static void enter_closed(tcp_socket_t* s) {
    bool was_open = s->state != TCP_CLOSED && s->state != TCP_LISTEN;
    s->state = TCP_CLOSED;
    s->retransmit_at = 0;
    if (was_open) {
        tcp_stats.connections_closed++;
        if (tcp_stats.active_connections) tcp_stats.active_connections--;
        if (s->on_close) s->on_close(s);
    }
    if (s->app_closed || s->parent) {
        detach_from_parent(s);
        release(s);
    }
}

static void enter_established(tcp_socket_t* s) {
    s->state = TCP_ESTABLISHED;
    tcp_stats.connections_established++;
    tcp_stats.active_connections++;
    if (s->on_connect) s->on_connect(s, true);
}

/* input */

typedef struct {
    uint32_t seq;
    uint32_t ack;
    uint8_t flags;
    uint16_t window;
    const uint8_t* data;
    uint32_t length;
    uint16_t mss;
} segment_t;

static bool parse_segment(const ip_header_t* ip, const void* packet, uint32_t length, segment_t* seg) {
    if (length < TCP_HEADER_MIN_SIZE) return false;
    const tcp_header_t* h = (const tcp_header_t*)packet;
    uint32_t header = (h->header_length_reserved >> 4) * 4u;
    if (header < TCP_HEADER_MIN_SIZE || header > length) return false;
    ip_address_t source = ip->source_ip;
    ip_address_t dest = ip->dest_ip;
    if (ip_finish_checksum(ip_pseudo_header_sum(&source, &dest, IP_PROTOCOL_TCP, (uint16_t)length), packet, length) != 0) {
        tcp_stats.checksum_errors++;
        return false;
    }
    seg->seq = be32(h->sequence_number);
    seg->ack = be32(h->acknowledgment_number);
    seg->flags = h->flags;
    seg->window = be16(h->window_size);
    seg->data = (const uint8_t*)packet + header;
    seg->length = length - header;
    seg->mss = TCP_MSS;
    const uint8_t* opt = (const uint8_t*)packet + TCP_HEADER_MIN_SIZE;
    for (uint32_t i = 0; i + 3 < header - TCP_HEADER_MIN_SIZE && opt[i] != 0; ) {
        if (opt[i] == 1) { i++; continue; }
        if (opt[i] == TCP_OPTION_MSS && opt[i + 1] == TCP_OPTION_MSS_LENGTH) seg->mss = (uint16_t)((opt[i + 2] << 8) | opt[i + 3]);
        if (opt[i + 1] < 2) break;
        i += opt[i + 1];
    }
    return true;
}

static tcp_socket_t* find_socket(const ip_address_t* local, uint16_t local_port, const ip_address_t* remote, uint16_t remote_port) {
    tcp_socket_t* listener = NULL;
    for (uint32_t i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_socket_t* s = &sockets[i];
        if (!s->in_use || s->local_port != local_port) continue;
        if (s->state == TCP_LISTEN) {
            listener = s;
            continue;
        }
        if (s->state != TCP_CLOSED && s->remote_port == remote_port && s->remote_ip.addr == remote->addr &&
            (s->local_ip.addr == 0 || s->local_ip.addr == local->addr)) {
            return s;
        }
    }
    return listener;
}

static void on_listen(tcp_socket_t* listener, const ip_header_t* ip, const tcp_header_t* h, const segment_t* seg) {
    if (!(seg->flags & TCP_FLAG_SYN) || (seg->flags & (TCP_FLAG_ACK | TCP_FLAG_RST))) return;
    if (listener->backlog_count >= listener->backlog_max) return;
    tcp_socket_t* child = tcp_create_socket();
    if (!child) return;
    child->local_ip = ip->dest_ip;
    child->remote_ip = ip->source_ip;
    child->local_port = listener->local_port;
    child->remote_port = be16(h->source_port);
    child->parent = listener;
    child->rcv_nxt = seg->seq + 1;
    child->snd_wnd = seg->window;
    child->mss = seg->mss < TCP_MSS ? seg->mss : TCP_MSS;
    child->iss = initial_sequence();
    child->snd_una = child->iss;
    child->snd_nxt = child->iss;
    child->state = TCP_SYN_RECEIVED;
    output(child);
}

static void on_syn_sent(tcp_socket_t* s, const segment_t* seg) {
    bool ack_ok = (seg->flags & TCP_FLAG_ACK) && seg->ack == s->iss + 1;
    if ((seg->flags & TCP_FLAG_ACK) && !ack_ok) return;
    if (seg->flags & TCP_FLAG_RST) {
        if (ack_ok) {
            s->reset = true;
            tcp_stats.resets_received++;
            if (s->on_connect) s->on_connect(s, false);
            enter_closed(s);
        }
        return;
    }
    if (!(seg->flags & TCP_FLAG_SYN)) return;
    s->rcv_nxt = seg->seq + 1;
    s->snd_wnd = seg->window;
    s->mss = seg->mss < TCP_MSS ? seg->mss : TCP_MSS;
    if (ack_ok) {
        s->snd_una = seg->ack;
        s->retries = 0;
        s->retransmit_at = 0;
        enter_established(s);
        send_ack(s);
        output(s);
    } else {
        s->state = TCP_SYN_RECEIVED;
        send_segment(s, s->iss, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);
    }
}

// Advances snd_una, frees acknowledged bytes and moves FIN states forward
static void process_ack(tcp_socket_t* s, const segment_t* seg) {
    if (!(seg->flags & TCP_FLAG_ACK) || !seq_lt(s->snd_una, seg->ack) || !seq_le(seg->ack, s->snd_nxt)) {
        if (seg->flags & TCP_FLAG_ACK) s->snd_wnd = seg->window;
        return;
    }
    uint32_t acked = seg->ack - s->snd_una;
    if (s->snd_una == s->iss) acked--;
    bool fin_acked = s->fin_sent && seg->ack == s->snd_nxt;
    if (fin_acked && acked) acked--;
    if (acked > s->tx_len) acked = s->tx_len;
    for (uint32_t i = acked; i < s->tx_len; i++) s->tx[i - acked] = s->tx[i];
    s->tx_len -= acked;
    s->snd_una = seg->ack;
    s->snd_wnd = seg->window;
    s->retries = 0;
    s->rto = TCP_INITIAL_RTO;
    s->retransmit_at = 0;

    if (s->state == TCP_SYN_RECEIVED) {
        enter_established(s);
        if (s->parent && s->parent->backlog_count < TCP_MAX_BACKLOG) {
            s->parent->backlog[s->parent->backlog_count++] = s;
        }
    }
    if (!fin_acked) return;
    if (s->state == TCP_FIN_WAIT_1) s->state = TCP_FIN_WAIT_2;
    else if (s->state == TCP_CLOSING) { s->state = TCP_TIME_WAIT; s->time_wait_until = get_system_time() + TCP_TIME_WAIT_TIMEOUT; }
    else if (s->state == TCP_LAST_ACK) enter_closed(s);
}

static bool accepts_data(const tcp_socket_t* s) {
    return s->state == TCP_ESTABLISHED || s->state == TCP_FIN_WAIT_1 || s->state == TCP_FIN_WAIT_2;
}

static uint32_t store_data(tcp_socket_t* s, const uint8_t* data, uint32_t length) {
    uint32_t space = receive_window(s);
    if (length > space) length = space;
    for (uint32_t i = 0; i < length; i++) s->rx[(s->rx_head + s->rx_len + i) % TCP_RX_BUFFER_SIZE] = data[i];
    s->rx_len += length;
    if (length && s->on_data) s->on_data(s, data, length);
    return length;
}

static void process_fin(tcp_socket_t* s) {
    s->rcv_nxt++;
    s->fin_received = true;
    if (s->state == TCP_ESTABLISHED) s->state = TCP_CLOSE_WAIT;
    else if (s->state == TCP_FIN_WAIT_1) s->state = TCP_CLOSING;
    else if (s->state == TCP_FIN_WAIT_2) {
        s->state = TCP_TIME_WAIT;
        s->time_wait_until = get_system_time() + TCP_TIME_WAIT_TIMEOUT;
    }
    if (s->on_close) s->on_close(s);
}

// In order data is kept, earlier bytes are trimmed and anything past rcv_nxt is dropped and acked again
static void on_synchronized(tcp_socket_t* s, const segment_t* seg) {
    if (seg->flags & TCP_FLAG_RST) {
        if (seq_le(s->rcv_nxt, seg->seq) && seq_lt(seg->seq, s->rcv_nxt + TCP_RX_BUFFER_SIZE)) {
            s->reset = true;
            tcp_stats.resets_received++;
            enter_closed(s);
        }
        return;
    }
    process_ack(s, seg);
    if (!s->in_use || s->state == TCP_CLOSED) return;

    const uint8_t* data = seg->data;
    uint32_t length = seg->length;
    uint32_t seq = seg->seq;
    bool need_ack = length > 0 || (seg->flags & TCP_FLAG_FIN);
    if (seq_lt(seq, s->rcv_nxt)) {
        uint32_t skip = s->rcv_nxt - seq;
        if (skip > length) skip = length;
        data += skip;
        length -= skip;
        seq += skip;
    }
    if (seq == s->rcv_nxt) {
        uint32_t taken = accepts_data(s) ? store_data(s, data, length) : 0;
        s->rcv_nxt += taken;
        if (taken == length && (seg->flags & TCP_FLAG_FIN) && !s->fin_received) process_fin(s);
    }
    if (need_ack) send_ack(s);
    output(s);
}

void tcp_process_packet(network_interface_t* iface, const ip_header_t* ip_header,
                       const void* tcp_packet, uint32_t length) {
    (void)iface;
    segment_t seg;
    if (!tcp_initialized || !parse_segment(ip_header, tcp_packet, length, &seg)) return;
    tcp_stats.segments_received++;
    const tcp_header_t* h = (const tcp_header_t*)tcp_packet;
    ip_address_t local = ip_header->dest_ip;
    ip_address_t remote = ip_header->source_ip;
    tcp_socket_t* s = find_socket(&local, be16(h->dest_port), &remote, be16(h->source_port));
    uint32_t seg_len = seg.length + ((seg.flags & TCP_FLAG_SYN) ? 1 : 0) + ((seg.flags & TCP_FLAG_FIN) ? 1 : 0);
    if (!s) {
        send_reset_reply(ip_header, h, seg_len);
        return;
    }
    if (s->state == TCP_LISTEN) on_listen(s, ip_header, h, &seg);
    else if (s->state == TCP_SYN_SENT) on_syn_sent(s, &seg);
    else on_synchronized(s, &seg);
}

/* application interface */

bool tcp_connect(tcp_socket_t* socket, const ip_address_t* remote_ip, uint16_t remote_port) {
    if (!socket || !remote_ip || socket->state != TCP_CLOSED) return false;
    if (!socket->local_port && !tcp_bind(socket, 0)) return false;
    socket->remote_ip = *remote_ip;
    socket->remote_port = remote_port;
    socket->local_ip = ip_source_for(remote_ip);
    if (socket->local_ip.addr == 0) return false;
    socket->iss = initial_sequence();
    socket->snd_una = socket->iss;
    socket->snd_nxt = socket->iss;
    socket->state = TCP_SYN_SENT;
    output(socket);
    uint32_t deadline = get_system_time() + TCP_CONNECT_TIMEOUT;
    while (socket->state == TCP_SYN_SENT || socket->state == TCP_SYN_RECEIVED) {
        if (get_system_time() >= deadline) {
            socket->state = TCP_CLOSED;
            return false;
        }
        network_poll();
    }
    return socket->state == TCP_ESTABLISHED;
}

int32_t tcp_send(tcp_socket_t* socket, const void* data, uint32_t length) {
    if (!socket || !data || socket->fin_queued) return -1;
    if (socket->state != TCP_ESTABLISHED && socket->state != TCP_CLOSE_WAIT) return -1;
    uint32_t space = TCP_TX_BUFFER_SIZE - socket->tx_len;
    if (length > space) length = space;
    copy_bytes(socket->tx + socket->tx_len, data, length);
    socket->tx_len += length;
    output(socket);
    return (int32_t)length;
}

// Returns 0 while the connection is open with nothing to read and -1 once the peer has finished
int32_t tcp_receive(tcp_socket_t* socket, void* buffer, uint32_t buffer_size) {
    if (!socket || !buffer || !socket->in_use) return -1;
    uint32_t length = socket->rx_len < buffer_size ? socket->rx_len : buffer_size;
    uint8_t* out = (uint8_t*)buffer;
    for (uint32_t i = 0; i < length; i++) out[i] = socket->rx[(socket->rx_head + i) % TCP_RX_BUFFER_SIZE];
    socket->rx_head = (socket->rx_head + length) % TCP_RX_BUFFER_SIZE;
    socket->rx_len -= length;
    bool open = socket->state == TCP_ESTABLISHED || socket->state == TCP_FIN_WAIT_1 || socket->state == TCP_FIN_WAIT_2;
    if (length && open && receive_window(socket) >= socket->last_window + WINDOW_UPDATE_THRESHOLD) send_ack(socket);
    if (length == 0 && (socket->fin_received || socket->state == TCP_CLOSED)) return -1;
    return (int32_t)length;
}

void tcp_close(tcp_socket_t* socket) {
    if (!socket || !socket->in_use) return;
    socket->app_closed = true;
    switch (socket->state) {
        case TCP_CLOSED:
        case TCP_LISTEN:
            for (uint8_t i = 0; i < socket->backlog_count; i++) tcp_close(socket->backlog[i]);
            release(socket);
            break;
        case TCP_SYN_SENT:
            enter_closed(socket);
            break;
        case TCP_SYN_RECEIVED:
        case TCP_ESTABLISHED:
        case TCP_CLOSE_WAIT:
            socket->fin_queued = true;
            if (socket->state == TCP_SYN_RECEIVED) socket->state = TCP_ESTABLISHED;
            output(socket);
            break;
        default:
            break;
    }
}

tcp_state_t tcp_get_state(const tcp_socket_t* socket) {
    return socket && socket->in_use ? socket->state : TCP_CLOSED;
}

bool tcp_get_remote(const tcp_socket_t* socket, ip_address_t* ip, uint16_t* port) {
    if (!socket || !socket->in_use) return false;
    if (ip) *ip = socket->remote_ip;
    if (port) *port = socket->remote_port;
    return true;
}

uint32_t tcp_unsent_bytes(const tcp_socket_t* socket) {
    return socket && socket->in_use ? socket->tx_len : 0;
}

const char* tcp_state_name(tcp_state_t state) {
    static const char* names[] = {"CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "FIN_WAIT_1",
                                  "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT"};
    return (uint32_t)state <= TCP_TIME_WAIT ? names[state] : "UNKNOWN";
}

uint32_t tcp_list_connections(tcp_connection_info_t* info, uint32_t max_entries) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < TCP_MAX_CONNECTIONS && count < max_entries; i++) {
        tcp_socket_t* s = &sockets[i];
        if (!s->in_use || (s->state == TCP_CLOSED && !s->local_port)) continue;
        info[count++] = (tcp_connection_info_t){s->state, s->local_ip, s->local_port, s->remote_ip, s->remote_port,
                                                s->tx_len, s->rx_len};
    }
    return count;
}

void tcp_set_connect_callback(tcp_socket_t* socket, void (*callback)(tcp_socket_t*, bool)) {
    if (socket) socket->on_connect = callback;
}

void tcp_set_data_callback(tcp_socket_t* socket, void (*callback)(tcp_socket_t*, const void*, uint32_t)) {
    if (socket) socket->on_data = callback;
}

void tcp_set_close_callback(tcp_socket_t* socket, void (*callback)(tcp_socket_t*)) {
    if (socket) socket->on_close = callback;
}

// Go back N: on timeout everything from snd_una is sent again with a doubled timeout
static void retransmit(tcp_socket_t* s) {
    if (++s->retries > TCP_MAX_RETRANSMITS) {
        send_segment(s, s->snd_nxt, TCP_FLAG_RST, NULL, 0);
        tcp_stats.resets_sent++;
        if (s->state == TCP_SYN_SENT && s->on_connect) s->on_connect(s, false);
        enter_closed(s);
        return;
    }
    tcp_stats.segments_retransmitted++;
    s->rto = s->rto * 2 > TCP_MAX_RTO ? TCP_MAX_RTO : s->rto * 2;
    s->retransmit_at = 0;
    s->snd_nxt = s->snd_una;
    if (s->fin_sent) {
        s->fin_sent = false;
        if (s->state == TCP_FIN_WAIT_1) s->state = TCP_ESTABLISHED;
        else if (s->state == TCP_LAST_ACK || s->state == TCP_CLOSING) s->state = TCP_CLOSE_WAIT;
    }
    output(s);
}

void tcp_process_timers(void) {
    if (!tcp_initialized) return;
    uint32_t now = get_system_time();
    for (uint32_t i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_socket_t* s = &sockets[i];
        if (!s->in_use) continue;
        if (s->state == TCP_TIME_WAIT && seq_le(s->time_wait_until, now)) enter_closed(s);
        else if (s->retransmit_at && seq_le(s->retransmit_at, now)) retransmit(s);
    }
}

tcp_statistics_t* tcp_get_statistics(void) {
    return tcp_initialized ? &tcp_stats : NULL;
}

void tcp_reset_statistics(void) {
    uint32_t active = tcp_stats.active_connections;
    tcp_stats = (tcp_statistics_t){0};
    tcp_stats.active_connections = active;
}