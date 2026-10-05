/* ps4_live0_payload.c — M2-LIVE0 console-side adapter payload.
 *
 * Delivered exactly once per attachment through the existing GoldHEN Payloader (TCP 9090,
 * HTTP POST /payload) and reuses the existing pinned libPS4 build (crt0.s + linker.x + libPS4.a)
 * plus libPS4's own kernel primitives:
 *
 *     get_kernel_base()                      -> KASLR kernel base of THIS boot
 *     get_memory_dump(kaddr, uaddr, size)    -> kernel read through the kernel's copyout
 *     get_firmware()                         -> firmware integer (13.52 -> 1352)
 *
 * It deliberately does NOT implement a second kernel read/write stack and exposes no shell or
 * command-execution primitive. The command surface is closed:
 *
 *     PING                       liveness + payload identity
 *     INFO                       firmware, kernel base, payload self-context, test-buffer address
 *     READ    kaddr=<hex> len=<hex>       bounded kernel read  (len <= 0x1000)
 *     WRITE   kaddr=<hex> hex=<hexbytes>  store into the payload's OWN user test buffer only
 *     VERIFY  kaddr=<hex> len=<hex>       direct user-space readback of the test buffer
 *     KREAD_USER kaddr=<hex> len=<hex>    independent readback of the test buffer via copyout
 *     QUIT                       leave
 *
 * Fail-closed properties enforced here, not merely by the host:
 *   - READ is refused outside the canonical kernel range; no MMIO window is ever touched.
 *   - WRITE is refused outside [test_buffer, test_buffer+size) — the only memory this payload owns.
 *   - VERIFY/KREAD_USER are refused outside that same range.
 *   - A kernel read that faults returns rc=-1 and is never retried.
 *   - No command reaches direct port I/O, MSRs, page tables or any device register.
 *   - Hard lifetime, idle timeout and a total read budget bound the resident window.
 *
 * Scope (M2-LIVE0): read-only kernel access, user-space mutation with verified restore. No kernel
 * writes, no persistent state, no service requests, no flash/NVS/SNVS/Syscon access.
 */

#include "ps4.h"

#define HOST_IP "192.168.1.148"
#define HOST_PORT 9025

#define PAYLOAD_ID "live2-trace-s1"
#define TEST_BUF_SIZE 0x1000u
#define TEST_BUF_FILL 0x5Au
#define TEST_BUF_FILL_B 0xA5u
#define MAX_READ 0x1000u
#define READ_BUDGET_BYTES (16u * 1024u * 1024u)
#define LIFETIME_SECONDS 900u
#define IDLE_SECONDS 180u
#define FRAME_MAX 0x20000

#define KERNEL_MIN 0xFFFF800000000000ull
/* Low MMIO windows (PCI/device BARs) that must never be read through this path. */
#define MMIO_LOW_LO 0x00000000E0000000ull
#define MMIO_LOW_HI 0x0000000100000000ull

/* Orbis returns SCE error codes from the sceNet* API, not plain -1: any code with the
 * 0x80410100 base is "0x80410100 + FreeBSD errno". Recv must therefore distinguish "no data yet"
 * from a real error, otherwise a quiet socket looks like a disconnect. */
#define SCE_NET_ERROR_EINTR 0x80410104u
#define SCE_NET_ERROR_EAGAIN 0x80410123u /* EWOULDBLOCK == EAGAIN on Orbis */

/* Phase 12R: reduzierte Write-Surface (Legacy-Write-Ops kompiliert aus) */
#ifndef TRACE_ONLY
#define TRACE_ONLY 1
#endif

static int g_sock = -1;
static uint64_t g_read_budget = READ_BUDGET_BYTES;
static int g_last_recv_error = 0;
static int g_recv_retries = 0;
/* Allocation provenance for the user test buffer: the host must be able to prove that the buffer
 * it writes into came from this payload instance's own allocation call, not from pattern or
 * pointer search. */
static int g_alloc_seq = 0;
static uint64_t g_alloc_ret = 0;
static uint64_t g_alloc_size = 0;
static uint64_t g_instance = 0;
/* LIVE1: two independent payload-owned allocations with their own generation counters. */
static uint64_t g_buf_a = 0, g_buf_b = 0;
static uint64_t g_buf_a_ret = 0, g_buf_b_ret = 0;
static uint64_t g_buf_a_size = 0, g_buf_b_size = 0;
static int g_buf_a_gen = 0, g_buf_b_gen = 0;

static int ssend(const void *b, int n) {
  const char *p = (const char *)b;
  int s = 0;
  while (s < n) {
    int k = sceNetSend(g_sock, (void *)(p + s), n - s, 0);
    if (k <= 0) return -1;
    s += k;
  }
  return 0;
}

static int send_frame(const char *body) {
  char head[10];
  int n = 0;
  while (body[n]) n++;
  if (n > FRAME_MAX) return -1;
  head[0] = '#';
  for (int i = 0; i < 8; i++) {
    int nib = (n >> ((7 - i) * 4)) & 0xF;
    head[1 + i] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
  }
  head[9] = 0;
  if (ssend(head, 9) != 0) return -1;
  if (n && ssend(body, n) != 0) return -1;
  return 0;
}

/* Returns 0 ok, -1 peer closed, -2 idle bound reached, -3 real socket error. */
static int recv_exact(void *dst, int n, uint64_t idle_deadline_us) {
  char *p = (char *)dst;
  int got = 0;
  while (got < n) {
    int k = sceNetRecv(g_sock, p + got, n - got, 0);
    if (k > 0) {
      got += k;
      continue;
    }
    if (k == 0) return -1;
    unsigned int code = (unsigned int)k;
    if (code == SCE_NET_ERROR_EINTR || code == SCE_NET_ERROR_EAGAIN) {
      if (sceKernelGetProcessTime() > idle_deadline_us) return -2;
      g_recv_retries++;
      sceKernelUsleep(10000); /* 10 ms */
      continue;
    }
    g_last_recv_error = (int)code;
    return -3;
  }
  return 0;
}

static int recv_frame(char *out, int cap) {
  char head[9];
  uint64_t idle_deadline = sceKernelGetProcessTime() + (uint64_t)IDLE_SECONDS * 1000000ull;
  int rc = recv_exact(head, 9, idle_deadline);
  if (rc != 0) return rc;
  if (head[0] != '#') return -4;
  int len = 0;
  for (int i = 1; i < 9; i++) {
    int d;
    char c = head[i];
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else return -1;
    len = (len << 4) | d;
  }
  if (len <= 0 || len >= cap) return -4;
  rc = recv_exact(out, len, idle_deadline);
  if (rc != 0) return rc;
  out[len] = 0;
  return len;
}

static int tcp_connect_to(const char *ip, int port, const char *tag) {
  for (int attempt = 0; attempt < 8; attempt++) {
    struct in_addr ia;
    struct sockaddr_in sk;
    sceNetInetPton(AF_INET, ip, &ia);
    memset(&sk, 0, sizeof(sk));
    sk.sin_len = sizeof(sk);
    sk.sin_family = AF_INET;
    sk.sin_addr = ia;
    sk.sin_port = sceNetHtons(port);
    int s = sceNetSocket(tag, AF_INET, SOCK_STREAM, 0);
    if (s < 0) continue;
    if (sceNetConnect(s, (struct sockaddr *)&sk, sizeof(sk)) == 0) return s;
    sceNetSocketClose(s);
    sceKernelSleep(1);
  }
  return -1;
}

/* ---- parsing helpers ---------------------------------------------------- */

static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, int cap) {
  int n = 0;
  int hi = -1;
  for (int i = 0; hex[i]; i++) {
    int v = hex_val(hex[i]);
    if (v < 0) return -1;
    if (hi < 0) {
      hi = v;
    } else {
      if (n >= cap) return -1;
      out[n++] = (uint8_t)((hi << 4) | v);
      hi = -1;
    }
  }
  if (hi >= 0) return -1;
  return n;
}

static uint64_t parse_hex_u64(const char *s, int *ok) {
  uint64_t v = 0;
  int i = 0;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) i = 2;
  if (!s[i]) {
    *ok = 0;
    return 0;
  }
  for (; s[i]; i++) {
    int d = hex_val(s[i]);
    if (d < 0) {
      *ok = 0;
      return 0;
    }
    v = (v << 4) | (uint64_t)d;
  }
  *ok = 1;
  return v;
}

static int key_value(const char *line, const char *key, char *out, int cap) {
  int klen = 0;
  while (key[klen]) klen++;
  for (int i = 0; line[i];) {
    while (line[i] == ' ') i++;
    int start = i;
    while (line[i] && line[i] != ' ') i++;
    int eq = -1;
    for (int j = start; j < i; j++) {
      if (line[j] == '=') {
        eq = j;
        break;
      }
    }
    if (eq < 0) continue;
    if (eq - start == klen) {
      int match = 1;
      for (int j = 0; j < klen; j++) {
        if (line[start + j] != key[j]) {
          match = 0;
          break;
        }
      }
      if (match) {
        int n = i - eq - 1;
        if (n >= cap) n = cap - 1;
        for (int j = 0; j < n; j++) out[j] = line[eq + 1 + j];
        out[n] = 0;
        return 1;
      }
    }
  }
  out[0] = 0;
  return 0;
}

/* Select the buffer named by buf=a|buf=b (default a) and return its base/size. */
static int select_buffer(const char *line, uint64_t *base, uint64_t *size) {
  char sel[8];
  if (key_value(line, "buf", sel, sizeof(sel)) && (sel[0] == 'b' || sel[0] == 'B')) {
    *base = g_buf_b;
    *size = g_buf_b_size;
    return 0;
  }
  *base = g_buf_a;
  *size = g_buf_a_size;
  return 0;
}

static int in_range(uint64_t a, uint64_t lo, uint64_t hi) {
  return a >= lo && a < hi;
}

static int kernel_readable(uint64_t a) {
  if (a < KERNEL_MIN) return 0;
  if (in_range(a, MMIO_LOW_LO, MMIO_LOW_HI)) return 0;
  return 1;
}

/* =====================================================================================
 * Phase 12R — korrigierter Stage-1-Trace-Block (FW 13.52, Liverpool-CIK)
 * BUILD-ONLY: gebaut und statisch verifiziert, NICHT deployt, KEINE Live-Aktion.
 *
 * Behebt 12Q-Findings F1 (kbase-Gate), F2/F3 (Gate-Paritaet), F5 (Response-Korrelation),
 * F6 (Stage-1-semantik) und haelt F4 (Health-Reihenfolge) auf der Host-Seite.
 *
 * Mechanik (unveraendert zur 12P-Geometrie, dort statisch verifiziert):
 *   0x4ddf73  e8 88 02 fd ff   call 0x4ae200    <- bestaetigte RB1-Submit-Site
 *   Patch      e9 <rel32>      -> Cave RVA 0x72b240 (14 Nullbytes, 16-B-aligned)
 *   Cave       48 b8 <imm64> ff e0   mov rax,&rb1_trampoline ; jmp rax   (12 von 14 B)
 *
 * Zustandskette (monoton, keine Phase wird im Erfolgsfall uebersprungen):
 *   phase 0xFFFFFFFF = unarmed (Payload-Start)
 *   phase 0          = armed          (gesetzt im Install, VOR dem Hook-Write)
 *   phase 1          = trampoline entered   (Sieger des atomaren One-Shot)
 *   phase 2          = original call completed (Rueckkehrziel rb1_after_call erreicht)
 *   phase 3          = continuation reached    (Handoff an kbase+0x4ddf78)
 *   Fatalzustaende laufen NICHT ueber phase, sondern ueber fatal_code (Monotonie bleibt).
 *
 * Write-Surface (vollstaendig, zugleich Store-Census-Grundlage):
 *   Kerneltext: (1) Cave-Stub, (2) Hooksite-Patch, (3) Restore Hooksite, (4) Restore Cave.
 *   Sonst nur payload-eigene Globals/Stack. KEIN Source-Read, KEINE Fremdspeicher-Deref,
 *   kein Stage 2/3 (compile-time ausgeschlossen).
 * ===================================================================================== */
#define TRACE_FW_EXPECTED  1352u
#define HOOK_RVA           0x4DDF73u
#define HOOK_WIN_RVA       0x4DDF63u
#define HOOK_LEN           5u
#define HOOK_WIN_LEN       22u
#define CAVE_RVA           0x72B240u
#define CAVE_LEN           14u
#define STUB_LEN           12u
#define RET_RVA            0x4DDF78u
#define CALLEE_RVA         0x4AE200u
#define A3_ANCHOR_RVA      0x4DC9F0u
#define A3_ANCHOR_LEN      32u
#define KERNEL_TEXT_LEN    0xCFE758u
#define PHASE_UNARMED      0xFFFFFFFFu
#define PHASE_ARMED        0u
#define PHASE_ENTERED      1u
#define PHASE_CALL_RETURN  2u
#define PHASE_CONTINUATION 3u
#define INSTALL_NONE       0u
#define INSTALL_ARMED      1u
#define INSTALL_RESTORED   2u
#define INSTALL_FAILED     3u
#define TRACE_MAGIC        0x52325452u   /* 'RT2R' */

/* Bytes aus dem FW13.52-Image (kernel.bin sha256 cf157ffd…ca35). */
static const unsigned char K_A3_ANCHOR[A3_ANCHOR_LEN] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x81, 0xEC,
    0xA8, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x25, 0x95, 0x04, 0x28, 0x02, 0x48, 0x8D, 0x3D, 0x44, 0xA0};
static const unsigned char K_HOOK_ORIG[HOOK_LEN] = {0xE8, 0x88, 0x02, 0xFD, 0xFF};
static const unsigned char K_HOOK_WIN[HOOK_WIN_LEN] = {
    0x8B, 0x08, 0x48, 0x8B, 0x78, 0x10, 0x41, 0x8B, 0x74, 0x24, 0x04, 0x49, 0x8B, 0x54, 0x24, 0x08,
    0xE8, 0x88, 0x02, 0xFD, 0xFF, 0x89};
static const unsigned char K_CAVE_ORIG[CAVE_LEN] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* Stage-1-Struktur: bewusst OHNE r12/src/count/source — was nicht existiert, kann nicht
 * gelesen und nicht geschrieben werden (struktureller Ausschluss von Fremdspeicher-Reads). */
struct rb1_trace_s {
  uint32_t magic;          /* 0x00 'RT2R' */
  uint32_t phase;          /* 0x04 PHASE_* (Monotonie) */
  uint32_t extra_hits;     /* 0x08 atomar; weitere Hook-Eintritte, KEINE Trace-Daten */
  uint32_t stage;          /* 0x0c immer 1 */
  uint64_t hit_count;      /* 0x10 atomar 0 -> 1 */
  uint32_t install_state;  /* 0x18 INSTALL_* */
  uint32_t gate_mask;      /* 0x1c Maske des letzten Install-Versuchs */
  uint64_t err_code;       /* 0x20 */
  uint64_t fatal_code;     /* 0x28 0 = kein fataler Zustand */
  uint64_t restore_ok;     /* 0x30 */
  uint64_t kbase;          /* 0x38 */
  uint64_t hook_va;        /* 0x40 */
  uint64_t cave_va;        /* 0x48 */
  uint64_t callee_va;      /* 0x50 */
  uint64_t cont_va;        /* 0x58 */
  uint64_t after_va;       /* 0x60 Zustandsmarken-Stub im Payload */
  uint64_t rb_hook;        /* 0x68 Readback Hooksite */
  uint64_t rb_cave;        /* 0x70 Readback Cave */
};
_Static_assert(sizeof(struct rb1_trace_s) == 0x78, "trace size");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, phase) == 0x04, "off");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, extra_hits) == 0x08, "off");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, stage) == 0x0c, "off");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, hit_count) == 0x10, "off");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, install_state) == 0x18, "off");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, gate_mask) == 0x1c, "off");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, err_code) == 0x20, "off");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, fatal_code) == 0x28, "off");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, restore_ok) == 0x30, "off");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, hook_va) == 0x40, "off");
_Static_assert(__builtin_offsetof(struct rb1_trace_s, after_va) == 0x60, "off");

/* Alle vom Assembly referenzierten Symbole: hidden -> keine Relocations (Projektregel). */
__attribute__((visibility("hidden"))) volatile struct rb1_trace_s g_trace;
__attribute__((visibility("hidden"))) uint64_t g_callee_slot;   /* kbase+0x4ae200 */
__attribute__((visibility("hidden"))) uint64_t g_cont_slot;     /* kbase+0x4ddf78 */
__attribute__((visibility("hidden"))) uint64_t g_after_slot;    /* &rb1_after_call */
extern void rb1_trampoline(void) __attribute__((visibility("hidden")));
extern void rb1_after_call(void) __attribute__((visibility("hidden")));
static unsigned char g_hook_patch[HOOK_LEN];
static unsigned char g_stub_patch[STUB_LEN];

/* ---- CPU-Zustand (unveraendert gegenueber 12P, dort verifiziert) ------------------- */
static inline uint64_t rb1_read_cr0(void) {
  uint64_t v;
  __asm__ volatile("mov %%cr0, %0" : "=r"(v));
  return v;
}
static inline void rb1_write_cr0(uint64_t v) {
  __asm__ volatile("mov %0, %%cr0" ::"r"(v) : "memory");
}
static void rb1_text_write(uint64_t addr, const unsigned char *bytes, uint32_t len) {
  uint64_t cr0 = rb1_read_cr0();
  rb1_write_cr0(cr0 & ~(1ull << 16));                 /* WP aus, nur fuer diese Bytes */
  volatile unsigned char *dst = (volatile unsigned char *)addr;
  for (uint32_t i = 0; i < len; i++) dst[i] = bytes[i];
  rb1_write_cr0(cr0);
  __asm__ volatile("mfence" ::: "memory");
}
static uint32_t rb1_bytes_equal(const unsigned char *a, const unsigned char *b, uint32_t n) {
  for (uint32_t i = 0; i < n; i++) if (a[i] != b[i]) return 0u;
  return 1u;
}
static uint64_t rb1_readback64(uint64_t addr, uint32_t n) {
  uint64_t v = 0;
  const volatile unsigned char *src = (const volatile unsigned char *)addr;
  for (uint32_t i = 0; i < n && i < 8u; i++) v |= ((uint64_t)src[i]) << (8u * i);
  return v;
}
static uint32_t rb1_parse_u32(const char *s) {
  uint32_t v = 0;
  for (int i = 0; s[i] && i < 10; i++) {
    if (s[i] < '0' || s[i] > '9') break;
    v = v * 10u + (uint32_t)(s[i] - '0');
  }
  return v;
}

/* ---- Gate-Maske: GENERIERT (gates_12r.inc) — identischer Ausdruckstext wie Host-seitig -- */
/* ---- ab hier GENERIERT aus work/gates_12r.py (nicht editieren) ---- */
/* =====================================================================================
 * gates_12r.inc — GENERIERT von work/gates_12r.py (Single Source of Truth).
 * NICHT editieren: Aenderungen gehoeren in die DSL in gates_12r.py.
 *
 * Bit i = Gate i. RB1_GATE_ALL = Installation erlaubt. Jede Abweichung => Maske != ALL
 * => rb1_install kehrt VOR jedem Textwrite zurueck (fail-closed).
 * Orakel: bytes_eq -> rb1_bytes_equal (im Payload echtes Kernel-Lesen).
 * ===================================================================================== */
#define RB1_GATE_COUNT 15
#define RB1_GATE_ALL   ((1u << RB1_GATE_COUNT) - 1u)

struct rb1_gate_ctx {
  uint64_t kbase;
  uint64_t hit_count;
  int64_t  rel64;
  uint32_t fw;
  uint32_t phase;
  uint32_t stage;
};

#define bytes_eq(addr, expect, n) rb1_bytes_equal((const unsigned char *)(addr), \
                                                 (const unsigned char *)(expect), (uint32_t)(n))

/* [0] kbase_canonical (runtime) — kbase ist kanonische Kernel-VA der oberen Haelfte (4-Level-Paging) */
/* [1] kbase_image_window (runtime) — kbase liegt im erwarteten Kernel-Image-Fenster [-2 GiB, -768 MiB] */
/* [2] kbase_alignment_attested (runtime) — 256-KiB-Alignment: das am Live-Layout BELEGTE Alignment, nicht steifer fordern */
/* [3] firmware_is_fw1352 (runtime) — gemeldete Firmware ist FW13.52 */
/* [4] stage_permitted (runtime) — nur Stage 1 in dieser Freigabe; Stage 2/3 -> Ablehnung ohne Write */
/* [5] phase_unarmed (runtime) — Trace-State unarmed/idle (Install genau einmal) */
/* [6] hit_count_zero (runtime) — kein Sample vorhanden (One-Shot) */
/* [7] a3_anchor_exact (runtime) — A3-Anker 32 Byte byte-exakt gegen FW13.52-Image */
/* [8] hook_window_exact (runtime) — 22-Byte-Hookfenster byte-exakt */
/* [9] hook_site_exact (runtime) — 5 Originalbytes der Hooksite (schliesst 'bereits gepatcht' aus) */
/* [10] cave_original_exact (runtime) — Cave traegt die dokumentierten 14 Nullbytes */
/* [11] rel32_reachable (static) — e9-rel32 Hooksite->Cave in int32-Reichweite (vorzeichenfrei formuliert, damit der C-Vergleich nicht in unsigned kippt) */
/* [12] rva_bounds (static) — alle benutzten RVA + Laengen im belegten Kernel-Textbereich (0xCFE758) */
/* [13] bin_hash_is_release (host) — Host: ausgeliefertes BIN ist das neu gebaute, hashgebundene Artefakt */
/* [14] bin_hash_not_retired_12p (host) — Host: das retired 12P-BIN ist ausdruecklich ausgeschlossen */

__attribute__((visibility("hidden"))) uint32_t rb1_gate_mask(const struct rb1_gate_ctx *c) {
  const uint64_t kbase = c->kbase, hit_count = c->hit_count;
  const int64_t rel64 = c->rel64;
  const uint32_t fw = c->fw, phase = c->phase, stage = c->stage;
  (void)kbase; (void)hit_count; (void)rel64; (void)fw; (void)phase; (void)stage;
  uint32_t m = RB1_GATE_ALL;
  m &= (((kbase >> 48) == 0xFFFF && kbase >= 0xFFFFFFFF80000000) ? (1u << 0) : 0u) | ~(1u << 0);  /* kbase_canonical */
  m &= ((kbase >= 0xFFFFFFFF80000000 && kbase <= 0xFFFFFFFFD0000000) ? (1u << 1) : 0u) | ~(1u << 1);  /* kbase_image_window */
  m &= (((kbase & 0x3FFFF) == 0) ? (1u << 2) : 0u) | ~(1u << 2);  /* kbase_alignment_attested */
  m &= ((fw == 1352) ? (1u << 3) : 0u) | ~(1u << 3);  /* firmware_is_fw1352 */
  m &= ((stage == 1) ? (1u << 4) : 0u) | ~(1u << 4);  /* stage_permitted */
  m &= ((phase == 0xFFFFFFFF) ? (1u << 5) : 0u) | ~(1u << 5);  /* phase_unarmed */
  m &= ((hit_count == 0) ? (1u << 6) : 0u) | ~(1u << 6);  /* hit_count_zero */
  m &= ((bytes_eq(kbase + 0x4DC9F0, K_A3_ANCHOR, 32)) ? (1u << 7) : 0u) | ~(1u << 7);  /* a3_anchor_exact */
  m &= ((bytes_eq(kbase + 0x4DDF63, K_HOOK_WIN, 22)) ? (1u << 8) : 0u) | ~(1u << 8);  /* hook_window_exact */
  m &= ((bytes_eq(kbase + 0x4DDF73, K_HOOK_ORIG, 5)) ? (1u << 9) : 0u) | ~(1u << 9);  /* hook_site_exact */
  m &= ((bytes_eq(kbase + 0x72B240, K_CAVE_ORIG, 14)) ? (1u << 10) : 0u) | ~(1u << 10);  /* cave_original_exact */
  m &= (((0x72B240 - (0x4DDF73 + 5)) <= 0x7FFFFFFF && (0x72B240 - (0x4DDF73 + 5)) >= 0 && (0x4DDF73 + 5) - 0x72B240 <= 0x7FFFFFFF) ? (1u << 11) : 0u) | ~(1u << 11);  /* rel32_reachable */
  m &= ((0x4DC9F0 + 32 <= 0xCFE758 && 0x4DDF63 + 22 <= 0xCFE758 && 0x4DDF73 + 5 <= 0xCFE758 && 0x72B240 + 14 <= 0xCFE758 && 0x4AE200 <= 0xCFE758 && 0x4DDF78 <= 0xCFE758) ? (1u << 12) : 0u) | ~(1u << 12);  /* rva_bounds */
  return m & RB1_GATE_ALL;
}

/* Compile-Zeit-Gates (kind=static) — identische Ausdruecke wie Host-seitig. */
_Static_assert(((0x72B240 - (0x4DDF73 + 5)) <= 0x7FFFFFFF && (0x72B240 - (0x4DDF73 + 5)) >= 0 && (0x4DDF73 + 5) - 0x72B240 <= 0x7FFFFFFF), "gate rel32_reachable");
_Static_assert((0x4DC9F0 + 32 <= 0xCFE758 && 0x4DDF63 + 22 <= 0xCFE758 && 0x4DDF73 + 5 <= 0xCFE758 && 0x72B240 + 14 <= 0xCFE758 && 0x4AE200 <= 0xCFE758 && 0x4DDF78 <= 0xCFE758), "gate rva_bounds");
_Static_assert(5103480 <= 13625176, "hook bound");
_Static_assert(7516750 <= 13625176, "cave bound");

#define RB1_GATE_ALL_EXPECTED RB1_GATE_ALL

/* ---- Restore: der EINE Pfad fuer alle Zustaende nach dem ersten Textwrite ---------- */
__attribute__((visibility("hidden"))) uint32_t rb1_restore_patches(void) {
  static const unsigned char zero[CAVE_LEN] = {0};
  uint64_t hook_va = g_trace.hook_va, cave_va = g_trace.cave_va;
  if (!hook_va || !cave_va) {                       /* nichts installiert: kein Write */
    g_trace.err_code = 0xF1u; g_trace.fatal_code = 0xF1u;
    g_trace.restore_ok = 0u; g_trace.install_state = INSTALL_FAILED;
    return 0u;
  }
  rb1_text_write(hook_va, K_HOOK_ORIG, HOOK_LEN);   /* Textwrite 3 */
  rb1_text_write(cave_va, zero, CAVE_LEN);          /* Textwrite 4 */
  g_trace.rb_hook = rb1_readback64(hook_va, HOOK_LEN);
  g_trace.rb_cave = rb1_readback64(cave_va, CAVE_LEN);
  if (rb1_bytes_equal((const unsigned char *)hook_va, K_HOOK_ORIG, HOOK_LEN) &&
      rb1_bytes_equal((const unsigned char *)cave_va, zero, CAVE_LEN)) {
    g_trace.restore_ok = 1u; g_trace.install_state = INSTALL_RESTORED;
    return 1u;
  }
  /* Kein stiller Teilzustand: explizit fatal (Host darf danach NICHT weitermachen). */
  g_trace.restore_ok = 0u; g_trace.install_state = INSTALL_FAILED;
  g_trace.fatal_code = 0xF2u; g_trace.err_code = 0xF2u;
  return 0u;
}

__attribute__((visibility("hidden"))) void rb1_on_capture(void) { (void)rb1_restore_patches(); }

/* Fehlerpfad nach einem Textwrite: immer erst restaurieren, dann fatal markieren. */
static uint32_t rb1_fail_after_write(uint32_t err) {
  g_trace.err_code = err;
  (void)rb1_restore_patches();
  if (!g_trace.restore_ok) g_trace.fatal_code = 0xF3u;
  return err;
}

/* ---- Installation: Gate-Maske VOR jedem Textwrite (fail-closed) ------------------- */
__attribute__((visibility("hidden"))) uint32_t rb1_install(uint64_t kbase, uint32_t stage) {
  struct rb1_gate_ctx c;
  uint64_t hook_va, cave_va;
  uint32_t m;
  int64_t rel;

  if (g_trace.magic != TRACE_MAGIC) {              /* Lazy-Init: unarmed, kein Sample */
    g_trace.magic = TRACE_MAGIC;
    g_trace.phase = PHASE_UNARMED;
    g_trace.stage = 1u;
    g_trace.install_state = INSTALL_NONE;
  }
  c.kbase = kbase;
  c.hit_count = g_trace.hit_count;
  c.rel64 = (int64_t)(CAVE_RVA - (HOOK_RVA + HOOK_LEN));
  c.fw = (uint32_t)get_firmware();
  c.phase = g_trace.phase;
  c.stage = stage;
  m = rb1_gate_mask(&c);
  g_trace.gate_mask = m;                            /* payload-eigener Store, kein Textwrite */
  g_trace.stage = stage;
  if (m != RB1_GATE_ALL_EXPECTED) {                 /* KEIN Textwrite in diesem Zweig */
    g_trace.err_code = 0xE3u;
    return 0xE3u;
  }
  hook_va = kbase + HOOK_RVA;
  cave_va = kbase + CAVE_RVA;
  g_trace.kbase = kbase;
  g_trace.hook_va = hook_va;
  g_trace.cave_va = cave_va;
  g_trace.callee_va = kbase + CALLEE_RVA;
  g_trace.cont_va = kbase + RET_RVA;
  g_trace.after_va = (uint64_t)(uintptr_t)&rb1_after_call;
  g_callee_slot = g_trace.callee_va;
  g_cont_slot = g_trace.cont_va;
  g_after_slot = g_trace.after_va;
  rel = (int64_t)(cave_va - (hook_va + HOOK_LEN));
  g_stub_patch[0] = 0x48; g_stub_patch[1] = 0xB8;   /* mov rax, imm64 */
  { uint64_t t = (uint64_t)(uintptr_t)&rb1_trampoline;
    for (int i = 0; i < 8; i++) g_stub_patch[2 + i] = (unsigned char)(t >> (8 * i)); }
  g_stub_patch[10] = 0xFF; g_stub_patch[11] = 0xE0; /* jmp rax */
  for (int i = 0; i < 4; i++) g_hook_patch[1 + i] = (unsigned char)((rel >> (8 * i)) & 0xFF);
  g_hook_patch[0] = 0xE9;
  g_trace.phase = PHASE_ARMED;                      /* armed VOR dem Hook-Write */
  g_trace.install_state = INSTALL_ARMED;
  /* Reihenfolge: erst Cave-Stub, dann Hook -> der Hook zeigt nie auf einen halben Stub. */
  rb1_text_write(cave_va, g_stub_patch, STUB_LEN);  /* Textwrite 1 */
  g_trace.rb_cave = rb1_readback64(cave_va, CAVE_LEN);
  if (!rb1_bytes_equal((const unsigned char *)cave_va, g_stub_patch, STUB_LEN))
    return rb1_fail_after_write(0xE9u);
  rb1_text_write(hook_va, g_hook_patch, HOOK_LEN);  /* Textwrite 2 */
  g_trace.rb_hook = rb1_readback64(hook_va, HOOK_LEN);
  if (!rb1_bytes_equal((const unsigned char *)hook_va, g_hook_patch, HOOK_LEN))
    return rb1_fail_after_write(0xEAu);
  return 0u;
}

/* ---- Trampoline + Zustandsmarken-Stub --------------------------------------------- */
/* Eintritt: wie ein realer Eintritt in 0x4ae200 (rsp = R, keine Ruecksprungadresse).
 * Ausgang: push g_after_slot ; push g_callee_slot ; ret  == call g_callee_slot  OHNE
 *          Registerbenutzung; danach rsp = R-8 mit [R-8] = g_after_slot, exakt wie ein
 *          Original-call, dessen Rueckkehrziel der Zustandsmarken-Stub ist.
 * One-Shot: hit_count 0 -> 1 atomar (lock xchg). Verlierer schreiben KEINE Trace-Daten,
 * extra_hits wird atomar gezaehlt, der Originalaufruf laeuft in beiden Faellen. */
__asm__(
    ".text\n"
    ".globl rb1_trampoline\n"
    ".hidden rb1_trampoline\n"
    ".type rb1_trampoline,@function\n"
    "rb1_trampoline:\n"
    "  pushfq\n"
    "  push %rax\n  push %rcx\n  push %rdx\n  push %rsi\n  push %rdi\n"
    "  push %r8\n   push %r9\n   push %r10\n push %r11\n"
    "  cld\n"
    "  cmpl $0, g_trace+0x04(%rip)\n"                  /* phase == armed ? */
    "  jne 8f\n"
    "  movl $1, %eax\n"
    "  lock xchgl %eax, g_trace+0x10(%rip)\n"          /* hit_count atomar 0 -> 1 */
    "  testl %eax, %eax\n"
    "  jne 8f\n"                                       /* schon ein Sample -> kein Write */
    "  movl $1, g_trace+0x04(%rip)\n"                  /* phase = trampoline entered */
    "  call rb1_on_capture\n"                          /* Selbstrestore vor dem Originalcall */
    "  jmp 9f\n"
    "8:\n"
    "  lock incl g_trace+0x08(%rip)\n"                 /* extra_hits++ (keine Trace-Daten) */
    "9:\n"
    "  pop %r11\n  pop %r10\n pop %r9\n  pop %r8\n"
    "  pop %rdi\n  pop %rsi\n pop %rdx\n pop %rcx\n pop %rax\n"
    "  popfq\n"
    "  pushq g_after_slot(%rip)\n"
    "  pushq g_callee_slot(%rip)\n"
    "  ret\n"
    ".size rb1_trampoline, .-rb1_trampoline\n"
    /* Zustandsmarken-Stub: wird AUSSCHLIESSLICH ueber das ret des Original-callee erreicht.
     * Nur MOV-Immediate-Stores + push/ret: kein Register- und kein Flag-Clobber. */
    ".globl rb1_after_call\n"
    ".hidden rb1_after_call\n"
    ".type rb1_after_call,@function\n"
    "rb1_after_call:\n"
    "  movl $2, g_trace+0x04(%rip)\n"                  /* phase = original call completed */
    "  movl $3, g_trace+0x04(%rip)\n"                  /* phase = continuation reached */
    "  pushq g_cont_slot(%rip)\n"
    "  ret\n"
    ".size rb1_after_call, .-rb1_after_call\n");

/* ---- Host-Steuerung mit Request-Korrelation (12Q-F5) ------------------------------ */
static void cmd_trace(const char *line) {
  char out[1600];
  char op[16], req[24], sv[8];
  unsigned int p;
  uint32_t rid = 0;
  if (key_value(line, "req", req, sizeof(req))) rid = rb1_parse_u32(req);
  if (key_value(line, "op", op, sizeof(op)) && op[0] == 'i') {
    uint32_t st, rc;
    if (!key_value(line, "stage", sv, sizeof(sv))) {
      p = 0;
      p += (unsigned int)sprintf(out + p, "ERR TRACE req=%u code=3 msg=missing_stage", rid);
      return (void)send_frame(out);
    }
    st = rb1_parse_u32(sv);
    if (st != 1u) {                       /* Stage 2/3 in dieser Freigabe nicht erlaubt */
      p = 0;
      p += (unsigned int)sprintf(out + p,
              "ERR TRACE req=%u code=2 msg=stage_not_permitted stage=%u text_writes=0", rid, st);
      return (void)send_frame(out);
    }
    rc = rb1_install(get_kernel_base(), st);
    p = 0;
    p += (unsigned int)sprintf(out + p,
        "OK TRACE req=%u op=install rc=0x%x phase=%u install_state=%u gate_mask=0x%x "
        "hook_va=0x%llx cave_va=0x%llx after_va=0x%llx",
        rid, rc, (unsigned)g_trace.phase, (unsigned)g_trace.install_state,
        (unsigned)g_trace.gate_mask, (unsigned long long)g_trace.hook_va,
        (unsigned long long)g_trace.cave_va, (unsigned long long)g_trace.after_va);
    return (void)send_frame(out);
  }
  if (key_value(line, "op", op, sizeof(op)) && op[0] == 'r') {
    uint32_t ok = rb1_restore_patches();
    p = 0;
    p += (unsigned int)sprintf(out + p,
        "OK TRACE req=%u op=restore restore_ok=%u install_state=%u fatal=0x%llx rb_hook=0x%llx "
        "rb_cave=0x%llx", rid, ok, (unsigned)g_trace.install_state,
        (unsigned long long)g_trace.fatal_code, (unsigned long long)g_trace.rb_hook,
        (unsigned long long)g_trace.rb_cave);
    return (void)send_frame(out);
  }
  if (key_value(line, "op", op, sizeof(op)) && op[0] == 'w') {
    char hex[40];
    if (!g_trace.hook_va) {
      p = 0;
      p += (unsigned int)sprintf(out + p, "ERR TRACE req=%u code=1 msg=not_installed", rid);
      return (void)send_frame(out);
    }
    for (int i = 0; i < (int)HOOK_LEN; i++)
      sprintf(hex + 2 * i, "%02x", ((const unsigned char *)g_trace.hook_va)[i]);
    hex[2 * HOOK_LEN] = 0;
    p = 0;
    p += (unsigned int)sprintf(out + p,
        "OK TRACE req=%u op=rw hook_bytes=%s hook_orig=%d cave_restored=%d rb_hook=0x%llx "
        "rb_cave=0x%llx", rid, hex,
        (int)rb1_bytes_equal((const unsigned char *)g_trace.hook_va, K_HOOK_ORIG, HOOK_LEN),
        (int)rb1_bytes_equal((const unsigned char *)g_trace.cave_va, K_CAVE_ORIG, CAVE_LEN),
        (unsigned long long)g_trace.rb_hook, (unsigned long long)g_trace.rb_cave);
    return (void)send_frame(out);
  }
  {                    /* Default: Status (keine Trace-/Fremddaten, Stage 1 only) */
    unsigned int q = 0;
    q += (unsigned int)sprintf(out + q,
        "OK TRACE req=%u phase=%u install_state=%u hit=%llu extra=%u stage=%u gate_mask=0x%x "
        "restore_ok=%llu err=0x%llx fatal=0x%llx kbase=0x%llx hook_va=0x%llx cave_va=0x%llx "
        "callee_va=0x%llx cont_va=0x%llx after_va=0x%llx rb_hook=0x%llx rb_cave=0x%llx",
        rid, (unsigned)g_trace.phase, (unsigned)g_trace.install_state,
        (unsigned long long)g_trace.hit_count, (unsigned)g_trace.extra_hits,
        (unsigned)g_trace.stage, (unsigned)g_trace.gate_mask,
        (unsigned long long)g_trace.restore_ok, (unsigned long long)g_trace.err_code,
        (unsigned long long)g_trace.fatal_code, (unsigned long long)g_trace.kbase,
        (unsigned long long)g_trace.hook_va, (unsigned long long)g_trace.cave_va,
        (unsigned long long)g_trace.callee_va, (unsigned long long)g_trace.cont_va,
        (unsigned long long)g_trace.after_va, (unsigned long long)g_trace.rb_hook,
        (unsigned long long)g_trace.rb_cave);
    (void)p;
    send_frame(out);
  }
}

/* ---- command handlers --------------------------------------------------- */

static void cmd_read(const char *line, uint64_t buf, uint64_t buflen) {
  (void)buflen;
  char raw[32], hexbuf[64];
  int ok = 0;
  if (!key_value(line, "kaddr", raw, sizeof(raw))) {
    send_frame("ERR READ code=1 msg=missing_kaddr");
    return;
  }
  uint64_t kaddr = parse_hex_u64(raw, &ok);
  if (!ok || !key_value(line, "len", hexbuf, sizeof(hexbuf))) {
    send_frame("ERR READ code=2 msg=bad_args");
    return;
  }
  uint64_t len = parse_hex_u64(hexbuf, &ok);
  if (!ok || len == 0 || len > MAX_READ) {
    send_frame("ERR READ code=3 msg=len_out_of_range");
    return;
  }
  if (!kernel_readable(kaddr)) {
    send_frame("ERR READ code=4 msg=address_not_readable");
    return;
  }
  if (len > g_read_budget) {
    send_frame("ERR READ code=5 msg=read_budget_exhausted");
    return;
  }
  uint8_t *dst = (uint8_t *)buf; /* the payload's own user buffer as the copyout target */
  memset(dst, 0, TEST_BUF_SIZE < len ? TEST_BUF_SIZE : (int)len);
  int rc = get_memory_dump(kaddr, (uint64_t *)dst, len);
  if (rc != 0) {
    char msg[96];
    sprintf(msg, "ERR READ code=6 msg=read_fault rc=%d", rc);
    send_frame(msg);
    return;
  }
  g_read_budget -= len;
  static char out[2 * MAX_READ + 128];
  int pos = 0;
  pos += sprintf(out + pos, "OK READ kaddr=0x%llx len=0x%llx rc=0 hex=",
                 (unsigned long long)kaddr, (unsigned long long)len);
  for (uint64_t i = 0; i < len; i++) {
    uint8_t b = dst[i];
    out[pos++] = "0123456789abcdef"[b >> 4];
    out[pos++] = "0123456789abcdef"[b & 0xF];
  }
  out[pos] = 0;
  send_frame(out);
}

static void cmd_write(const char *line, uint64_t buf, uint64_t buflen) {
  char raw[32], hexbuf[2 * MAX_READ + 8];
  int ok = 0;
  if (!key_value(line, "kaddr", raw, sizeof(raw))) {
    send_frame("ERR WRITE code=1 msg=missing_kaddr");
    return;
  }
  uint64_t kaddr = parse_hex_u64(raw, &ok);
  if (!ok || !key_value(line, "hex", hexbuf, sizeof(hexbuf))) {
    send_frame("ERR WRITE code=2 msg=bad_args");
    return;
  }
  uint8_t data[MAX_READ];
  int n = hex_to_bytes(hexbuf, data, sizeof(data));
  if (n <= 0) {
    send_frame("ERR WRITE code=3 msg=bad_hex");
    return;
  }
  /* The only writable memory in LIVE0 is this payload's own user test buffer. */
  if (kaddr < buf || kaddr + (uint64_t)n > buf + buflen) {
    send_frame("ERR WRITE code=4 msg=outside_test_buffer");
    return;
  }
  for (int i = 0; i < n; i++) ((uint8_t *)buf)[kaddr - buf + i] = data[i];
  char msg[96];
  sprintf(msg, "OK WRITE kaddr=0x%llx len=0x%x rc=0", (unsigned long long)kaddr, n);
  send_frame(msg);
}

static void cmd_verify(const char *line, uint64_t buf, uint64_t buflen) {
  char raw[32], hexbuf[64];
  int ok = 0;
  if (!key_value(line, "kaddr", raw, sizeof(raw))) {
    send_frame("ERR VERIFY code=1 msg=missing_kaddr");
    return;
  }
  uint64_t kaddr = parse_hex_u64(raw, &ok);
  if (!ok || !key_value(line, "len", hexbuf, sizeof(hexbuf))) {
    send_frame("ERR VERIFY code=2 msg=bad_args");
    return;
  }
  uint64_t len = parse_hex_u64(hexbuf, &ok);
  if (!ok || len == 0 || len > MAX_READ) {
    send_frame("ERR VERIFY code=3 msg=len_out_of_range");
    return;
  }
  if (kaddr < buf || kaddr + len > buf + buflen) {
    send_frame("ERR VERIFY code=4 msg=outside_test_buffer");
    return;
  }
  static char out[2 * MAX_READ + 128];
  int pos = 0;
  pos += sprintf(out + pos, "OK VERIFY kaddr=0x%llx len=0x%llx hex=",
                 (unsigned long long)kaddr, (unsigned long long)len);
  for (uint64_t i = 0; i < len; i++) {
    uint8_t b = ((uint8_t *)buf)[kaddr - buf + i];
    out[pos++] = "0123456789abcdef"[b >> 4];
    out[pos++] = "0123456789abcdef"[b & 0xF];
  }
  out[pos] = 0;
  send_frame(out);
}

/* Independent readback of the same user buffer through the kernel copyout path. */
static void cmd_kread_user(const char *line, uint64_t buf, uint64_t buflen) {
  char raw[32], hexbuf[64];
  int ok = 0;
  if (!key_value(line, "kaddr", raw, sizeof(raw))) {
    send_frame("ERR KREAD_USER code=1 msg=missing_kaddr");
    return;
  }
  uint64_t kaddr = parse_hex_u64(raw, &ok);
  if (!ok || !key_value(line, "len", hexbuf, sizeof(hexbuf))) {
    send_frame("ERR KREAD_USER code=2 msg=bad_args");
    return;
  }
  uint64_t len = parse_hex_u64(hexbuf, &ok);
  if (!ok || len == 0 || len > MAX_READ) {
    send_frame("ERR KREAD_USER code=3 msg=len_out_of_range");
    return;
  }
  if (kaddr < buf || kaddr + len > buf + buflen) {
    send_frame("ERR KREAD_USER code=4 msg=outside_test_buffer");
    return;
  }
  static uint8_t dst[MAX_READ];
  memset(dst, 0, len);
  int rc = get_memory_dump(kaddr, (uint64_t *)dst, len);
  if (rc != 0) {
    char msg[96];
    sprintf(msg, "ERR KREAD_USER code=6 msg=read_fault rc=%d", rc);
    send_frame(msg);
    return;
  }
  static char out[2 * MAX_READ + 128];
  int pos = 0;
  pos += sprintf(out + pos, "OK KREAD_USER kaddr=0x%llx len=0x%llx rc=0 hex=",
                 (unsigned long long)kaddr, (unsigned long long)len);
  for (uint64_t i = 0; i < len; i++) {
    out[pos++] = "0123456789abcdef"[dst[i] >> 4];
    out[pos++] = "0123456789abcdef"[dst[i] & 0xF];
  }
  out[pos] = 0;
  send_frame(out);
}

/* ---- LIVE2: bounded split-view writer + double-read consumer -------------- */

static uint64_t g_boot_nonce = 0;

#define RACE_MAX_TRANS 100000u
#define RACE_MAX_MS 100u
#define RACE_RING 256u

/* Writer lifecycle state machine (LIVE2.2.1): a new operation is only accepted in IDLE, the owner
   waits for DONE of *its own* generation, joins the thread and verifies the counter is stable before
   the next attempt may start. A late DONE from a previous generation can never unlock an attempt. */
#define RACE_IDLE 0
#define RACE_STARTING 1
#define RACE_RUNNING 2
#define RACE_STOPPING 3
#define RACE_DONE 4
#define RACE_HANDOVER_TIMEOUT_US 500000ull

static volatile int g_race_state = RACE_IDLE;
static volatile uint64_t g_race_gen = 0;       /* current attempt generation */
static volatile uint64_t g_writer_gen = 0;     /* generation the running writer belongs to */
static volatile uint64_t g_done_gen = 0;       /* generation whose writer observed DONE */
static const char *g_race_state_names[5] = {"IDLE", "STARTING", "RUNNING", "STOPPING", "DONE"};

static volatile int g_race_run = 0;
static volatile int g_race_ready = 0;
static volatile int g_race_done = 0;
static volatile uint64_t g_race_count = 0;
static volatile uint64_t g_race_t_first = 0;
static volatile uint64_t g_race_t_last = 0;
static volatile int g_race_alternate = 1;
static volatile int g_race_mode = 0;
static uint64_t g_race_base = 0, g_race_off = 0, g_race_val_a = 0, g_race_val_b = 0;
static uint64_t g_race_max_trans = 0, g_race_max_ms = 0;
/* per-transition ring: id | timestamp_us | old | new (most recent RACE_RING transitions) */
static volatile uint64_t g_ring_id[RACE_RING], g_ring_ts[RACE_RING];
static volatile uint64_t g_ring_old[RACE_RING], g_ring_new[RACE_RING];
static volatile uint64_t g_ring_head = 0, g_ring_total = 0;
static ScePthread g_race_thread = 0;

/* Event/time-driven toggle engine: stops on request_done (g_race_run=0), max transitions or
   max writer runtime -- all three limits are hard. Records every transition with a timestamp. */
static void *race_writer(void *arg) {
  /* The generation of record is g_writer_gen: the owner sets it before creating this thread. The
     pthread argument is deliberately NOT used as the source of truth -- a NULL/0 argument made the
     writer believe it was generation 0, which broke the DONE binding (found live: gen=1/done_gen=0). */
  UNUSED(arg);
  uint64_t gen = g_writer_gen;
  uint64_t t0 = sceKernelGetProcessTime();
  uint64_t value = g_race_val_b;
  g_race_run = 1;
  g_race_ready = 1;
  /* wait out STARTING (bounded): exiting here would race the owner's RUNNING transition */
  while (g_race_state == RACE_STARTING && (sceKernelGetProcessTime() - t0) < 100000ull) {
    scePthreadYield();
  }
  if (g_race_state != RACE_RUNNING || g_writer_gen != gen) {
    g_race_state = RACE_STOPPING;
    g_race_run = 0;
    g_done_gen = gen;
    g_race_done = 1;
    g_race_state = RACE_DONE;
    return 0;
  }
  /* only this generation, and only while the owner has it RUNNING, performs transitions */
  while (g_race_state == RACE_RUNNING && g_writer_gen == gen && g_race_run) {
    value = (g_race_alternate && value == g_race_val_b) ? g_race_val_a : g_race_val_b;
    *(volatile uint64_t *)(g_race_base + g_race_off) = value;
    uint64_t now = sceKernelGetProcessTime();
    uint64_t id = g_race_count + 1;
    uint64_t slot = g_ring_head % RACE_RING;
    g_ring_id[slot] = id;
    g_ring_ts[slot] = now;
    g_ring_old[slot] = (value == g_race_val_a) ? g_race_val_b : g_race_val_a;
    g_ring_new[slot] = value;
    g_ring_head = id;
    g_ring_total = id;
    g_race_count = id;
    if (id == 1) g_race_t_first = now;
    g_race_t_last = now;
    if (id >= g_race_max_trans) break;
    if ((now - t0) / 1000ull >= g_race_max_ms) break;
    if (g_race_mode == 1) scePthreadYield();
    else if (g_race_mode == 2) sceKernelUsleep(200);
  }
  g_race_state = RACE_STOPPING;
  g_race_run = 0;
  g_done_gen = gen;          /* DONE is generation-tagged: stale DONE cannot unlock a new attempt */
  g_race_done = 1;
  g_race_state = RACE_DONE;
  return 0;
}

/* bounded hand-over: wait for THIS generation's DONE, join, then prove the writer stopped writing */
static int race_handover(uint64_t gen, uint64_t *handover_us, int *joined, int *stable) {
  uint64_t t0 = sceKernelGetProcessTime();
  while (g_race_state != RACE_DONE && (sceKernelGetProcessTime() - t0) < RACE_HANDOVER_TIMEOUT_US) {
    sceKernelUsleep(50);
  }
  *handover_us = sceKernelGetProcessTime() - t0;
  if (g_race_state != RACE_DONE || g_done_gen != gen) {
    return 0;                                   /* WRITER_HANDOVER_TIMEOUT: no new attempt may start */
  }
  int rc = scePthreadJoin(g_race_thread, 0);
  *joined = (rc == 0) ? 1 : 0;
  uint64_t before = g_race_count;
  sceKernelUsleep(200);                         /* settle window */
  uint64_t after = g_race_count;
  *stable = (before == after) ? 1 : 0;          /* no transition after the joined DONE */
  return 1;
}

static void cmd_race(const char *line) {
  char raw[32], hexbuf[32];
  int ok = 0;
  uint64_t base = 0, size = 0;
  select_buffer(line, &base, &size);
  if (g_race_run) {
    send_frame("ERR RACE code=1 msg=already_running");
    return;
  }
  if (!key_value(line, "off", raw, sizeof(raw))) {
    send_frame("ERR RACE code=2 msg=missing_off");
    return;
  }
  g_race_off = parse_hex_u64(raw, &ok);
  if (!ok || g_race_off + 8 > size) {
    send_frame("ERR RACE code=3 msg=off_out_of_range");
    return;
  }
  if (!key_value(line, "a", hexbuf, sizeof(hexbuf))) {
    send_frame("ERR RACE code=4 msg=missing_a");
    return;
  }
  g_race_val_a = parse_hex_u64(hexbuf, &ok);
  if (!ok || !key_value(line, "b", hexbuf, sizeof(hexbuf))) {
    send_frame("ERR RACE code=5 msg=bad_b");
    return;
  }
  g_race_val_b = parse_hex_u64(hexbuf, &ok);
  if (!ok) {
    send_frame("ERR RACE code=6 msg=bad_b");
    return;
  }
  g_race_max_trans = 100000;
  g_race_max_ms = 50;
  g_race_mode = 0;
  g_race_alternate = 1;
  if (key_value(line, "max_trans", hexbuf, sizeof(hexbuf))) g_race_max_trans = parse_hex_u64(hexbuf, &ok);
  if (key_value(line, "ms", hexbuf, sizeof(hexbuf))) g_race_max_ms = parse_hex_u64(hexbuf, &ok);
  if (key_value(line, "mode", hexbuf, sizeof(hexbuf))) g_race_mode = (int)parse_hex_u64(hexbuf, &ok);
  if (key_value(line, "alt", hexbuf, sizeof(hexbuf))) g_race_alternate = (int)parse_hex_u64(hexbuf, &ok);
  if (g_race_max_trans == 0 || g_race_max_trans > RACE_MAX_TRANS ||
      g_race_max_ms == 0 || g_race_max_ms > RACE_MAX_MS || g_race_mode > 2) {
    send_frame("ERR RACE code=7 msg=bounds");
    return;
  }
  g_race_base = base;
  g_race_count = 0;
  g_race_t_first = 0;
  g_race_t_last = 0;
  g_ring_head = 0;
  g_ring_total = 0;
  g_race_ready = 0;
  g_race_done = 0;
  g_race_run = 1;
  if (scePthreadCreate(&g_race_thread, 0, race_writer, 0, "live2race") != 0) {
    g_race_run = 0;
    send_frame("ERR RACE code=8 msg=thread_create_failed");
    return;
  }
  /* handshake: do not report started before the writer thread is live (bounded wait, 100 ms) */
  uint64_t hs = sceKernelGetProcessTime();
  while (!g_race_ready && (sceKernelGetProcessTime() - hs) < 100000ull) sceKernelUsleep(100);
  char msg[200];
  sprintf(msg, "OK RACE started ready=%d base=0x%llx off=0x%llx alt=%d mode=%d max_trans=0x%llx max_ms=0x%llx",
          g_race_ready, (unsigned long long)base, (unsigned long long)g_race_off, g_race_alternate,
          g_race_mode, (unsigned long long)g_race_max_trans, (unsigned long long)g_race_max_ms);
  send_frame(msg);
}

/* One consumer run: two reads of the SAME field with a real intervening kernel call. */
static void cmd_dr(const char *line) {
  uint64_t base = 0, size = 0;
  select_buffer(line, &base, &size);
  char raw[32];
  int ok = 0;
  if (!key_value(line, "off", raw, sizeof(raw))) {
    send_frame("ERR DR code=1 msg=missing_off");
    return;
  }
  uint64_t off = parse_hex_u64(raw, &ok);
  if (!ok || off + 8 > size) {
    send_frame("ERR DR code=2 msg=off_out_of_range");
    return;
  }
  uint64_t other = (base == g_buf_a) ? g_buf_b : g_buf_a;
  static uint64_t scratch[4];
  uint64_t t1 = sceKernelGetProcessTime();
  uint64_t w1 = *(volatile uint64_t *)(base + off);
  int rc = get_memory_dump(other, scratch, 32); /* intervening helper call */
  uint64_t w2 = *(volatile uint64_t *)(base + off);
  uint64_t t2 = sceKernelGetProcessTime();
  char msg[200];
  sprintf(msg, "OK DR w1=0x%llx w2=0x%llx t1=%llu t2=%llu other_rc=%d",
          (unsigned long long)w1, (unsigned long long)w2,
          (unsigned long long)t1, (unsigned long long)t2, rc);
  send_frame(msg);
}

/* LIVE2.1: the whole event sequence inside ONE payload operation -- writer_ready → request_start →
   phase-1 read → intervening kernel call → phase-2 read → request_done → writer stop. No network
   round trip between the writer start and the reads, so the writer is provably live in the window. */
static void cmd_drw(const char *line) {
  uint64_t base = 0, size = 0;
  int ok = 0;
  char raw[40];
  select_buffer(line, &base, &size);
  if (g_race_run) {
    send_frame("ERR DRW code=1 msg=busy");
    return;
  }
  if (!key_value(line, "off", raw, sizeof(raw))) {
    send_frame("ERR DRW code=2 msg=missing_off");
    return;
  }
  uint64_t off = parse_hex_u64(raw, &ok);
  if (!ok || off + 8 > size) {
    send_frame("ERR DRW code=3 msg=off_out_of_range");
    return;
  }
  if (!key_value(line, "a", raw, sizeof(raw))) {
    send_frame("ERR DRW code=4 msg=missing_a");
    return;
  }
  uint64_t va = parse_hex_u64(raw, &ok);
  if (!ok || !key_value(line, "b", raw, sizeof(raw))) {
    send_frame("ERR DRW code=5 msg=missing_b");
    return;
  }
  uint64_t vb = parse_hex_u64(raw, &ok);
  if (!ok) {
    send_frame("ERR DRW code=6 msg=bad_b");
    return;
  }
  g_race_max_ms = 50;
  g_race_max_trans = 100000;
  g_race_mode = 0;
  g_race_alternate = 1;
  if (key_value(line, "ms", raw, sizeof(raw))) g_race_max_ms = parse_hex_u64(raw, &ok);
  if (key_value(line, "mode", raw, sizeof(raw))) g_race_mode = (int)parse_hex_u64(raw, &ok);
  if (key_value(line, "alt", raw, sizeof(raw))) g_race_alternate = (int)parse_hex_u64(raw, &ok);
  if (g_race_max_ms == 0 || g_race_max_ms > RACE_MAX_MS || g_race_mode > 2) {
    send_frame("ERR DRW code=7 msg=bounds");
    return;
  }
  g_race_base = base;
  g_race_off = off;
  g_race_val_a = va;
  g_race_val_b = vb;
  g_race_count = 0;
  g_ring_head = 0;
  g_ring_total = 0;
  g_race_t_first = 0;
  g_race_t_last = 0;
  g_race_ready = 0;
  g_race_done = 0;
  g_race_run = 1;
  if (scePthreadCreate(&g_race_thread, 0, race_writer, 0, "live2race") != 0) {
    g_race_run = 0;
    send_frame("ERR DRW code=8 msg=thread_create_failed");
    return;
  }
  uint64_t hs = sceKernelGetProcessTime();
  while (!g_race_ready && (sceKernelGetProcessTime() - hs) < 100000ull) sceKernelUsleep(50);
  uint64_t rst = sceKernelGetProcessTime();
  static uint64_t drw_scratch[4];
  uint64_t w1 = *(volatile uint64_t *)(base + off);
  uint64_t other = (base == g_buf_a) ? g_buf_b : g_buf_a;
  int rc = get_memory_dump(other, drw_scratch, 32);
  uint64_t w2 = *(volatile uint64_t *)(base + off);
  uint64_t rdone = sceKernelGetProcessTime();
  g_race_run = 0;
  uint64_t waited = 0;
  while (!g_race_done && waited < 200000ull) {
    sceKernelUsleep(100);
    waited += 100;
  }
  char msg[8192];
  int mo = sprintf(msg, "OK DRW w1=0x%llx w2=0x%llx t1=%llu t2=%llu rst=%llu rdone=%llu ready=%d "
                        "trans=%llu ring_total=%llu other_rc=%d off=0x%llx",
                   (unsigned long long)w1, (unsigned long long)w2, (unsigned long long)rst,
                   (unsigned long long)rdone, (unsigned long long)rst, (unsigned long long)rdone,
                   g_race_ready, (unsigned long long)g_race_count, (unsigned long long)g_ring_total,
                   rc, (unsigned long long)off);
  uint64_t total = g_ring_total;
  uint64_t avail = (total < RACE_RING) ? total : RACE_RING;
  if (avail > 64) avail = 64;
  mo += sprintf(msg + mo, " avail=%llu trace=", (unsigned long long)avail);
  for (uint64_t i = 0; i < avail; i++) {
    if (mo > (int)sizeof(msg) - 96) break;
    uint64_t slot = (g_ring_head - avail + i) % RACE_RING;
    mo += sprintf(msg + mo, "%s%llu:%llu:%llx:%llx", (i == 0) ? "" : ",",
                  (unsigned long long)g_ring_id[slot], (unsigned long long)g_ring_ts[slot],
                  (unsigned long long)g_ring_old[slot], (unsigned long long)g_ring_new[slot]);
  }
  send_frame(msg);
}

/* LIVE2.2: the discovered candidate chain, instantiated in payload-owned memory --
   read #1 → validation/use → intervening kernel call → read #2 → consumer (destination write)
   with the bounded writer toggling the field during the whole operation. */
static void cmd_tr(const char *line) {
  uint64_t base = 0, size = 0;
  int ok = 0;
  char raw[40];
  select_buffer(line, &base, &size);
  if (g_race_state != RACE_IDLE) {
    char busy[160];
    sprintf(busy, "ERR TR code=1 msg=busy state=%s gen=%llu done_gen=%llu",
            g_race_state_names[g_race_state], (unsigned long long)g_race_gen,
            (unsigned long long)g_done_gen);
    send_frame(busy);
    return;
  }
  if (!key_value(line, "off", raw, sizeof(raw))) {
    send_frame("ERR TR code=2 msg=missing_off");
    return;
  }
  uint64_t off = parse_hex_u64(raw, &ok);
  if (!ok || off + 8 > size) {
    send_frame("ERR TR code=3 msg=off_out_of_range");
    return;
  }
  uint64_t dest = off + 0x40;
  if (key_value(line, "dest", raw, sizeof(raw))) dest = parse_hex_u64(raw, &ok);
  if (dest + 16 > size || (dest < off + 8 && dest + 16 > off)) {
    send_frame("ERR TR code=4 msg=dest_out_of_range");
    return;
  }
  int use_read2 = 1;
  if (key_value(line, "use", raw, sizeof(raw))) use_read2 = (int)parse_hex_u64(raw, &ok);
  if (!key_value(line, "a", raw, sizeof(raw))) {
    send_frame("ERR TR code=5 msg=missing_a");
    return;
  }
  uint64_t va = parse_hex_u64(raw, &ok);
  if (!ok || !key_value(line, "b", raw, sizeof(raw))) {
    send_frame("ERR TR code=6 msg=missing_b");
    return;
  }
  uint64_t vb = parse_hex_u64(raw, &ok);
  if (!ok) {
    send_frame("ERR TR code=7 msg=bad_b");
    return;
  }
  g_race_max_ms = 50;
  g_race_max_trans = 100000;
  g_race_mode = 0;
  g_race_alternate = 1;
  if (key_value(line, "ms", raw, sizeof(raw))) g_race_max_ms = parse_hex_u64(raw, &ok);
  if (key_value(line, "mode", raw, sizeof(raw))) g_race_mode = (int)parse_hex_u64(raw, &ok);
  if (key_value(line, "alt", raw, sizeof(raw))) g_race_alternate = (int)parse_hex_u64(raw, &ok);
  if (g_race_max_ms == 0 || g_race_max_ms > RACE_MAX_MS || g_race_mode > 2) {
    send_frame("ERR TR code=8 msg=bounds");
    return;
  }
  uint64_t gen = g_race_gen + 1;
  g_race_gen = gen;
  g_race_base = base;
  g_race_off = off;
  g_race_val_a = va;
  g_race_val_b = vb;
  /* per-attempt reset only at this point: previous generation joined, state is IDLE */
  g_race_count = 0;
  g_ring_head = 0;
  g_ring_total = 0;
  g_race_t_first = 0;
  g_race_t_last = 0;
  g_race_ready = 0;
  g_race_done = 0;
  g_race_run = 0;
  g_writer_gen = gen;
  g_race_state = RACE_STARTING;
  if (scePthreadCreate(&g_race_thread, 0, race_writer, (void *)(uintptr_t)gen, "live2race") != 0) {
    g_race_state = RACE_IDLE;
    send_frame("ERR TR code=9 msg=thread_create_failed");
    return;
  }
  uint64_t hs = sceKernelGetProcessTime();
  while (!g_race_ready && (sceKernelGetProcessTime() - hs) < 100000ull) sceKernelUsleep(50);
  if (!g_race_ready) {
    g_race_state = RACE_STOPPING;
    char msg[160];
    sprintf(msg, "ERR TR code=10 msg=writer_ready_timeout gen=%llu", (unsigned long long)gen);
    send_frame(msg);
    return;
  }
  if (g_race_state == RACE_STARTING) {
    g_race_state = RACE_RUNNING;      /* never overwrite a state the writer already advanced */
  }
  /* do not open the request window before the writer has written at least once: otherwise read #1
     can still observe the value left by an earlier experiment (found live: A/A produced 1 split) */
  uint64_t wait0 = sceKernelGetProcessTime();
  while (g_race_count == 0 && (sceKernelGetProcessTime() - wait0) < 100000ull) sceKernelUsleep(20);
  if (g_race_count == 0) {
    g_race_state = RACE_STOPPING;
    char msg[160];
    sprintf(msg, "ERR TR code=12 msg=writer_first_transition_timeout gen=%llu",
            (unsigned long long)gen);
    send_frame(msg);
    return;
  }
  uint64_t rst = sceKernelGetProcessTime();
  uint64_t r1 = *(volatile uint64_t *)(base + off);              /* read #1 */
  int val_rc = (r1 == g_race_val_a) ? 0 : 1;                     /* validation/use of read #1 */
  static uint64_t tr_scratch[4];
  uint64_t other = (base == g_buf_a) ? g_buf_b : g_buf_a;
  int krc = get_memory_dump(other, tr_scratch, 32);               /* intervening kernel call */
  uint64_t r2 = *(volatile uint64_t *)(base + off);              /* read #2 */
  uint64_t consumer_value = use_read2 ? r2 : r1;                 /* consumer decision */
  *(volatile uint64_t *)(base + dest) = consumer_value;           /* consumer effect */
  uint64_t rdone = sceKernelGetProcessTime();
  g_race_state = RACE_STOPPING;
  uint64_t handover_us = 0;
  int joined = 0, stable = 0;
  if (!race_handover(gen, &handover_us, &joined, &stable)) {
    char msg[220];
    sprintf(msg, "ERR TR code=11 msg=WRITER_HANDOVER_TIMEOUT gen=%llu done_gen=%llu state=%s "
                 "handover_us=%llu",
            (unsigned long long)gen, (unsigned long long)g_done_gen, g_race_state_names[g_race_state],
            (unsigned long long)handover_us);
    send_frame(msg);
    return;                                  /* no new writer started; attempt is not accepted */
  }
  uint64_t trans_final = g_race_count;
  uint64_t ring_final = g_ring_total;
  g_race_state = RACE_IDLE;                  /* only now may the next attempt begin */
  char msg[8192];
  int mo = sprintf(msg, "OK TR r1=0x%llx r2=0x%llx t1=%llu t2=%llu val_rc=%d krc=%d use=%d dest=0x%llx "
                        "gen=%llu done_gen=%llu joined=%d stable=%d handover_us=%llu state=%s "
                        "trans=%llu ring_total=%llu destbuf=",
                   (unsigned long long)r1, (unsigned long long)r2, (unsigned long long)rst,
                   (unsigned long long)rdone, val_rc, krc, use_read2, (unsigned long long)dest,
                   (unsigned long long)gen, (unsigned long long)g_done_gen, joined, stable,
                   (unsigned long long)handover_us, g_race_state_names[RACE_IDLE],
                   (unsigned long long)trans_final, (unsigned long long)ring_final);
  const uint8_t *dbuf = (const uint8_t *)(base + dest);
  for (int i = 0; i < 16; i++) mo += sprintf(msg + mo, "%02x", dbuf[i]);
  uint64_t total = g_ring_total;
  uint64_t avail = (total < RACE_RING) ? total : RACE_RING;
  if (avail > 64) avail = 64;
  mo += sprintf(msg + mo, " avail=%llu trace=", (unsigned long long)avail);
  for (uint64_t i = 0; i < avail; i++) {
    if (mo > (int)sizeof(msg) - 96) break;
    uint64_t slot = (g_ring_head - avail + i) % RACE_RING;
    mo += sprintf(msg + mo, "%s%llu:%llu:%llx:%llx", (i == 0) ? "" : ",",
                  (unsigned long long)g_ring_id[slot], (unsigned long long)g_ring_ts[slot],
                  (unsigned long long)g_ring_old[slot], (unsigned long long)g_ring_new[slot]);
  }
  send_frame(msg);
}

static void cmd_rstop(void) {
  uint64_t waited = 0;
  g_race_run = 0;
  while (!g_race_done && waited < 200000ull) {
    sceKernelUsleep(200);
    waited += 200;
  }
  char msg[250];
  sprintf(msg, "OK RSTOP transitions=%llu t_first=%llu t_last=%llu writer_done=%d ring_total=%llu waited_us=%llu",
          (unsigned long long)g_race_count, (unsigned long long)g_race_t_first,
          (unsigned long long)g_race_t_last, g_race_done, (unsigned long long)g_ring_total,
          (unsigned long long)waited);
  send_frame(msg);
}

/* Dump the most recent ring entries so the host can count transitions inside its request window. */
static void cmd_rtrace(const char *line) {
  char raw[32];
  int ok = 0;
  uint64_t want = 64;
  if (key_value(line, "n", raw, sizeof(raw))) want = parse_hex_u64(raw, &ok);
  if (want == 0 || want > RACE_RING) want = RACE_RING;
  uint64_t total = g_ring_total;
  uint64_t avail = (total < RACE_RING) ? total : RACE_RING;
  if (want > avail) want = avail;
  char msg[8192];
  int off = sprintf(msg, "OK RTRACE ring_total=%llu avail=%llu trace=", (unsigned long long)total,
                    (unsigned long long)avail);
  for (uint64_t i = 0; i < want; i++) {
    if (off > (int)sizeof(msg) - 96) break;
    uint64_t slot = (g_ring_head - want + i) % RACE_RING;
    off += sprintf(msg + off, "%s%llu:%llu:%llx:%llx", (i == 0) ? "" : ",",
                   (unsigned long long)g_ring_id[slot], (unsigned long long)g_ring_ts[slot],
                   (unsigned long long)g_ring_old[slot], (unsigned long long)g_ring_new[slot]);
  }
  send_frame(msg);
}

/* ---- entry ------------------------------------------------------------- */

int _main(struct thread *td) {
  UNUSED(td);
  initKernel();
  initLibc();
  initPthread();
  /* LIVE2: the race writer thread is created lazily by the RACE command. */
  initNetwork();
  initSysUtil();

  printf_notification("live0: start");

  g_instance = sceKernelGetProcessTime();
  void *test_buf = mmap(NULL, TEST_BUF_SIZE, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if ((int64_t)test_buf < 0) {
    printf_notification("live0: mmap failed");
    return -1;
  }
  g_alloc_seq++;
  g_alloc_ret = (uint64_t)test_buf;
  g_alloc_size = TEST_BUF_SIZE;
  memset(test_buf, TEST_BUF_FILL, TEST_BUF_SIZE);

  /* Buffer A and Buffer B: two separate allocations, equal size, distinct deterministic fill. */
  g_buf_a = (uint64_t)test_buf;
  g_buf_a_ret = (uint64_t)test_buf;
  g_buf_a_size = TEST_BUF_SIZE;
  g_buf_a_gen = g_alloc_seq;
  void *buf_b = mmap(NULL, TEST_BUF_SIZE, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if ((int64_t)buf_b < 0) {
    printf_notification("live1: mmap B failed");
    return -1;
  }
  g_alloc_seq++;
  g_buf_b = (uint64_t)buf_b;
  g_buf_b_ret = (uint64_t)buf_b;
  g_buf_b_size = TEST_BUF_SIZE;
  g_buf_b_gen = g_alloc_seq;
  memset(buf_b, TEST_BUF_FILL_B, TEST_BUF_SIZE);

  int *heap_block = (int *)malloc(64);
  int heap_stack_marker = 0;

  uint16_t fw = get_firmware();
  uint64_t kbase = get_kernel_base();

  g_sock = tcp_connect_to(HOST_IP, HOST_PORT, "live0");
  if (g_sock < 0) {
    printf_notification("live0: relay unreachable");
    return -2;
  }

  char out[512];
  /* nonce: startup timestamp, so the host can tell a fresh greeting from a stale session */
  g_boot_nonce = sceKernelGetProcessTime();
  sprintf(out, "OK HELLO payload=%s fw=%u kbase=0x%llx instance=0x%llx pid=0x%x nonce=%llu",
          PAYLOAD_ID, (unsigned)fw, (unsigned long long)kbase, (unsigned long long)g_instance,
          (unsigned)getpid(), (unsigned long long)g_boot_nonce);
  send_frame(out);

  uint64_t t0 = sceKernelGetProcessTime();
  uint64_t last_cmd = t0;

  for (;;) {
    uint64_t now = sceKernelGetProcessTime();
    if ((now - t0) / 1000000ull > LIFETIME_SECONDS) {
      send_frame("OK BYE reason=lifetime");
      break;
    }
    if ((now - last_cmd) / 1000000ull > IDLE_SECONDS) {
      send_frame("OK BYE reason=idle");
      break;
    }
    char line[4096];
    int n = recv_frame(line, sizeof(line));
    if (n < 0) {
      /* Never retry a broken control channel: report it and leave. */
      sprintf(out, "OK BYE reason=recv_%d recv_error=0x%x retries=%d", n,
              (unsigned)g_last_recv_error, g_recv_retries);
      send_frame(out);
      printf_notification("live0: control channel ended");
      break;
    }
    last_cmd = sceKernelGetProcessTime();

    if (line[0] == 'P' && line[1] == 'I' && line[2] == 'N' && line[3] == 'G') {
      sprintf(out, "OK PING payload=%s uptime_ms=%llu", PAYLOAD_ID,
              (unsigned long long)((last_cmd - t0) / 1000ull));
      send_frame(out);
    } else if (line[0] == 'I' && line[1] == 'N' && line[2] == 'F' && line[3] == 'O') {
      sprintf(out,
              "OK INFO payload=%s fw=%u kbase=0x%llx sp=0x%llx text=0x%llx data=0x%llx "
              "stack=0x%llx heap=0x%llx buf=0x%llx buflen=0x%llx "
              "alloc=mmap alloc_ret=0x%llx alloc_size=0x%llx alloc_seq=%d pid=0x%x instance=0x%llx "
              "buf_a=0x%llx buf_a_ret=0x%llx buf_a_size=0x%llx buf_a_gen=%d "
              "buf_b=0x%llx buf_b_ret=0x%llx buf_b_size=0x%llx buf_b_gen=%d",
              PAYLOAD_ID, (unsigned)fw, (unsigned long long)kbase,
              (unsigned long long)(uint64_t)&line, (unsigned long long)(uint64_t)&cmd_read,
              (unsigned long long)(uint64_t)&g_sock, (unsigned long long)(uint64_t)&heap_stack_marker,
              (unsigned long long)(uint64_t)heap_block, (unsigned long long)(uint64_t)test_buf,
              (unsigned long long)TEST_BUF_SIZE,
              (unsigned long long)g_alloc_ret, (unsigned long long)g_alloc_size, g_alloc_seq,
              (unsigned)getpid(), (unsigned long long)g_instance,
              (unsigned long long)g_buf_a, (unsigned long long)g_buf_a_ret,
              (unsigned long long)g_buf_a_size, g_buf_a_gen,
              (unsigned long long)g_buf_b, (unsigned long long)g_buf_b_ret,
              (unsigned long long)g_buf_b_size, g_buf_b_gen);
      send_frame(out);
    } else if (line[0] == 'R' && line[1] == 'E' && line[2] == 'A' && line[3] == 'D') {
      cmd_read(line, (uint64_t)test_buf, TEST_BUF_SIZE);
    #if !TRACE_ONLY
    } else if (line[0] == 'W' && line[1] == 'R' && line[2] == 'I' && line[3] == 'T' &&
               line[4] == 'E') {
      uint64_t sb = 0, ss = 0;
      select_buffer(line, &sb, &ss);
      cmd_write(line, sb, ss);
    } else if (line[0] == 'V' && line[1] == 'E' && line[2] == 'R' && line[3] == 'I') {
      uint64_t sb = 0, ss = 0;
      select_buffer(line, &sb, &ss);
      cmd_verify(line, sb, ss);
    } else if (line[0] == 'K' && line[1] == 'R' && line[2] == 'E' && line[3] == 'A') {
      uint64_t sb = 0, ss = 0;
      select_buffer(line, &sb, &ss);
      cmd_kread_user(line, sb, ss);
    } else if (line[0] == 'R' && line[1] == 'A' && line[2] == 'C' && line[3] == 'E') {
      cmd_race(line);
    } else if (line[0] == 'D' && line[1] == 'R' && line[2] == 'W') {
      cmd_drw(line);
    } else if (line[0] == 'D' && line[1] == 'R') {
      cmd_dr(line);
    } else if (line[0] == 'R' && line[1] == 'S' && line[2] == 'T' && line[3] == 'O') {
      cmd_rstop();
    } else if (line[0] == 'R' && line[1] == 'T' && line[2] == 'R' && line[3] == 'A') {
      cmd_rtrace(line);
    } else if (line[0] == 'T' && line[1] == 'R') {
      cmd_tr(line);

#endif /* !TRACE_ONLY */
    } else if (line[0] == 'T' && line[1] == 'R' && line[2] == 'A' && line[3] == 'C') {
      cmd_trace(line);
    } else if (line[0] == 'Q' && line[1] == 'U' && line[2] == 'I' && line[3] == 'T') {
      send_frame("OK BYE reason=quit");
      break;
    } else {
      send_frame("ERR UNKNOWN code=1 msg=unknown_command");
    }
  }

  send_frame("OK ENDE payload=" PAYLOAD_ID);
  printf_notification("live0: end");
  if (g_sock >= 0) sceNetSocketClose(g_sock);
  munmap(test_buf, TEST_BUF_SIZE);
  if (g_buf_b) munmap((void *)g_buf_b, TEST_BUF_SIZE);
  if (heap_block) free(heap_block);
  return 0;
}
