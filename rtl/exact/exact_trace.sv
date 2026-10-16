// TDCC Exact's trace engine: the hash chain of tdcc_exact/trace.py (TraceLog), in hardware.
// docs/exact-rtl.md has the interface, the timing and the integration plan.
//
// Every event moves the chain to SHA-256(chain || message):
//   step   message = slice (2 B LE) || pc (4 B LE) || the instruction's 8 words (32 B, each LE)
//                    || R0..R15 after it (64 B, each LE)                       (134 B with chain)
//   aux    message = kind (1 B: "W", "O", "R" or "C") || payload (aux_len B, at most 64)
//          W: slice (2) || addr (8) || H(data) (32);  O: slice (2) || addr (8) || len (8) ||
//          H(data) (32);  R: the arguments, 4 B each (LE);  C: H(state hashes) (32)
//          -- the host computes the payload's hashes (it has the data); C's state hash is
//          the host's too, until the card hashes a slice's state itself (docs/exact-rtl.md)
//   init   chain = SHA-256("tdcc-exact/trace/v3" || binding)  (trace.chain_start; also zeroes
//          the step counter and the event counter)
//
// Steps come from the sequencer through a FIFO (DEPTH entries): step_ready is low while it is
// full (valid/ready: the sequencer holds the step, and its issue, until it is taken), and
// step_afull (a flip-flop) is high while at most one entry is free, for a sequencer that would
// rather hold its issue on a registered term: one push may still follow afull's rise. Nothing
// is ever dropped.
//
// Checkpoints: with EVERY != 0, after the step whose count is a multiple of EVERY the engine
// stops taking steps (STATUS CKPT_WAIT) until the host posts a "C" event; the FIFO then fills
// and holds the sequencer (TraceLog.observe's checkpoint at step % every == 0). The host's
// other checkpoints (a run's end, TraceLog.finish, and the skip of a repeated one) are posts
// like any other.
// Order: a posted event is hashed when the FIFO is empty and the engine idle, or at a
// checkpoint pause; the host posts W / O / R / C only while the core is not running or at a
// pause (as TraceLog sees them), so the chain's order is TraceLog's.
//
// Control registers (word addresses; reg_rdata is the word at reg_addr one cycle later).
// Byte strings (CHAIN, BINDING, AUX_DATA) are packed little-endian: word k holds bytes
// 4k..4k+3, byte 4k in bits [7:0] -- what the host gets with np.frombuffer(b, "<u4").
//   0x00 CTRL/STATUS  W: bit0 INIT (hash the binding into the chain), bit1 POST (hash the aux
//                     event)
//                     R: bit0 BUSY (an event is being hashed, or one is waiting: FIFO not
//                     empty, INIT or POST pending), bit1 CKPT_WAIT, bit2 POST pending, bit3
//                     INIT pending, bit4 FIFO empty, bit5 FIFO full, bit6 READY (the chain was
//                     initialized), [23:16] FIFO entries
//   0x01 EVERY        RW  steps between checkpoint pauses (0: never pause)
//   0x02 AUX_KIND     RW  [7:0] the event's kind byte
//   0x03 AUX_LEN      RW  payload bytes (0..64; more is taken as 64)
//   0x04 STEP_LO      RO  steps hashed since INIT
//   0x05 STEP_HI      RO
//   0x06 EVENTS       RO  aux events hashed since INIT
//   0x07 STALL        RO  cycles step_valid was high and the FIFO full (saturating)
//   0x08 + k CHAIN    RO  the chain, k = 0..7
//   0x10 + k BINDING  RW  k = 0..7
//   0x20 + k AUX_DATA RW  the payload, k = 0..15
module exact_trace #(
  parameter int DEPTH = 16             // step FIFO entries (a power of two, >= 4)
) (
  input  logic          clk,
  input  logic          rst,
  // the step events: one per instruction the slice steps
  input  logic          step_valid,
  output logic          step_ready,
  output logic          step_afull,    // registered: at most one free entry
  input  logic [15:0]   step_slice,
  input  logic [31:0]   step_pc,
  input  logic [255:0]  step_ir,       // word k in [32k +: 32] (otpu_seq's ir)
  input  logic [511:0]  step_regs,     // R[k] in [32k +: 32], after the instruction
  // control registers
  input  logic          reg_we,
  input  logic [5:0]    reg_addr,
  input  logic [31:0]   reg_wdata,
  output logic [31:0]   reg_rdata,
  // the chain, for a monitor (a cycle-accurate view: upd pulses when chain moved)
  output logic [255:0]  chain,
  output logic          upd,
  output logic [63:0]   steps
);
  localparam int AW = $clog2(DEPTH);
  localparam int FW = 16 + 32 + 256 + 512;              // a FIFO entry
  localparam int MB = 136;                               // message buffer bytes (34 words)
  localparam logic [151:0] TAG = "tdcc-exact/trace/v3";  // 19 bytes, first in [151:144]
  initial if (DEPTH != (1 << AW) || DEPTH < 4) $fatal(1, "exact_trace: DEPTH: a power of 2, >= 4");

  function automatic logic [31:0] bswap(input logic [31:0] x);
    return {x[7:0], x[15:8], x[23:16], x[31:24]};
  endfunction

  // ------------------------------------------------------------------ the step FIFO
  logic [FW-1:0] fifo [DEPTH];
  logic [AW:0]   wp, rp;
  logic [AW:0]   cnt;
  logic          pop, fempty, ffull;
  assign cnt = wp - rp;
  assign fempty = cnt == '0;
  assign ffull = cnt[AW];
  assign step_ready = !ffull;
  wire push = step_valid && !ffull;
  logic [FW-1:0] head;
  assign head = fifo[rp[AW-1:0]];

  // ------------------------------------------------------------------ control registers
  logic [31:0] every, aux_kind, aux_len;
  logic [31:0] binding [8];
  logic [31:0] aux [16];
  logic        init_req, post_req, ckpt_wait, ready;
  logic [31:0] events, stall, ck_cnt;
  logic [63:0] nsteps;
  assign steps = nsteps;

  // ------------------------------------------------------------------ the hasher
  typedef enum logic [1:0] {E_IDLE, E_SEND, E_WAIT} est_t;
  typedef enum logic [1:0] {K_STEP, K_AUX, K_INIT} ekind_t;
  est_t          est;
  ekind_t        ek;
  logic [MB*8-1:0] mbuf;          // the message, first byte in the top bits
  logic [7:0]      mlen;          // bytes left to send
  logic            s_start, s_valid, s_ready, s_out;
  logic [255:0]    s_dig;
  logic [7:0]      s_kind;

  /* verilator lint_off PINCONNECTEMPTY */
  exact_sha256 u_sha (
    .clk, .rst, .start(s_start), .in_valid(s_valid), .in_ready(s_ready),
    .in_data(mbuf[MB*8-1 -: 32]), .in_nbytes(mlen >= 8'd4 ? 3'd4 : 3'(mlen)),
    .in_last(mlen <= 8'd4), .busy(), .out_valid(s_out), .digest(s_dig));
  /* verilator lint_on PINCONNECTEMPTY */

  // what the idle engine takes next: INIT, a posted event at a pause or with the FIFO empty,
  // else a step (none while paused)
  logic go_init, go_aux, go_step;
  always_comb begin
    go_init = est == E_IDLE && init_req;
    go_aux  = est == E_IDLE && !init_req && ready && post_req && (fempty || ckpt_wait);
    go_step = est == E_IDLE && !init_req && ready && !go_aux && !fempty && !ckpt_wait;
    pop = go_step;
    s_start = go_init || go_aux || go_step;
    s_valid = est == E_SEND;
  end

  // the messages (chain first; bytes after the message's end are don't-care)
  logic [MB*8-1:0] m_step, m_aux, m_init;
  always_comb begin
    logic [511:0] rb, pb;
    logic [255:0] wb, bb;
    for (int k = 0; k < 16; k++) rb[511 - 32 * k -: 32] = bswap(head[32 * k +: 32]);
    for (int k = 0; k < 8; k++) wb[255 - 32 * k -: 32] = bswap(head[512 + 32 * k +: 32]);
    for (int k = 0; k < 16; k++) pb[511 - 32 * k -: 32] = bswap(aux[k]);
    for (int k = 0; k < 8; k++) bb[255 - 32 * k -: 32] = bswap(binding[k]);
    // head = {slice, pc, ir, regs}
    m_step = {chain, head[FW-9 -: 8], head[FW-1 -: 8], bswap(head[FW-17 -: 32]), wb, rb, 16'h0};
    m_aux  = {chain, aux_kind[7:0], pb, 312'h0};
    m_init = {TAG, bb, 680'h0};
  end

  always_ff @(posedge clk) begin
    upd <= 1'b0;
    if (rst) begin
      wp <= '0; rp <= '0; est <= E_IDLE;
      every <= '0; aux_kind <= '0; aux_len <= '0;
      init_req <= 1'b0; post_req <= 1'b0; ckpt_wait <= 1'b0; ready <= 1'b0;
      events <= '0; stall <= '0; ck_cnt <= '0; nsteps <= '0; chain <= '0;
      step_afull <= 1'b0;
    end else begin
      // ---- FIFO
      if (push) begin
        fifo[wp[AW-1:0]] <= {step_slice, step_pc, step_ir, step_regs};
        wp <= wp + 1'b1;
      end
      if (pop) rp <= rp + 1'b1;
      step_afull <= (cnt + (AW+1)'(push) - (AW+1)'(pop)) >= (AW+1)'(DEPTH - 1);
      if (step_valid && ffull && stall != '1) stall <= stall + 1;
      // ---- registers
      if (reg_we)
        case (reg_addr)
          6'h00: begin
            if (reg_wdata[0]) init_req <= 1'b1;
            if (reg_wdata[1]) post_req <= 1'b1;
          end
          6'h01: every <= reg_wdata;
          6'h02: aux_kind <= reg_wdata;
          6'h03: aux_len <= reg_wdata;
          default: begin
            if (reg_addr[5:3] == 3'b010) binding[reg_addr[2:0]] <= reg_wdata;
            if (reg_addr[5:4] == 2'b10) aux[reg_addr[3:0]] <= reg_wdata;
          end
        endcase
      // ---- the hasher
      case (est)
        E_IDLE: begin
          if (go_init) begin
            mbuf <= m_init; mlen <= 8'd51; ek <= K_INIT; init_req <= 1'b0;
            est <= E_SEND;
          end else if (go_aux) begin
            mbuf <= m_aux; mlen <= 8'd33 + ((aux_len > 32'd64) ? 8'd64 : 8'(aux_len)); ek <= K_AUX; post_req <= 1'b0;
            s_kind <= aux_kind[7:0];
            est <= E_SEND;
          end else if (go_step) begin
            mbuf <= m_step; mlen <= 8'd134; ek <= K_STEP;
            est <= E_SEND;
          end
        end
        E_SEND: if (s_ready) begin
          mbuf <= mbuf << 32;
          mlen <= (mlen > 8'd4) ? mlen - 8'd4 : 8'd0;
          if (mlen <= 8'd4) est <= E_WAIT;
        end
        E_WAIT: if (s_out) begin
          chain <= s_dig;
          upd <= 1'b1;
          est <= E_IDLE;
          case (ek)
            K_INIT: begin
              ready <= 1'b1; nsteps <= '0; events <= '0; ck_cnt <= '0; ckpt_wait <= 1'b0;
            end
            K_AUX: begin
              events <= events + 1;
              if (s_kind == "C") ckpt_wait <= 1'b0;
            end
            default: begin
              nsteps <= nsteps + 1;
              if (every != '0 && ck_cnt + 1 == every) begin
                ckpt_wait <= 1'b1; ck_cnt <= '0;
              end else ck_cnt <= ck_cnt + 1;
            end
          endcase
        end
        default: est <= E_IDLE;
      endcase
    end
  end

  // ---- reads: one cycle after the address
  logic [31:0] rd;
  always_comb begin
    rd = '0;
    case (reg_addr)
      6'h00: begin
        rd[0] = est != E_IDLE || !fempty || init_req || post_req;
        rd[1] = ckpt_wait; rd[2] = post_req; rd[3] = init_req;
        rd[4] = fempty; rd[5] = ffull; rd[6] = ready;
        rd[23:16] = 8'(cnt);
      end
      6'h01: rd = every;
      6'h02: rd = aux_kind;
      6'h03: rd = aux_len;
      6'h04: rd = nsteps[31:0];
      6'h05: rd = nsteps[63:32];
      6'h06: rd = events;
      6'h07: rd = stall;
      default: begin
        if (reg_addr[5:3] == 3'b001) rd = bswap(chain[255 - 32 * reg_addr[2:0] -: 32]);
        if (reg_addr[5:3] == 3'b010) rd = binding[reg_addr[2:0]];
        if (reg_addr[5:4] == 2'b10) rd = aux[reg_addr[3:0]];
      end
    endcase
  end
  always_ff @(posedge clk) reg_rdata <= rd;

endmodule
