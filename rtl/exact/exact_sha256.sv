// SHA-256 (FIPS 180-4) of one message of any length, streamed in as 32-bit words: an iterative
// core, one round per cycle, for TDCC Exact's trace engine (exact_trace.sv, docs/exact-rtl.md).
//
//   start            (only while !busy) begin a message: H = the IV, length 0
//   in_valid/ready   one word per cycle; the first message byte is in_data[31:24]. in_nbytes
//                    (1..4) bytes of the word are message bytes, from the top; it is 4 on every
//                    word but the last (in_last). The empty message is one in_last word with
//                    in_nbytes = 0. Bytes below in_nbytes are ignored (masked here).
//   out_valid        one cycle: digest is the message's hash, H0 in [255:224] (the digest's
//                    first byte in [255:248]); digest holds until the next start
//   busy             a message is open: start is ignored while it is high
//
// The padding (0x80, zeros, the 64-bit bit length) is made here, after in_last.
//
// Two stages, so loading overlaps hashing:
//   L  the loader shifts words (the message's, then the padding's) into nb, a 16-word block
//      buffer; with nb full it waits for C to take it
//   C  the compressor takes nb into the schedule window w (cycle 0, which also loads a..h from
//      H and precomputes h + K[0] + W[0]), runs the 64 rounds (cycles 1..64) and adds the
//      working variables into H (cycle 65): 66 cycles per block, while L fills the next block
// A message of B blocks takes about 66 B + 17 cycles from its first word to out_valid.
//
// The round's long path is the T1 + T2 sum. h + K[t] + W[t] is computed a round early (hkw,
// from g, which becomes h, and the window's next word), so the round adds hkw + S1(e) +
// Ch(e,f,g) + S0(a) + Maj(a,b,c): five terms into a, four into e.
module exact_sha256 (
  input  logic         clk,
  input  logic         rst,
  input  logic         start,
  input  logic         in_valid,
  output logic         in_ready,
  input  logic [31:0]  in_data,
  input  logic [2:0]   in_nbytes,
  input  logic         in_last,
  output logic         busy,
  output logic         out_valid,
  output logic [255:0] digest
);
  function automatic logic [31:0] rotr(input logic [31:0] x, input int n);
    return (x >> n) | (x << (32 - n));
  endfunction
  function automatic logic [31:0] bs0(input logic [31:0] x);
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
  endfunction
  function automatic logic [31:0] bs1(input logic [31:0] x);
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
  endfunction
  function automatic logic [31:0] ss0(input logic [31:0] x);
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
  endfunction
  function automatic logic [31:0] ss1(input logic [31:0] x);
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
  endfunction

  function automatic logic [31:0] kconst(input logic [5:0] t);
    case (t)
      6'd0:  return 32'h428a2f98; 6'd1:  return 32'h71374491; 6'd2:  return 32'hb5c0fbcf;
      6'd3:  return 32'he9b5dba5; 6'd4:  return 32'h3956c25b; 6'd5:  return 32'h59f111f1;
      6'd6:  return 32'h923f82a4; 6'd7:  return 32'hab1c5ed5; 6'd8:  return 32'hd807aa98;
      6'd9:  return 32'h12835b01; 6'd10: return 32'h243185be; 6'd11: return 32'h550c7dc3;
      6'd12: return 32'h72be5d74; 6'd13: return 32'h80deb1fe; 6'd14: return 32'h9bdc06a7;
      6'd15: return 32'hc19bf174; 6'd16: return 32'he49b69c1; 6'd17: return 32'hefbe4786;
      6'd18: return 32'h0fc19dc6; 6'd19: return 32'h240ca1cc; 6'd20: return 32'h2de92c6f;
      6'd21: return 32'h4a7484aa; 6'd22: return 32'h5cb0a9dc; 6'd23: return 32'h76f988da;
      6'd24: return 32'h983e5152; 6'd25: return 32'ha831c66d; 6'd26: return 32'hb00327c8;
      6'd27: return 32'hbf597fc7; 6'd28: return 32'hc6e00bf3; 6'd29: return 32'hd5a79147;
      6'd30: return 32'h06ca6351; 6'd31: return 32'h14292967; 6'd32: return 32'h27b70a85;
      6'd33: return 32'h2e1b2138; 6'd34: return 32'h4d2c6dfc; 6'd35: return 32'h53380d13;
      6'd36: return 32'h650a7354; 6'd37: return 32'h766a0abb; 6'd38: return 32'h81c2c92e;
      6'd39: return 32'h92722c85; 6'd40: return 32'ha2bfe8a1; 6'd41: return 32'ha81a664b;
      6'd42: return 32'hc24b8b70; 6'd43: return 32'hc76c51a3; 6'd44: return 32'hd192e819;
      6'd45: return 32'hd6990624; 6'd46: return 32'hf40e3585; 6'd47: return 32'h106aa070;
      6'd48: return 32'h19a4c116; 6'd49: return 32'h1e376c08; 6'd50: return 32'h2748774c;
      6'd51: return 32'h34b0bcb5; 6'd52: return 32'h391c0cb3; 6'd53: return 32'h4ed8aa4a;
      6'd54: return 32'h5b9cca4f; 6'd55: return 32'h682e6ff3; 6'd56: return 32'h748f82ee;
      6'd57: return 32'h78a5636f; 6'd58: return 32'h84c87814; 6'd59: return 32'h8cc70208;
      6'd60: return 32'h90befffa; 6'd61: return 32'ha4506ceb; 6'd62: return 32'hbef9a3f7;
      default: return 32'hc67178f2;
    endcase
  endfunction

  localparam logic [255:0] IV = {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a,
                                 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};

  // ------------------------------------------------------------------ L: the loader
  typedef enum logic [2:0] {L_IDLE, L_MSG, L_PAD80, L_ZERO, L_LENH, L_LENL, L_DONE} lph_t;
  lph_t        lph;
  logic [31:0] nb [16];          // the block being loaded: nb[15] the newest word
  logic [4:0]  nbn;              // words in nb (16: full, waiting for C)
  logic        nb_last;          // nb is the message's last block
  logic [60:0] nbytes;           // message bytes so far
  logic        take;             // C takes nb this cycle

  logic        push;
  logic [31:0] pw;               // the word pushed
  logic        pw_last;          // ... and it ends the message (the length's low word)
  logic [31:0] dmask, dword;
  always_comb begin
    case (in_nbytes)
      3'd0: dmask = 32'h0000_0000;
      3'd1: dmask = 32'hFF00_0000;
      3'd2: dmask = 32'hFFFF_0000;
      3'd3: dmask = 32'hFFFF_FF00;
      default: dmask = 32'hFFFF_FFFF;
    endcase
    // a short last word carries the 0x80 right after its bytes
    dword = (in_data & dmask) | ((in_last && in_nbytes < 3'd4) ? (32'h8000_0000 >> (8 * in_nbytes))
                                                               : 32'h0);
    in_ready = lph == L_MSG && nbn != 5'd16;
    push = 1'b0; pw = '0; pw_last = 1'b0;
    if (nbn != 5'd16)
      case (lph)
        L_MSG:   begin push = in_valid; pw = dword; end
        L_PAD80: begin push = 1'b1; pw = 32'h8000_0000; end
        L_ZERO:  begin push = 1'b1; pw = '0; end
        L_LENH:  begin push = 1'b1; pw = {nbytes[60:29]}; end
        L_LENL:  begin push = 1'b1; pw = {nbytes[28:0], 3'b000}; pw_last = 1'b1; end
        default: ;
      endcase
  end

  always_ff @(posedge clk) begin
    if (rst) begin
      lph <= L_IDLE; nbn <= '0; nb_last <= 1'b0; nbytes <= '0;
    end else begin
      if (start && !busy) begin
        lph <= L_MSG; nbn <= '0; nb_last <= 1'b0; nbytes <= '0;
      end else begin
        if (take) nbn <= '0;
        if (push) begin
          for (int i = 0; i < 15; i++) nb[i] <= nb[i + 1];
          nb[15] <= pw;
          nbn <= nbn + 5'd1;
          nb_last <= pw_last;
          // after a word, the length goes in words 14 and 15 of a block: the next pushed word
          // is word nbn + 1
          case (lph)
            L_MSG: begin
              nbytes <= nbytes + 61'(in_nbytes);
              if (in_last) lph <= (in_nbytes == 3'd4) ? L_PAD80 : (nbn == 5'd13 ? L_LENH : L_ZERO);
            end
            L_PAD80, L_ZERO: if (nbn == 5'd13) lph <= L_LENH; else lph <= L_ZERO;
            L_LENH: lph <= L_LENL;
            L_LENL: lph <= L_DONE;
            default: ;
          endcase
        end
        if (lph == L_DONE && out_valid) lph <= L_IDLE;
      end
    end
  end

  // ------------------------------------------------------------------ C: the compressor
  logic [6:0]  t;                // 0: take; 1..64: round t-1; 65: add
  logic        cbusy, clast;
  logic [31:0] H [8];
  logic [31:0] a, b, c, d, e, f, g, hh;
  logic [31:0] w [16];           // W[r] .. W[r+15] in round r
  logic [31:0] hkw;              // h + K[r] + W[r] for the round about to run

  assign take = !cbusy && nbn == 5'd16;

  logic [31:0] t1, t2, wn;
  always_comb begin
    t1 = hkw + bs1(e) + ((e & f) ^ (~e & g));
    t2 = bs0(a) + ((a & b) ^ (a & c) ^ (b & c));
    wn = ss1(w[14]) + w[9] + ss0(w[1]) + w[0];
  end

  always_ff @(posedge clk) begin
    out_valid <= 1'b0;
    if (rst) begin
      cbusy <= 1'b0; t <= '0; clast <= 1'b0;
    end else if (start && !busy) begin
      for (int i = 0; i < 8; i++) H[i] <= IV[255 - 32 * i -: 32];
    end else if (take) begin
      cbusy <= 1'b1; t <= 7'd1; clast <= nb_last;
      for (int i = 0; i < 16; i++) w[i] <= nb[i];
      a <= H[0]; b <= H[1]; c <= H[2]; d <= H[3];
      e <= H[4]; f <= H[5]; g <= H[6]; hh <= H[7];
      hkw <= H[7] + kconst(6'd0) + nb[0];
    end else if (cbusy) begin
      if (t != 7'd65) begin
        // round r = t - 1
        hh <= g; g <= f; f <= e; e <= d + t1;
        d <= c; c <= b; b <= a; a <= t1 + t2;
        for (int i = 0; i < 15; i++) w[i] <= w[i + 1];
        w[15] <= wn;
        hkw <= g + kconst(t[5:0]) + w[1];      // round r + 1's (t = 64: unused)
        t <= t + 7'd1;
      end else begin
        H[0] <= H[0] + a; H[1] <= H[1] + b; H[2] <= H[2] + c; H[3] <= H[3] + d;
        H[4] <= H[4] + e; H[5] <= H[5] + f; H[6] <= H[6] + g; H[7] <= H[7] + hh;
        cbusy <= 1'b0;
        out_valid <= clast;
      end
    end
  end

  assign digest = {H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]};
  assign busy = lph != L_IDLE;
endmodule
