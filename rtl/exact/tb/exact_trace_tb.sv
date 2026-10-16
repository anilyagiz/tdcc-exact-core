// exact_trace driven by a command file (tests/test_exact_rtl.py writes it from a TraceLog's
// events): +in=<file>. All values hex. The testbench plays both the sequencer (steps, pushed
// back to back under valid/ready) and the host (the control registers):
//   I b0 .. b7                    INIT with the binding (words as BINDING), wait for it
//   E every                       EVERY
//   S slice pc i0 .. i7 r0 .. r15 a step (i: the instruction's words, r: R0..R15 after it)
//   A kind len d0 .. d15          post an event: waits until the engine is idle or paused
//   Q                             wait until idle; print "R steps events stall c0 .. c7" (the
//                                 registers, as the host reads them) and "CYCLES <n>"
// Every chain update prints "U <steps> <chain>" (the chain's bytes in order, as trace.py's hex).
`timescale 1ns / 1ps
module exact_trace_tb;
  logic clk = 1'b0, rst = 1'b1;
  always #5 clk = ~clk;
  logic          step_valid = 1'b0, step_ready, step_afull;
  logic [15:0]   step_slice = '0;
  logic [31:0]   step_pc = '0;
  logic [255:0]  step_ir = '0;
  logic [511:0]  step_regs = '0;
  logic          reg_we = 1'b0;
  logic [5:0]    reg_addr = '0;
  logic [31:0]   reg_wdata = '0, reg_rdata;
  logic [255:0]  chain;
  logic          upd;
  logic [63:0]   steps;
  exact_trace #(.DEPTH(8)) dut (.*);

  always @(posedge clk) if (upd) $display("U %0d %064h", steps, chain);
  // step_afull's contract: with afull high, at most one entry is free
  always @(posedge clk) if (!rst && step_afull && dut.cnt < 7) $fatal(1, "afull with room");

  task automatic wr(input logic [5:0] a, input logic [31:0] d);
    @(negedge clk);
    reg_we = 1'b1; reg_addr = a; reg_wdata = d;
    @(negedge clk);
    reg_we = 1'b0;
  endtask
  task automatic rd(input logic [5:0] a, output logic [31:0] d);
    @(negedge clk);
    reg_addr = a;
    @(negedge clk);
    d = reg_rdata;
  endtask

  integer fd, k, cyc0, r;
  logic [31:0] v, st, sl, kind, len, lo, hi, ev, stl;
  logic [31:0] cw [8];
  string fn;
  byte c;
  initial begin
    if (!$value$plusargs("in=%s", fn)) $fatal(1, "+in=<file>");
    fd = $fopen(fn, "r");
    if (fd == 0) $fatal(1, "cannot open %s", fn);
    repeat (3) @(negedge clk);
    rst = 1'b0;
    cyc0 = int'($time / 10);
    while ($fscanf(fd, " %c", c) == 1) begin
      case (c)
        "I": begin
          for (k = 0; k < 8; k++) begin
            r = $fscanf(fd, "%h", v);
            wr(6'h10 + 6'(k), v);
          end
          wr(6'h00, 32'h1);
          do rd(6'h00, st); while (st[0]);
        end
        "E": begin
          r = $fscanf(fd, "%h", v);
          wr(6'h01, v);
        end
        "S": begin
          r = $fscanf(fd, "%h %h", sl, v);
          @(negedge clk);
          step_slice = sl[15:0]; step_pc = v;
          for (k = 0; k < 8; k++) begin
            r = $fscanf(fd, "%h", v);
            step_ir[32 * k +: 32] = v;
          end
          for (k = 0; k < 16; k++) begin
            r = $fscanf(fd, "%h", v);
            step_regs[32 * k +: 32] = v;
          end
          step_valid = 1'b1;
          while (!step_ready) @(negedge clk);
          @(negedge clk);
          step_valid = 1'b0;
        end
        "A": begin
          r = $fscanf(fd, "%h %h", kind, len);
          do rd(6'h00, st); while (!(!st[0] || st[1]) || st[2]);
          wr(6'h02, kind);
          wr(6'h03, len);
          for (k = 0; k < 16; k++) begin
            r = $fscanf(fd, "%h", v);
            wr(6'h20 + 6'(k), v);
          end
          wr(6'h00, 32'h2);
        end
        "Q": begin
          do rd(6'h00, st); while (st[0]);
          rd(6'h04, lo); rd(6'h05, hi); rd(6'h06, ev); rd(6'h07, stl);
          for (k = 0; k < 8; k++) rd(6'h08 + 6'(k), cw[k]);
          $display("R %0d %0d %0d %08h %08h %08h %08h %08h %08h %08h %08h", {hi, lo}, ev, stl,
                   cw[0], cw[1], cw[2], cw[3], cw[4], cw[5], cw[6], cw[7]);
          $display("CYCLES %0d", int'($time / 10) - cyc0);
        end
        default: $fatal(1, "bad command %c", c);
      endcase
    end
    $finish;
  end
endmodule
