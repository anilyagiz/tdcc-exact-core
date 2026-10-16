// exact_sha256 on messages from a file (tests/test_exact_rtl.py): +in=<file>, one message per
// line, "<bytes> <word> <word> ..." (decimal byte count, then big-endian 32-bit hex words, at
// least one); prints "D <digest>" and "CYCLES <n>" (start to out_valid) per message.
`timescale 1ns / 1ps
module exact_sha256_tb;
  logic clk = 1'b0, rst = 1'b1;
  always #5 clk = ~clk;
  logic         start = 1'b0, in_valid = 1'b0, in_last = 1'b0, in_ready, busy, out_valid;
  logic [31:0]  in_data = '0;
  logic [2:0]   in_nbytes = '0;
  logic [255:0] digest;
  exact_sha256 dut (.*);

  integer fd, n, k, nw, cyc0;
  logic [31:0] w;
  string fn;
  initial begin
    if (!$value$plusargs("in=%s", fn)) $fatal(1, "+in=<file>");
    fd = $fopen(fn, "r");
    if (fd == 0) $fatal(1, "cannot open %s", fn);
    repeat (3) @(negedge clk);
    rst = 1'b0;
    while ($fscanf(fd, "%d", n) == 1) begin
      @(negedge clk);
      start = 1'b1; cyc0 = int'($time / 10);
      @(negedge clk);
      start = 1'b0;
      nw = (n + 3) / 4;
      if (nw == 0) nw = 1;
      for (k = 0; k < nw; k++) begin
        if ($fscanf(fd, "%h", w) != 1) $fatal(1, "short message");
        in_valid = 1'b1; in_data = w;
        in_last = k == nw - 1;
        in_nbytes = (k == nw - 1) ? 3'(n - 4 * k) : 3'd4;
        while (!in_ready) @(negedge clk);
        @(negedge clk);
      end
      in_valid = 1'b0; in_last = 1'b0;
      while (!out_valid) @(negedge clk);
      $display("D %064h", digest);
      $display("CYCLES %0d", int'($time / 10) - cyc0);
    end
    $finish;
  end
endmodule
