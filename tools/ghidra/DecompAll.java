// DecompAll.java -- decompile every function in the analysed image to one file.
//
// Usage (from tools/ghidra_analyze.sh's project, after an analysis run):
//
//   tools/ghidra_decompile.sh --all sdram1.bin
//
// or directly:
//
//   analyzeHeadless <proj> mc101 -process sdram1.bin -noanalysis \
//     -scriptPath tools/ghidra -postscript DecompAll.java
//
// Output: $GHIDRA_WORK/<image>.decompall.txt (default /tmp/rev101).
//
// This is the workhorse for the findings in docs/SECONDARY_MCU.md: the QSPI
// read path and the CRC-32 routines there were located by grepping the
// whole-program decompilation rather than by targeted single-function
// decompiles, because most of them have no direct callers in the analyser's
// call graph (they are reached through computed/jump addresses).
//
// Each function is written as a header line
//
//     ================ <address> <name> size=<n> ================
//
// followed by its C, then a blank line.  A per-function time limit is used so
// that one pathological function cannot stall the whole run.
//
//@category MC101

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import java.io.PrintWriter;
import java.io.File;

public class DecompAll extends GhidraScript {

    /** Seconds allowed per function before the decompiler gives up. */
    private static final int TIMEOUT_SECONDS = 45;

    private File outFile() {
        String work = System.getenv("GHIDRA_WORK");
        if (work == null || work.isEmpty()) {
            work = "/tmp/rev101";
        }
        return new File(work, currentProgram.getName() + ".decompall.txt");
    }

    @Override
    public void run() throws Exception {
        File out = outFile();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();

        PrintWriter w = new PrintWriter(out);
        int total = 0;
        int ok = 0;
        int failed = 0;
        try {
            for (Function f : fm.getFunctions(true)) {
                total++;
                w.println("================ " + f.getEntryPoint() + " "
                          + f.getName()
                          + " size=" + f.getBody().getNumAddresses()
                          + " ================");
                try {
                    DecompileResults res =
                        di.decompileFunction(f, TIMEOUT_SECONDS, monitor);
                    if (res != null && res.decompileCompleted()) {
                        w.println(res.getDecompiledFunction().getC());
                        ok++;
                    } else {
                        w.println("DECOMPILE FAILED");
                        failed++;
                    }
                } catch (Exception e) {
                    w.println("EXC " + e);
                    failed++;
                }
                w.println();
            }
        } finally {
            w.close();
        }
        println("WROTE " + out.getAbsolutePath()
                + " funcs=" + total + " ok=" + ok + " failed=" + failed);
    }
}
