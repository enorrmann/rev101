// DecompOne.java -- decompile one or more functions to a file.
//
// Usage: -postscript DecompOne.java 0x01075972 [more addresses...]
// Output: $GHIDRA_WORK/decomp_out.txt (default /tmp/rev101/decomp_out.txt)
//
//@category MC101

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.PrintWriter;
import java.io.File;

public class DecompOne extends GhidraScript {

    private File outFile() {
        String work = System.getenv("GHIDRA_WORK");
        if (work == null || work.isEmpty()) {
            work = "/tmp/rev101";
        }
        return new File(work, "decomp_out.txt");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("no addresses given");
            return;
        }

        File out = outFile();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        PrintWriter w = new PrintWriter(out);
        try {
            for (String a : args) {
                Address addr = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(a);
                Function f = getFunctionAt(addr);
                if (f == null) {
                    w.println("no function at " + a);
                    continue;
                }
                w.println("================ " + f.getEntryPoint()
                          + " " + f.getName() + " ================");
                DecompileResults res = di.decompileFunction(f, 120, monitor);
                if (res != null && res.decompileCompleted()) {
                    w.println(res.getDecompiledFunction().getC());
                } else {
                    w.println("DECOMPILE FAILED: "
                              + (res == null ? "null" : res.getErrorMessage()));
                }
                w.println();
            }
        } finally {
            w.close();
        }
        println("WROTE " + out.getAbsolutePath());
    }
}
