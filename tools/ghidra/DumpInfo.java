// DumpInfo.java -- summarize a headless Ghidra analysis of the MC-101 images.
//
// Writes $GHIDRA_WORK/<image>.ghidra.txt (default /tmp/rev101) with a header
// line and one "FUNC <address> <name> size=<n>" line per recovered function.
//
//@category MC101

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import java.io.PrintWriter;
import java.io.File;

public class DumpInfo extends GhidraScript {

    private File outFile() {
        String work = System.getenv("GHIDRA_WORK");
        if (work == null || work.isEmpty()) {
            work = "/tmp/rev101";
        }
        return new File(work, currentProgram.getName() + ".ghidra.txt");
    }

    @Override
    public void run() throws Exception {
        File out = outFile();
        FunctionManager fm = currentProgram.getFunctionManager();

        PrintWriter w = new PrintWriter(out);
        int n = 0;
        try {
            w.println("PROGRAM=" + currentProgram.getName());
            w.println("LANG=" + currentProgram.getLanguageID());
            w.println("BASE=" + currentProgram.getImageBase());
            w.println("FUNCCOUNT=" + fm.getFunctionCount());
            for (Function f : fm.getFunctions(true)) {
                w.println("FUNC " + f.getEntryPoint() + " " + f.getName()
                          + " size=" + f.getBody().getNumAddresses());
                n++;
            }
        } finally {
            w.close();
        }
        println("WROTE " + out.getAbsolutePath() + " funcs=" + n);
    }
}
