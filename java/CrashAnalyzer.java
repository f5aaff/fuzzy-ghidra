import java.io.File;

public class CrashAnalyzer {

    public void analyzeCrashes(String crashDir) {
        File dir = new File(crashDir);
        File[] crashFiles = dir.listFiles();

        if (crashFiles == null || crashFiles.length == 0) {
            System.out.println("No crashes found.");
            return;
        }

        for (File crashFile : crashFiles) {
            System.out.println("Crash found in file: " + crashFile.getName());
            // Further analysis could be done here using GDB or a custom crash analyzer
        }
    }
}

