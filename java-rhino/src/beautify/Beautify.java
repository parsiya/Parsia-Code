package beautify;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.Scriptable;

/**
 * Beautify
 */
public class Beautify {

    public static void main(String[] args) {

        try {
            beautifyFile("cookiebanner.min.js", "cookie-beautified.js");
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Done");
    }

    public static void beautifyFile(String inFilePath, String outFilePath) throws IOException {
        // Read the file.
        File inFile = new File(inFilePath);
        String fileContent = FileUtils.readFileToString(inFile, "UTF-8");

        File outFile = new File(outFilePath);
        try {
            String beautified = beautify(fileContent);
            FileUtils.writeStringToFile(outFile, beautified, "UTF-8");
        } catch (Exception e) {
            // TODO: handle exception
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            System.out.println(sw.toString());
        }
    }

    public static String beautify(String uglyJS) throws IOException {
        // Following this tutorial
        // https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Rhino/Embedding_tutorial
        
        // Enter a context.
        Context cx = Context.enter();
        // Seems like it's not needed anymore.
        cx.setOptimizationLevel(-1);

        // Set version to JavaScript1.2 so that we get object-literal style
        // printing instead of "[object Object]"
        // cx.setLanguageVersion(Context.VERSION_1_2);

        // Initialize standard objects.
        Scriptable scope = cx.initSafeStandardObjects();

        // Read the jsbeautify.js file.
        String jsbeautifyFile = getResourceFile(Beautify.class, "/beautify.js");

        // Solution: https://stackoverflow.com/a/16338524 -- doesn't work
        cx.evaluateString(scope, "var global = {}; "+jsbeautifyFile, "global", 0, null);

        // Add our own export.
        cx.evaluateString(scope, "var js_beautify = global.js_beautify;", "export", 0, null);
        
        // Get the function.
        Object fjsBeautify = scope.get("js_beautify", scope);
        String result = "";

        if (!(fjsBeautify instanceof Function)) {
            System.out.println("js_beautify is undefined or not a function.");
            // System.out.println(fjsBeautify.toString());
        } else {
            Object functionArgs[] = { uglyJS };
            // Object functionArgs[] = { "var x='1234';var y='4444';var z='3123123';" };
            Function f = (Function)fjsBeautify;
            Object rst = f.call(cx, scope, scope, functionArgs);
            // System.out.println(report);
            result = Context.toString(rst);
        }
        // We should throw an exception here in production code.
        Context.exit();
        return result;
    }

    public static String getResourceFile(Class cls, String name) throws IOException {
        InputStream in = cls.getResourceAsStream(name);
        String content = IOUtils.toString(in, "UTF-8");
        in.close();
        return content;
    }
}