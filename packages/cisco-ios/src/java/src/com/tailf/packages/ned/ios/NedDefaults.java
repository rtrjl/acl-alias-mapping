/**
 * Utility class for injecting hidden default values if explicitly set in NSO.
 * Uses the meta-data tag "default-value".
 * Example:
 *   tailf:meta-data "default-value" {
 *    tailf:meta-value "$1 $2<NL> <DEFAULT><NL>exit<NL>"
 *        + " :: wrr-queue cos-map 1 1 0 :: wrr-queue cos-map 1 1 1"
 *        + " :: wrr-queue cos-map 1 2 2 :: wrr-queue cos-map 1 2 3"
 *        + " :: wrr-queue cos-map 3 1 6";
 *   }
 *
 * @author lbang
 * @version 20180510
 */

package com.tailf.packages.ned.ios;

import com.tailf.packages.ned.nedcom.NedComCliBase;
import static com.tailf.packages.ned.nedcom.NedString.stringQuote;

import java.util.regex.Pattern;

import com.tailf.ned.NedWorker;
import com.tailf.ned.NedException;

import com.tailf.conf.ConfBuf;
import com.tailf.conf.ConfPath;

import com.tailf.navu.NavuContainer;
import com.tailf.navu.NavuContext;
import com.tailf.navu.NavuList;

import com.tailf.ned.CliSession;


//
// NedDefaults
//
@SuppressWarnings("deprecation")
public class NedDefaults {

    private static final String SP = "^";
    private static final String[][] defaultMaps = {
        {
            "WRR-QUEUE-COSMAP-2",
            "wrr-queue cos-map 1 1 0 :: wrr-queue cos-map 1 1 1 :: wrr-queue cos-map 1 2 2 :: wrr-queue cos-map 1 2 3"
        },
        {
            "WRR-QUEUE-COSMAP-3",
            "wrr-queue cos-map 1 1 0 :: wrr-queue cos-map 1 2 1 :: wrr-queue cos-map 3 1 6"
        }
    };

    // Constructor data:
    private NedComCliBase owner;

    // Local data:
    private String operRoot;
    private String operList;

    /*
     * Constructor
     */
    NedDefaults(NedComCliBase owner) throws NedException {
        this.owner = owner;
        this.operRoot = "/ncs:devices/ncs:device{"
            +owner.device_id
            +"}/ncs:ned-settings/ios-op:cisco-ios-oper/defaults";
        this.operList = this.operRoot + "{%s}";
    }


    /**
     *
     * @param
     */
    public void cache(CliSession session, NedWorker worker, String[] lines, String model) throws NedException {

        if (session == null) {
            owner.logInfo(worker, "NedDefaults.cache() disabled due to offline device");
            return;
        }

        for (int i = 0 ; i < lines.length - 1; i++) {
            if (!isMetaDataDefault(lines[i])) {
                continue; // not a meta-data default
            }
            int c;
            for (c = i + 1; c < lines.length; c++) {
                if (!lines[c].trim().startsWith("! meta-data :: ")) {
                    break; // found command line
                }
            }
            cacheLine(session, worker, lines[c].trim(), lines[i].trim(), model);
        }
    }


    /**
     * Inject default values
     * @param
     * @return
     */
    public String inject(CliSession session, NedWorker worker, String res) throws NedException {

        if (session == null) {
            return res;
        }

        // Get defaults list using NAVU
        NavuContext context;
        StringBuilder sb = new StringBuilder();
        NavuList defaultsList;
        try {
            context = new NavuContext(owner.cdbOper);
            ConfPath cp = new ConfPath(this.operRoot);
            defaultsList = (NavuList)new NavuContainer(context).getNavuNode(cp);
        } catch (Exception e) {
            throw new NedException("DEFAULTS: failed to get list root", e);
        }

        // Insert entries first in configuration
        try {
            for (NavuContainer entry : defaultsList.elements()) {
                String inject = entry.leaf("inject").valueAsString();
                owner.traceInfo(worker, "transformed <= injected DEFAULTS: "+stringQuote(inject));
                sb.insert(0, inject); // add first
            }
        } catch (Exception e) {
            owner.logError(worker, "DEFAULTS - inject() ERROR", e);
        } finally {
            context.removeCdbSessions();
        }

        return sb.toString() + res;
    }


    /**
     * Cache a line
     * @param
     * @return
     * @throws NedException
     */
    private void cacheLine(CliSession session, NedWorker worker, String line, String meta, String model)
        throws NedException {
        int i;

        // metas[0] = ! meta-data
        // metas[1] = path
        // metas[2] = default-value
        // metas[3] = inject syntax
        // metas[4] = default line(s)
        String[] metas = meta.split(" :: ");

        // Get root path for default-value container
        String root = metas[1].substring(0, metas[1].lastIndexOf('/'));
        root = root.replaceFirst("(.*)}/config/(.*)", "$2");

        // Replace '/' within keys with SP to avoid being counted as token
        int depth = 0;
        for (i = 0; i < root.length(); i++) {
            if (root.charAt(i) == '{') {
                depth++;
            } else if (root.charAt(i) == '}') {
                depth--;
            } else if (root.charAt(i) == '/' && depth > 0) {
                root = root.substring(0,i)+SP+root.substring(i+1);
            }
        }
        String[] tokens = root.split("/");

        // Delete or create command
        boolean delete = false;
        if (line.startsWith("no ")) {
            owner.traceVerbose(worker, "DEFAULTS - Un-caching default : " + root);
            line = line.substring(3);
            delete = true;
        } else {
            owner.traceVerbose(worker, "DEFAULTS - Caching default : " + root);
        }

        //
        // Check if command matches one of the defaults [honor model regexp]
        //
        String defaultLine = null;
        if (metas[4].startsWith("MAP=")) {

            // Using pre-configured default map
            String defaultMap = metas[4].substring(4);

            // Dynamic maps
            if (metas[4].startsWith("MAP=WRR-QUEUE-COSMAP")) {
                defaultMap = getWrrQueueCosMapDefaultMap(session, worker, tokens);
            }

            // Look for default value in matching defaultMap
            owner.traceVerbose(worker, "DEFAULTS - Using default map = " + defaultMap);
            for (int map = 0; map < defaultMaps.length && defaultLine == null; map++) {
                if (defaultMaps[map][0].equals(defaultMap)) {
                    String[] defaults = defaultMaps[map][1].split(" :: ");
                    for (i = 0; i < defaults.length; i++) {
                        if (defaults[i].equals(line)) {
                            defaultLine = line;
                            break;
                        }
                    }
                }
            }
        } else {
            String modelRegexp = "";
            for (i = 4; i < metas.length; i++) {
                int j;
                if ((j = metas[i].indexOf(" MODEL=")) > 0) {
                    defaultLine = metas[i].substring(0, j);
                    modelRegexp = metas[i].substring(j + 7);
                    if (!model.matches(".*"+modelRegexp+".*")) {
                        continue;
                    }
                } else {
                    defaultLine = metas[i];
                }
                if (defaultLine.equals(line)) {
                    break;
                }
            }
            if (i == metas.length) {
                defaultLine = null;
            }
        }
        if (defaultLine == null) {
            return;
        }

        //
        // Command matches a default
        //

        //
        // Create inject config snippet using the template from metas[3]
        //
        String inject = metas[3];
        inject = inject.replace("<NL>", "\n");
        int offset = 0;
        for (i = inject.indexOf('$'); i >= 0; i = inject.indexOf('$', i+offset)) {
            int num = (inject.charAt(i+1) - '1');
            inject = inject.substring(0,i) + tokens[num] + inject.substring(i+2);
            offset = offset + tokens[num].length() - 2;
        }
        inject = inject.replace("<DEFAULT>", line);
        inject = inject.replace("{", " ");
        inject = inject.replace("}", " ");
        inject = inject.replace(SP, "/");

        //
        // Create root path to store the inject config in oper cache
        //
        root = root.replace(" ", SP); // multiple keys, can't have blank in keys
        root = root.replace("{", "(").replace("}", ")");
        root = root + line.replace(" ", "");

        //
        // Add/update or delete defaults cache
        //
        if (delete) {
            owner.traceInfo(worker, "DEFAULTS - Deleting : " + root);
            operDeleteList(worker, root);
        } else {
            owner.traceInfo(worker, "DEFAULTS - Adding : "+root);
            operSetElem(worker, inject, root+"/inject");
        }
    }


    /**
     * Set default entry in oper data defaults list
     * @param
     */
    private void operSetElem(NedWorker worker, String value, String path) {
        final String root = path.substring(0,path.lastIndexOf('/'));
        final String elem = path.substring(path.lastIndexOf('/'));
        try {
            ConfPath cp = new ConfPath(String.format(this.operList, root));
            if (!owner.cdbOper.exists(cp)) {
                owner.cdbOper.create(cp);
            }
            owner.cdbOper.setElem(new ConfBuf(value), cp.append(elem));
        } catch (Exception e) {
            owner.logError(worker, "DEFAULTS - ERROR : failed to set "+path, e);
        }
    }


    /**
     * Delete default entry in oper data defaults list
     * @param
     */
    private void operDeleteList(NedWorker worker, String path) {
        try {
            ConfPath cp = new ConfPath(String.format(this.operList, path));
            if (owner.cdbOper.exists(cp)) {
                owner.cdbOper.delete(cp);
            }
        } catch (Exception e) {
            owner.logError(worker, "DEFAULTS - ERROR : failed to delete "+path, e);
        }
    }


    /**
     *
     * @param
     * @return
     */
    private boolean isMetaDataDefault(String line) {
        if (!line.trim().startsWith("! meta-data :: ")) {
            return false;
        }
        return line.contains(" :: default-value");
    }


    /**
     * Run command on device
     * @param
     * @return
     */
    private String print_line_exec(CliSession session, NedWorker worker, String line) throws Exception {
        String prompt = "\\A[^\\# ]+#[ ]?$";

        // Send command and wait for echo
        session.print(line + "\n");
        session.expect(new String[] { Pattern.quote(line) }, worker);

        // Return command output
        return session.expect(prompt, worker);
    }


    /**
     *
     * @param
     * @return
     */
    private String getWrrQueueCosMapDefaultMap(CliSession session, NedWorker worker, String[] tokens) {
        String defaultMap = "WRR-QUEUE-COSMAP-2";

        // Interface name
        String ifname = tokens[0] + " " + tokens[1];
        ifname = ifname.replace("{", "").replace("}", "").replace(SP, "/");

        // Show queuing to determine what type of default map
        try {
            // WS-C6504-E
            String res = print_line_exec(session, worker, "show queueing "+ifname+" | i WRR");
            // CISCOIOS7604
            if (res.contains("Invalid input detected at")) {
                res = print_line_exec(session, worker, "show mls qos queuing "+ifname+" | i WRR");
            }
            if (res.contains("Invalid input detected at")) {
                owner.logInfo(worker, "DEFAULTS - cache() ERROR :: failed to show queuing for interface");
            } else if (res.contains("[queue 3]")) {
                defaultMap = "WRR-QUEUE-COSMAP-3";
            }
        } catch (Exception e) {
            owner.logError(worker, "DEFAULTS - cache() ERROR :: show queuing exception", e);
        }

        return defaultMap;
    }

}
