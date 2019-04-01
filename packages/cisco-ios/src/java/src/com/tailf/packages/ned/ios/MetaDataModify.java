package com.tailf.packages.ned.ios;

import com.tailf.packages.ned.nedcom.NedComCliBase;
import static com.tailf.packages.ned.nedcom.NedString.getMatch;
import static com.tailf.packages.ned.nedcom.NedString.stringQuote;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import com.tailf.ned.NedWorker;
import com.tailf.ned.NedException;

import com.tailf.conf.ConfPath;
import com.tailf.conf.ConfValue;

import com.tailf.maapi.Maapi;

import com.tailf.navu.NavuContainer;
import com.tailf.navu.NavuContext;
import com.tailf.navu.NavuList;
import com.tailf.navu.NavuLeaf;


/**
 * Utility class for modifying config data based on YANG model meta data provided by NCS.
 * Note: old code does not handle multiple meta-data tags
 *
 * @author lbang
 * @version 20180509
 */

// META SYNTAX:
// ================================
// metas[0]    = ! meta-data
// metas[1]    = path
// metas[2]    = annotation name
// metas[3..N] = meta value(s)
//
// Supported new line annotations:
//    max-values
//    max-values-mode
//    max-values-copy-meta
//    replace-list
//    replace-mls-qos-srr-queue
//    string-add-quotes
//    patch-interface-speed
//    inject-interface-config-X
//    ip-vrf-rd-restore
//    if-vrf-restore
//    trim-delete-when-empty
//    trim-empty-create
//    trim-when-list-deleted
//    boolean-delete-with-default
//    delete-with-default
//    appnav-controller-change
//    shutdown-container-before-delete
//    inactivate-container-before-change

// Supported old line annotations:
//    add-keyword
//    string-remove-quotes
//    range-list-syntax
//    range-list-syntax-mode
//    diff-interface-move-X
//    shutdown-container-before-change

@SuppressWarnings("deprecation")
public class MetaDataModify {

    // Static data:
    private static final String PFX = "ios";
    private static final String METADATA = "! meta-data :: /ncs:devices/device{";

    // Constructor data:
    private NedComCliBase owner;

    // Cached ned-settings:
    private boolean autoIpCommunityListRepopulate;
    private boolean autoIpVrfRdRestore;
    private boolean autoIfSwitchportSpPatch;
    private boolean autoVrfForwardingRestore;
    private boolean aaaAccountingModeFormat;

    /**
     * Constructor
     */
    MetaDataModify(NedComCliBase owner) throws Exception {
        this.owner = owner;

        this.autoIpCommunityListRepopulate = owner.nedSettings.getBoolean("auto/ip-community-list-repopulate");
        this.autoIpVrfRdRestore = owner.nedSettings.getBoolean("auto/ip-vrf-rd-restore");
        this.autoIfSwitchportSpPatch = owner.nedSettings.getBoolean("auto/if-switchport-sp-patch");
        this.autoVrfForwardingRestore = owner.nedSettings.getBoolean("auto/vrf-forwarding-restore");
        this.aaaAccountingModeFormat = owner.nedSettings.getBoolean("api/aaa-accounting-mode-format");
    }


    /*
     * Modify config data based on meta-data given by NCS.
     *
     * @param data - config data from applyConfig, before commit
     * @return Config data modified after parsing !meta-data tags
     */
    public String modifyData(NedWorker worker, String data, int toTh, int fromTh, Maapi mm, String model)
        throws NedException {
        int j;
        String match;
        final boolean isNetsim = model.contains("NETSIM");

        NavuContext toContext = null;
        try {
            toContext = new NavuContext(mm, toTh);
        } catch (Exception e) {
            throw new NedException("MetaDataModify.modifyData() - ERROR :: failed to create NAVU context", e);
        }

        //
        // MODIFY LINE NEW
        // Note: Can add new lines and can handle multiple meta-data tags per cmd
        //
        String[] lines = data.split("\n");
        StringBuilder sb = new StringBuilder();
        StringBuilder sblast = new StringBuilder();
        int lastif = -1;
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].trim().isEmpty()) {
                continue;
            }
            if (lines[i].startsWith("interface ")) {
                lastif = i;
                lines = ncsPatchInterface(worker, lines, lastif, isNetsim);
            }
            if (!lines[i].trim().startsWith("! meta-data :: /ncs:devices/device{")) {
                sb.append(lines[i] + "\n");  // Normal config line -> add
                continue;
            }

            // Find command index (reason: can be multiple meta-data tags per command)
            int cmd = getCmd(lines, i + 1);
            if (cmd == -1) {
                continue;
            }
            String otherMetas = "";
            for (j = i + 1; j < cmd; j++) {
                otherMetas += lines[j] + "\n";
            }
            //traceVerbose(worker, "OTHER-METAS='"+otherMetas+"'");
            String trimmed = lines[cmd].trim();
            String command = trimmed.startsWith("no ") ? trimmed.substring(3) : trimmed;
            String nexttrim = (cmd + 1 < lines.length) ? lines[cmd+1].trim() : "";
            String pxSpace = lines[cmd].substring(0, lines[cmd].length() - trimmed.length());
            String spaces = lines[cmd].replace(trimmed, "");

            // Extract meta-data and meta-value(s), store in metas[] where:
            // metas[1] = meta path
            // metas[2] = meta tag name
            // metas[3] = first meta-value (each value separated by ' :: '
            String meta = lines[i].trim();
            String[] metas = meta.split(" :: ");
            String metaPath = metas[1];
            String configPath = metaPath.substring(metaPath.indexOf("/config/")+8);
            String metaTag = metas[2];

            //for (j = 0; j < metas.length; j++) traceVerbose(worker, "METAS["+j+"]='"+metas[j]+"'");
            //traceVerbose(worker, "LINE='"+line+"'");

            // if-switchport-sp-patch
            // ======================
            // Fix me3600 problem with switchport clearing service-policy and then bugging out
            if ("if-switchport-sp-patch".equals(metaTag)) {
                if (!autoIfSwitchportSpPatch) {
                    continue;
                }
                lines = trimMetaTags(worker, lines, i + 1, meta);
                if ("switchport".equals(trimmed) || "no switchport".equals(trimmed)) {
                    try {
                        // Inject "no service-policy output <name>" since cleared by switchport
                        String p = metaPath.replace("/switchport", "/service-policy/output");
                        if (mm.exists(toTh, p)) {
                            String polname = ConfValue.getStringByValue(p, mm.getElem(toTh, p));
                            traceMeta(worker, metaTag, "injected delete of output service-policy "+polname);
                            sb.append(" no service-policy output "+polname+"\n");
                        }
                        // Inject "no service-policy input <name>" since cleared by switchport
                        p = metaPath.replace("/switchport", "/service-policy/input");
                        if (mm.exists(toTh, p)) {
                            String polname = ConfValue.getStringByValue(p, mm.getElem(toTh, p));
                            traceMeta(worker, metaTag, "injected delete of input service-policy "+polname);
                            sb.append(" no service-policy input "+polname+"\n");
                        }
                    } catch (Exception e) {
                        throw new NedException("modifyData(if-switchport-sp-patch) - ERROR :: "+e.getMessage(), e);
                    }
                }
            }

            // add-remove-keyword
            // ======================
            else if ("add-remove-keyword".equals(metaTag)) {
                if (isNetsim) {
                    continue;
                }
                if (!maapiExists(worker, mm, fromTh, "from", metaPath)) {
                    continue;
                }
                if (!maapiExists(worker, mm, toTh, "to", metaPath)) {
                    continue;
                }
                traceMeta(worker, metaTag, "modifying '"+trimmed+"', injected add|remote keyword");
                if (trimmed.startsWith("no ")) {
                    lines[cmd] = lines[cmd].replace("no ", "").replace(metas[3], metas[3]+" remove");
                } else {
                    lines[cmd] = lines[cmd].replace(metas[3], metas[3]+" add");
                }
            }

            // split-long-line
            // ====================
            // Split config lines with multiple values into multiple lines
            // metas[3] = offset in values[] for first value
            // Example:
            // tailf:meta-data "split-long-line" {
            //  tailf:meta-value "2";
            // }
            else if (metaTag.startsWith("split-long-line")) {
                if (lines[cmd].length() < 250) {
                    continue;
                }

                int words = Integer.parseInt(metas[3]);
                if (trimmed.startsWith("no ")) {
                    words++;
                }

                int offset = -1;
                for (int w = 0; w < words; w++) {
                    offset = trimmed.indexOf(' ', offset + 1);
                }
                String base = spaces + trimmed.substring(0, offset);
                String[] values = trimmed.substring(offset + 1).split(" +");

                String line = base;
                for (int v = 0; v < values.length; v++) {
                    if (line.length() + 1 + values[v].length() >= 250) {
                        sb.append(line+"\n");
                        line = base;
                    }
                    line += " " + values[v];
                }
                if (!line.equals(base)) {
                    sb.append(line+"\n");
                }

                traceMeta(worker, metaTag, "split '"+trimmed+"' into multiple lines");
                lines[cmd] = "";
            }

            // max-values
            // max-values-copy-meta
            // max-values-mode
            // max-values-add
            // ====================
            // Split config lines with multiple values into multiple lines with a maximum
            // number of values per line.
            // metas[3] = offset in values[] for first value
            // metas[4] = maximum number of values per line
            // metas[5] = value separator [OPTIONAL]
            // Example:
            // tailf:meta-data "max-values" {
            //  tailf:meta-value "4 :: 8 :: ";
            // }
            else if (metaTag.startsWith("max-values")) {
                // Do not split modes with separators if contents in submode
                if ("max-values-mode".equals(metaTag)
                    && cmd + 1 < lines.length
                    && !isTopExit(lines[cmd+1])) {
                    continue;
                }
                String sep = " ";
                if (metas.length > 5) {
                    sep = metas[5];
                }
                int offset = Integer.parseInt(metas[3]);
                if (trimmed.startsWith("no ")) {
                    offset++;
                }
                if ("max-values-add".equals(metaTag)
                    && maapiExists(worker, mm, fromTh, "from", metaPath)) {
                    offset++;
                    lines[cmd] = lines[cmd].replace(metas[6], metas[6]+" add");
                    trimmed = lines[cmd].trim();
                }
                int start = NindexOf(trimmed, " ", offset);
                if (start > 0) {
                    int maxValues = Integer.parseInt(metas[4]);
                    String[] val = trimmed.substring(start+1).trim().split(sep+"+");
                    if (val.length > maxValues) {
                        String lprefix = pxSpace + trimmed.substring(0, start).trim();
                        if (metaTag.contains("-copy-meta")) {
                            lprefix = otherMetas + lprefix;
                        }
                        traceMeta(worker, metaTag, "split '"+trimmed+"' into max "
                                  +maxValues+" values, separator='"+sep+"'");
                        sb.append(duplicateToX2(lprefix, val, "", maxValues, sep));
                        lines = trimCmd(lines, i, cmd);
                    }
                }
            }


            // replace-list[-withkey][-withdesc]
            // =================================
            // Use with lists where the entire list is deleted if one entry is deleted
            // metas[1] = path
            // metas[2] = "replace-list[-opt]"
            // metas[3] = entry prefix
            // metas[4] = sublist list name
            // metas[5] = sublist list key | sublist leaf [with replace-list-withkey]
            // metas[6] = device regexp [OPTIONAL]
            // Example:
            // tailf:meta-data "replace-list" {
            //  tailf:meta-value "ip community-list standard :: entry :: expr :: C3550";
            // }
            else if (metaTag.startsWith("replace-list")) {
                if (autoIpCommunityListRepopulate && metas[3].startsWith("ip community-list ")) {
                    // Honor old ned-setting regardless of device model
                }
                else if (metas.length > 6 && !model.matches(".*"+metas[6]+".*")) {
                    traceVerbose(worker, "meta-data :: "+metaTag+" :: ignored, different model: "+model);
                    lines = trimMetaTags(worker, lines, i, meta);
                    continue;
                }
                String name = metaPath.substring(metaPath.lastIndexOf('{')+1).replace("}", "");
                boolean hasDeleteLine = false;
                for (j = cmd; j < lines.length; j++) {
                    if (lines[j].trim().startsWith("no " + metas[3] + " " + name + " ")) {
                        hasDeleteLine = true;
                        break;
                    }
                }
                if (!hasDeleteLine) {
                    // No delete of individual entries -> trim all identical meta-data tags on this entry
                    lines = trimMetaTags(worker, lines, i, meta);
                    continue;
                }

                // Delete list and trim all tags & commands operating on this list entry
                traceMeta(worker, metaTag, metas[3] + " " + name);
                lines = trimMetaTagsAndCmd(lines, i, meta);
                sb.append("no " + metas[3] + " " + name + "\n");

                // If non-empty list put back all existing entries
                NavuContainer root;
                try {
                    ConfPath cp = new ConfPath(metaPath);
                    root = (NavuContainer)new NavuContainer(toContext).getNavuNode(cp);
                    if (root == null || !root.exists()) {
                        continue;
                    }
                } catch (Exception ignore) {
                    // Ignore Exception
                    continue;
                }
                try {
                    // -withdesc
                    if (metaTag.contains("-withdesc")) {
                        String val = root.leaf(PFX, "description").valueAsString().trim();
                        sb.append(metas[3] + " " + name + " description " + val + "\n");
                    }
                    NavuList list = root.list(PFX, metas[4]);
                    if (list == null || list.isEmpty()) {
                        continue;
                    }
                    for (NavuContainer entry : list.elements()) {
                        String val = "";
                        if (metaTag.contains("-withkey")) {
                            val = " " + metas[4] + " " + entry.leaf(PFX, metas[4]).valueAsString().trim();
                        }
                        val += " " + entry.leaf(PFX, metas[5]).valueAsString().trim();
                        sb.append(metas[3] + " " + name + val + "\n");
                    }
                } catch (Exception e) {
                    throw new NedException("modifyData(replace-list) - ERROR :: "+e.getMessage(), e);
                }
            }

            // new-ip-acl-type-change
            // ======================
            else if ("new-ip-acl-type-change".equals(metaTag)) {
                if (trimmed.startsWith("no ")) {
                    continue;
                }
                String oldType = maapiGetLeafString(worker, mm, fromTh, "from", metaPath);
                String newType = maapiGetLeafString(worker, mm, toTh, "to", metaPath);
                if (oldType == null || oldType.equals(newType)) {
                    continue;
                }

                // Delete the previous list
                traceMeta(worker, metaTag, "changing access-list type: "+trimmed);
                if ("standard".equals(oldType)) {
                    sb.append("no "+trimmed.replace("extended", "standard")+"\n");
                } else {
                    sb.append("no "+trimmed.replace("standard", "extended")+"\n");
                }

                // Trim all no commands
                for (j = cmd + 1; j < lines.length; j++) {
                    if ("exit".equals(lines[j])) {
                        break;
                    }
                    if (lines[j].trim().startsWith("no ")) {
                        lines[j] = "";
                    }
                }
            }

            // replace-mls-qos-srr-queue
            // =========================
            // A cat3750 can't delete single entries in the mls qos srr-queue
            // As a consequence the whole list must be removed first.
            // And then all entries always added back.
            else if ("replace-mls-qos-srr-queue".equals(metaTag)) {
                String name = metaPath.substring(metaPath.lastIndexOf('{')+1).replace("}", "");
                boolean hasDeleteLine = false;
                for (j = cmd; j < lines.length; j++) {
                    if (lines[j].trim().startsWith("no mls qos srr-queue " + name + " ")) {
                        hasDeleteLine = true;
                        break;
                    }
                }
                if (!hasDeleteLine) {
                    // Did not find a single delete of entry -> add this line -> but split to max 8 values
                    int start = NindexOf(trimmed, " ", 9);
                    if (start > 0) {
                        String lprefix = trimmed.substring(0, start).trim();
                        sb.append(duplicateToX(lprefix, trimmed.substring(start+1).trim(), "", 8, " "));
                        lines = trimCmd(lines, i, cmd);
                    }
                    continue;
                }

                // Delete list and trim all tags & commands operating on this list entry
                traceMeta(worker, metaTag, "'mls qos srr-queue "+name+"'");
                lines = trimMetaTagsAndCmd(lines, i, meta);
                sb.append("no mls qos srr-queue " + name + "\n");

                // If non-empty list put back all existing entries
                NavuContainer root;
                try {
                    ConfPath cp = new ConfPath(metaPath);
                    root = (NavuContainer)new NavuContainer(toContext).getNavuNode(cp);
                    if (root == null || !root.exists()) {
                        continue;
                    }
                } catch (Exception ignore) {
                    // Ignore Exception
                    continue;
                }
                try {
                    NavuList list = root.list(PFX, "queue-threshold-list");
                    if (list == null || list.isEmpty()) {
                        continue;
                    }
                    for (NavuContainer entry : list.elements()) {
                        String key1 = entry.leaf(PFX, "queue").valueAsString().trim();
                        String key2 = entry.leaf(PFX, "threshold").valueAsString().trim();
                        String key = "queue " + key1 + " threshold " + key2;
                        NavuLeaf valuesLeaf = entry.leaf(PFX, "values");
                        if (valuesLeaf == null || valuesLeaf.valueAsString() == null) {
                            traceInfo(worker, "meta-data WARNING :: null values in: mls qos srr-queue "+name+" "+key);
                            continue;
                        }
                        String values = valuesLeaf.valueAsString().trim();
                        sb.append(duplicateToX("mls qos srr-queue " + name + " " + key, values, "", 8, " "));
                    }
                } catch (Exception e) {
                    throw new NedException("modifyData(replace-mls-qos-srr-queue) - ERROR :: "+e.getMessage(), e);
                }
            }

            // string-add-quotes
            // =================
            // Add a " before and after specified string
            // metas[3] = regexp, where <STRING> is the string to look at.
            // example:
            // tailf:meta-data "string-add-quotes" {
            //  tailf:meta-value "syslog msg <STRING>";
            // }
            else if ("string-add-quotes".equals(metaTag)) {
                String regexp = metas[3].replace("<STRING>", "(.*)");
                String replacement = metas[3].replace("<STRING>", "\\\"$1\\\"");
                String newline = lines[cmd].replaceFirst(regexp, replacement);
                if (!lines[cmd].equals(newline)) {
                    lines[cmd] = newline;
                    traceMeta(worker, metaTag, "quoted '"+lines[cmd]+"'");
                }
            }

            // patch-interface-speed
            // =====================
            else if ("patch-interface-speed".equals(metaTag)) {
                if (isNetsim) {
                    continue;
                }
                if ("no speed".equals(trimmed)) {
                    traceMeta(worker, metaTag, "injected 'speed auto' before 'no speed'");
                    sb.append(" speed auto\n");
                } else if ("speed auto".equals(trimmed)) {
                    traceMeta(worker, metaTag, "injected 'no speed' before 'speed auto'");
                    sb.append(" no speed\n");
                }
            }

            // inject-interface-config
            // =======================
            // Inject config from TO transaction after or before this.
            // metas[3] = relative path
            // metas[4] = leaf name line
            // metas[5] = after|before
            // metas[6] = create|delete|any
            // metas[7] = value to ignore in set [OPTIONAL]
            // Example:
            // tailf:meta-data "inject-interface-config" {
            //  tailf:meta-value "speed :: speed :: after create";
            // }
            else if (metaTag.startsWith("inject-interface-config")) {
                boolean before = metas[5].indexOf("before") >= 0;
                lines = trimDuplicateInterfaceMetaTags(worker, lines, i, meta, before);
                if (lines[i].isEmpty()) {
                    continue;
                }
                lines[i] = ""; // Strip meta-data comment
                if ("create".equals(metas[6])
                    && lines[cmd].trim().startsWith("no ")) {
                    continue;
                }
                if ("delete".equals(metas[6])
                    && !lines[cmd].trim().startsWith("no ")) {
                    continue;
                }
                if (isInterfaceDeleted(lines, i, lastif)) {
                    continue; // Interface deleted in same transaction
                }
                if (getInterfaceLine(lines, lastif, " " + metas[4]) >= 0) {
                    continue; // Target config modified in same transaction
                }

                // Get target interface config
                String ifpath = metaPath.substring(0,metaPath.lastIndexOf('}')+1) + "/";
                String path = ifpath + metas[3];
                String val = maapiGetLeafString(worker, mm, toTh, "to", path);
                if (val == null) {
                    continue;
                }
                if (metas.length > 7 && metas[7].equals(val)) {
                    continue; // ignore setting this (e.g. default) value
                }

                // Re-inject interface config
                String insert = " " + metas[4] + " " + val;
                traceMeta(worker, metaTag, "injected '"+insert+"' "+metas[5]+" '"+lines[cmd]+"'");
                if (before) {
                    sb.append(insert + "\n");
                } else {
                    lines = insertCmdAfter(lines, i, cmd, insert);
                    i--;
                }
            }

            // ip-vrf-rd-restore
            // =================
            // Restore config which ip vrf * / rd change deletes. Currently:
            //  ip vrf * / route-target
            else if (metaTag.startsWith("ip-vrf-rd-restore")) {
                if (trimmed.startsWith("no ") || !autoIpVrfRdRestore || isNetsim) {
                    continue;
                }

                // Add rd command first
                sb.append(lines[cmd]+"\n");
                lines[cmd] = "";

                //
                // Restore 'ip vrf * / route-target'
                //
                int changes = 0;
                for (j = cmd; j < lines.length; j++) {
                    // Trim all route-target changes in this transaction
                    if ("exit".equals(lines[j])) {
                        break;
                    }
                    if (lines[j].trim().matches("^(?:no )?route-target .*$")) {
                        lines[j] = "";
                        changes++;
                    }
                }
                try {
                    // Add back all existing route-target's
                    ConfPath cp = new ConfPath(metaPath.replace("/rd", ""));
                    NavuContainer ipvrfRoot = (NavuContainer)new NavuContainer(toContext).getNavuNode(cp);
                    NavuList rt = ipvrfRoot.container(PFX, "route-target").list(PFX, "export");
                    if (rt != null) {
                        for (NavuContainer entry : rt.elements()) {
                            String asn = entry.leaf(PFX, "asn-ip").valueAsString().trim();
                            sb.append(" route-target export "+asn+"\n");
                            changes++;
                        }
                    }
                    rt = ipvrfRoot.container(PFX, "route-target").list(PFX, "import");
                    if (rt != null) {
                        for (NavuContainer entry : rt.elements()) {
                            String asn = entry.leaf(PFX, "asn-ip").valueAsString().trim();
                            sb.append(" route-target import "+asn+"\n");
                            changes++;
                        }
                    }
                    if (changes > 0) {
                        traceMeta(worker, metaTag, configPath+" modified, restored route-target(s)");
                    }
                } catch (Exception e) {
                    traceInfo(worker, "modifyData(ip-vrf-rd-restore) WARNING Exception : "+e.getMessage());
                }
            }

            // if-vrf-restore
            // ==============
            // Restore interface addresses if vrf is modified
            else if ("if-vrf-restore".equals(metaTag)) {
                if (isNetsim || !autoVrfForwardingRestore) {
                    continue;
                }
                String ifpath = metaPath.substring(0,metaPath.lastIndexOf('}')+1);
                boolean v4only = ifpath.contains("ip-vrf/ip");

                // Append vrf command first, prior to restoring addresses
                sb.append(lines[cmd]+"\n");
                lines[cmd] = "";

                // Trim all (subsequent) address changes in this transaction (except ipv6 delete)
                traceVerbose(worker, metaTag+" restoring addresses, lastif = "+lastif);
                for (j = cmd + 1; j < lines.length; j++) {
                    if ("exit".equals(lines[j])) {
                        break;
                    }
                    if (lines[j].matches("^ (?:no )?ip address .*$")) {
                        lines[j] = "";
                    }
                    if (v4only) {
                        continue;
                    }
                    if (lines[j].startsWith(" no ipv6 address")) {
                        sb.append(lines[j]+"\n"); // Note: Not deleted? throw it in to be sure
                    }
                    if (lines[j].matches("^ (?:no )?ipv6 address .*$")) {
                        lines[j] = "";
                    }
                    if (lines[j].matches("^ (no )?ipv6 enable$")) {
                        lines[j] = "";
                    }
                }

                // Add back all current interface addresses
                String config = navuGetIfAddrs(worker, toContext, mm, toTh, ifpath, v4only);
                if (!config.isEmpty()) {
                    traceMeta(worker, metaTag, lines[lastif]+" vrf modified, restored: "+stringQuote(config));
                    sb.append(config);
                }
            }

            // trim-delete-when-empty
            // ======================
            // Strip all sub-leaves when deleting or device will keep the entry
            // metas[3] = strip all after this regexp match
            // Example:
            // tailf:meta-data "trim-delete-when-empty" {
            //  tailf:meta-value " preempt";
            // }
            // tailf:ned-data "." { tailf:transaction to; }
            else if ("trim-delete-when-empty".equals(metaTag)) {
                lines = trimMetaTags(worker, lines, i + 1, meta);
                if (trimmed.startsWith("no ")
                    && !maapiExists(worker, mm, toTh, "to", metaPath)) {
                    Pattern pattern = Pattern.compile(metas[3]);
                    Matcher matcher = pattern.matcher(lines[cmd]);
                    if (matcher.find()) {
                        String transformed = lines[cmd].substring(0, matcher.end(1));
                        traceMeta(worker, metaTag, "deleted '"+transformed+"'");
                        lines[cmd] = transformed;
                    }
                }
            }

            // trim-change
            // ===========
            else if ("trim-change".equals(metaTag)) {
                if (!trimmed.startsWith("no "+metas[3])) {
                    continue;
                }
                if (!nexttrim.equals(meta)) {
                    continue;
                }
                traceMeta(worker, metaTag, "trimmed unrequired '"+trimmed+"'");
                lines[cmd] = "";
                lines[cmd+1] = "";
            }

            // delete-syntax
            // =========================
            // Change delete syntax, three variants:
            // metas[3] = null -> strip delete line
            // metas[3] = <new delete line>
            // metas[3] = <regexp> metas[4] = <replacement>
            else if ("delete-syntax".equals(metaTag)) {
                if (!trimmed.startsWith("no ") || isNetsim) {
                    continue;
                }
                if (metas.length > 4) {
                    lines[cmd] = lines[cmd].replaceFirst(metas[3], metas[4]);
                } else if (metas.length > 3) {
                    lines[cmd] = metas[3]; // Reset delete line
                } else {
                    lines[cmd] = ""; // Strip delete line
                }
            }

            // trim-empty-create
            // ===================
            else if (metaTag.startsWith("trim-empty-create")) {
                if (trimmed.startsWith("no ")) {
                    continue;
                }
                if (lines[cmd].matches("^"+metas[3]+"$")
                    || ("trim-empty-create-trimmed".equals(metaTag) && trimmed.matches("^"+metas[3]+"$"))) {
                    traceMeta(worker, metaTag, "stripped '"+trimmed+"'");
                    lines[cmd] = "";
                }
            }

            // trim-when-list-deleted
            // ===================
            // Strip interface config create line if interface is deleted
            else if ("trim-when-list-deleted".equals(metaTag)) {
                if (!trimmed.startsWith("no ")
                    && !maapiExists(worker, mm, toTh, "to", metaPath.substring(0, metaPath.lastIndexOf('}')+1))) {
                    traceMeta(worker, metaTag, "stripped '"+trimmed+"'");
                    lines[cmd] = "";
                }
            }

            // boolean-delete-with-default
            // ===================
            // delete with 'default' cmd
            else if ("boolean-delete-with-default".equals(metaTag)) {
                if (!trimmed.startsWith("no ")
                    && !maapiExists(worker, mm, toTh, "to", metaPath)) {
                    String transformed = "default "+trimmed;
                    traceMeta(worker, metaTag, "transformed '"+transformed+"'");
                    lines[cmd] = spaces+transformed;
                }
            }

            // delete-with-default
            // ===================
            // delete with 'default' cmd instead of 'no'
            else if ("delete-with-default".equals(metaTag)) {
                if (trimmed.startsWith("no ")
                    && !maapiExists(worker, mm, toTh, "to", metaPath)) {
                    String transformed = trimmed.replace("no ", "default ");
                    traceMeta(worker, metaTag, "transformed '"+transformed+"'");
                    lines[cmd] = spaces+transformed;
                }
            }

            // display-separated
            // =================
            // Inject a single entry in list without sub-leaves
            // Example:
            // tailf:meta-data "display-separated" {
            //  tailf:meta-value '(peer \S+)';
            // }
            else if (metaTag.equals("display-separated")) {
                lines = trimMetaTags(worker, lines, i, meta);
                if (trimmed.startsWith("no ") && maapiExists(worker, mm, toTh, "to", metas[1])) {
                    continue; // Partial delete
                }
                if (!trimmed.startsWith("no ") && maapiExists(worker, mm, fromTh, "from", metas[1])) {
                    continue; // List already created before
                }
                //if (isNetsim) continue;
                Pattern pattern = Pattern.compile(metas[3]);
                Matcher matcher = pattern.matcher(lines[cmd]);
                if (matcher.find()) {
                    String line = lines[cmd].replace(command, matcher.group(1));
                    if (line.equals(lines[cmd])) {
                        continue;
                    }
                    traceMeta(worker, metaTag, "injected '"+line+"'");
                    lines[i] = line;
                    if (trimmed.startsWith("no ") && i+1 == cmd) {
                        traceMeta(worker, metaTag, "reversed delete of '"+line+"'");
                        for (j = cmd; j < lines.length; j++) {
                            //traceVerbose(worker, "LINES[j] = '" + lines[j] +"'");
                            if (lines[j].startsWith(line) || lines[j].isEmpty()) {
                                lines[j-1] = lines[j];
                                lines[j] = line;
                            }
                        }
                    }
                    sb.append(lines[i] + "\n");
                }
            }

            // appnav-controller-change
            // ========================
            // Called when 'service-insertion appnav-controller-group * / appnav-controller *' is modified
            else if ("appnav-controller-change".equals(metaTag)) {
                if (trimmed.startsWith("no ")) {
                    continue;
                }
                String group0 = getMatch(metaPath, "appnav-controller-group\\{(\\S+?)\\}");
                try {
                    String srvpath = metaPath.substring(0, metaPath.indexOf("/appnav-controller-group"))+"/service-context";
                    ConfPath cp = new ConfPath(srvpath);
                    NavuList srvlist = (NavuList)new NavuContainer(toContext).getNavuNode(cp);
                    if (srvlist != null) {
                        for (NavuContainer entry : srvlist.elements()) {
                            String group1 = entry.leaf(PFX, "appnav-controller-group").valueAsString().trim();
                            if (!group0.equals(group1)) {
                                continue;
                            }
                            if (!entry.leaf(PFX, "enable").exists()) {
                                continue;
                            }
                            String name = entry.leaf(PFX, "name").valueAsString().trim();
                            String block = getMatchAll(data, "\nservice-insertion service-context "+name+"(.*?)\n!");
                            if (block != null && block.contains("\n enable")) {
                                continue;
                            }
                            traceMeta(worker, metaTag, "added "+configPath+" -> re-enable 'service-context "+name+"'");
                            sblast.append("service-insertion service-context "+name+"\n");
                            sblast.append(" enable\n");
                            sblast.append("!\n");
                        }
                    }
                } catch (Exception e) {
                    owner.logError(worker, "modifyData(appnav-controller-change) Exception ERROR :: "+e.getMessage(), e);
                }
            }

            // shutdown-container-before-delete
            // ================================
            // Inject shutdown before container deleted
            else if ("shutdown-container-before-delete".equals(metaTag)) {
                if (trimmed.startsWith("no ")) {
                    String container = trimmed.substring(3);
                    String leaf = metas.length == 4 ? metas[3] : "shutdown";
                    traceMeta(worker, metaTag, "injected "+leaf+" in '"+container+"'");
                    sb.append(container + "\n");
                    sb.append(spaces + " " + leaf + "\n");
                    sb.append("exit\n");
                }
            }

            // lower-than
            // higher-than
            // ===========
            // Make sure this value is lower than target value.
            //    NOTE: Requires target to always follow this (i.e. afterwards in YANG file)
            // metas[3] = relative path to target config
            // metas[4] = target default value
            // metas[5] = target 'command/exit' lines (note: white space sensitive)
            else if ("lower-than".equals(metaTag) || "higher-than".equals(metaTag)) {
                if (trimmed.startsWith("no ")) {
                    continue; // deleting this, nothing to reorder
                }
                int target = getLine(lines, i + 1, metas[5]);
                if (target == -1) {
                    continue; // not modifying target, nothing to reorder
                }
                String targetPath = metaPath+"/"+metas[3];
                long targetDefault = Long.parseLong(metas[4]);
                long targetFrom = maapiGetLeafLong(worker, mm, fromTh, "from", targetPath, targetDefault);
                long targetTo = maapiGetLeafLong(worker, mm, toTh, "to", targetPath, targetDefault);
                if ((metaTag.contains("lower") && targetTo > targetFrom)
                    || (metaTag.contains("higher") && targetTo < targetFrom)) {
                    // lower-than and rasing the limit -> move target before this
                    // higher-than and lowering the limit -> move target before this
                    traceMeta(worker, metaTag, "moved up '"+lines[target].trim()+"' before '"+trimmed);
                    sb.append(lines[target]+"\n");
                    lines[target] = "";
                }
            }

            // secret & username clean
            // =======================
            else if ("secret".equals(metaTag)
                     && lines[cmd].startsWith("no username ")
                     && getMatch(lines[cmd], "no username (\\S+)") != null) {
                sb.append(lines[i] + "\n"); // keep meta tag for SECRET code
                // note: lines[cmd] added later
                for (j = cmd + 1; j < lines.length - 1; j++) {
                    // If tags are identical, this may be an identical delete, trim it (NSO bug)
                    if (lines[j].equals(lines[i]) && lines[j+1].equals(lines[cmd])) {
                        traceVerbose(worker, "meta-data secret :: trimmed duplicate delete of "+lines[j+1]);
                        lines[j] = "";
                        lines[j+1] = "";
                        break;
                    }
                }
            }

            // aaa-accounting-mode-format
            // ==========================
            else if ("aaa-accounting-mode-format".equals(metaTag)) {
                if (!aaaAccountingModeFormat || trimmed.startsWith("no ")) {
                    continue;
                }
                Pattern p = Pattern.compile("(aaa accounting .+) (none|start-stop|stop-only)( broadcast)?( group \\S+)?");
                Matcher m = p.matcher(trimmed);
                if (!m.find()) {
                    continue;
                }
                traceMeta(worker, metaTag, "aaa accounting mode format: '"+m.group(1)+"'");
                if (maapiExists(worker, mm, fromTh, "from", metaPath)
                    && sb.indexOf("no "+m.group(1)+"\n") < 0) {
                    sb.append("no "+m.group(1)+"\n");
                }
                sb.append(m.group(1)+"\n");
                sb.append(" action-type "+m.group(2)+"\n");
                if (m.group(3) != null) {
                    sb.append(m.group(3)+"\n");
                }
                if (m.group(4) != null) {
                    sb.append(m.group(4)+"\n");
                }
                sb.append("exit\n");
                lines[cmd] = "";
            }

            // DELETE:
            // =======
            else if ("nedcom-parse-compact-syntax".equals(metaTag)) {
                // Throw away
            }

            // metaTag not handled by this loop -> copy it over
            else {
                sb.append(lines[i] + "\n");
            }
        }
        data = sb.toString() + sblast.toString();


        //
        // MODIFY LINE OLD (old style - can't add lines)
        //
        lines = data.split("\n");
        lastif = -1;
        int toptag = -1;
        StringBuilder sbfirst = new StringBuilder();
        sblast = new StringBuilder();
        for (int i = 0; i < lines.length - 1; i++) {
            if (lines[i].isEmpty()) {
                continue;
            }
            if (lines[i].startsWith("interface ")) {
                lastif = i;
            }
            if (isTopExit(lines[i])) {
                toptag = -1;
            } else if (isTop(lines[i])) {
                toptag = i;
            }

            String meta = lines[i].trim();
            if (!meta.startsWith(METADATA)) {
                continue;
            }
            String[] metas = meta.split(" :: ");
            String metaTag = metas[2];
            String line = lines[i+1];
            String trimmed = line.trim();

            // Strip duplicate meta-data tags
            if (meta.equals(line)) {
                lines[i] = ""; // Trim duplicate meta-data comment
                traceVerbose(worker, "meta-data :: trimmed duplicate tag :: "+meta);
                continue;
            }

            // Warn and ignore if multiple meta-data tags
            if (trimmed.startsWith(METADATA)) {
                traceInfo(worker, "meta-data :: ERROR :: double tag :: "+meta+" :: "+line);
                continue;
            }


            // add-keyword
            // ===========
            // Add 'insert' keyword if 'search' not in command line
            // metas[3] = add keyword
            // metas[4] = positive regexp
            // metas[5] = negative regexp
            // metas[6] = last word [OPTIONAL]
            // Example:
            // add 'log disable' if extended|webtype and not log set
            // tailf:meta-data "add-keyword" {
            //   tailf:meta-value "log disable :: access-list \\S+ \"(extended|webtype) .* :: .* log ::  inactive";
            // }
            if (metaTag.startsWith("add-keyword")) {
                lines[i] = ""; // Strip meta-data comment
                if (!line.matches("^"+metas[4].trim()+"$")) {
                    continue;
                }
                if (line.matches("^"+metas[5].trim()+"$")) {
                    continue;
                }
                if (metas.length > 6 && line.endsWith(metas[6])) {
                    lines[i+1] = line.substring(0,line.length()-metas[6].length()) + " " + metas[3] + metas[6];
                } else {
                    lines[i+1] = line + " " + metas[3];
                }
                traceMeta(worker, metaTag, "new line '"+lines[i+1]+"'");
            }

            // string-remove-quotes
            // ====================
            // metas[3] = regexp, where <STRING> is the string to look at.
            // example:
            // tailf:meta-data "string-remove-quotes" {
            //  tailf:meta-value "route-policy <STRING>";
            // }
            else if (metaTag.startsWith("string-remove-quotes")) {
                lines[i] = ""; // Strip meta-data comment
                String regexp = metas[3].replace("<STRING>", "\\\"(.*)\\\"");
                String replacement = metas[3].replace("<STRING>", "$1");
                String newline = lines[i+1].replaceFirst(regexp, replacement);
                if (!lines[i+1].equals(newline)) {
                    lines[i+1] = newline;
                    traceMeta(worker, metaTag, "unquoted '"+lines[i+1]+"'");
                }
            }

            // range-list-syntax
            // range-list-syntax-mode
            // ======================
            // Compact individual entries to range syntax.
            // Also supports empty mode and list delete.
            // metas[3] = entry to look for, contains <ID> and optional $i tags
            // Example:
            // tailf:meta-data "range-list-syntax" {
            //  tailf:meta-value "spanning-tree vlan <ID> $3 $4";
            // }
            else if (metaTag.startsWith("range-list-syntax")) {
                String[] values = trimmed.split(" +");
                int delete = "no".equals(values[0]) ? 1 : 0; // let first line device if create/delete
                boolean modeSearch = "range-list-syntax-mode".equals(metaTag) && delete == 0;

                // Create line regexp and simple first match (to minimize regexp searches)
                String regexp = metas[3];
                if (delete == 1) {
                    regexp = "no " + regexp;
                }
                String first = regexp.substring(0,regexp.indexOf(" <ID>"));
                regexp = regexp.replace("<ID>", "(\\d+)");
                if (regexp.contains(" $")) {
                    // Replace $i with value from line
                    String[] tokens = regexp.trim().split(" +");
                    for (int x = 0; x < tokens.length; x++) {
                        if (tokens[x].startsWith("$")) {
                            int index = (int)(tokens[x].charAt(1) - '0');
                            if (index + delete < values.length) {
                                regexp = regexp.replace(tokens[x],values[index+delete]);
                            }
                        }
                    }
                    if (regexp.contains(" $")) {
                        traceInfo(worker, metaTag + " :: ignoring '"+line+"'");
                        continue; // unresolved values, ignore non-matching line
                    }
                }

                // Find all matching entries, including this one (to extract first low/high value)
                int low = -1, high = -1;
                traceVerbose(worker, metaTag + " :: searching : mode="+modeSearch+" delete="+delete
                             +" first='"+first+"' regexp='"+regexp+"'");
                for (j = i; j < lines.length - 1; j++) {
                    if (lines[j].indexOf(metaTag) < 0) {
                        continue; // non-matching meta
                    }
                    if (!lines[j+1].trim().startsWith(first)) {
                        continue; // create/delete mismatch
                    }
                    if (modeSearch && delete == 0) {
                        if (j + 2 >= lines.length) {
                            break;
                        }
                        if (!("!".equals(lines[j+2].trim()) || "exit".equals(lines[j+2].trim()))) {
                            break; // entry contains submode config, can't compress this entry
                        }
                    }
                    Pattern pattern = Pattern.compile("^\\s*"+regexp+"$");
                    Matcher matcher = pattern.matcher(lines[j+1]);
                    if (!matcher.find()) {
                        continue; // non-matching line (mismatching $i values)
                    }
                    int index = Integer.parseInt(matcher.group(1));
                    if (low == -1) {
                        // first entry (the command line which will be modified if range found)
                        high = index;
                        low = index;
                    } else if (index - 1 == high) {
                        // interval increased by 1
                        high++;
                        lines[j+1] = ""; // Strip command and optional mode exit
                        if (modeSearch) {
                            lines[j+2] = "";
                        }
                    } else if (index + 1 == low) {
                        // interval decreased by 1
                        low--;
                        lines[j+1] = ""; // Strip command and optional mode exit
                        if (modeSearch) {
                            lines[j+2] = "";
                        }
                    } else {
                        break; // non linear range, end compression [possibly a continue, to find scattered entries?]
                    }
                    lines[j] = ""; // First or expanded range match -> strip meta-data comment
                }

                // Compress single entries to span, minimum 2 entries
                if (high - low > 0) {
                    traceMeta(worker, metaTag, "compressed '"+lines[i+1]+"' to range="+low+"-"+high);
                    lines[i+1] = regexp.replace("(\\d+)", low + "-" + high);
                } else {
                    lines[i] = ""; // Strip meta-data comment
                }
            }

            // diff-move-lower-last
            // ====================
            // If a value is lowered, move the entire config block last
            // metas[3] = to regex
            else if ("diff-move-lower-last".equals(metaTag)) {
                lines[i] = ""; // Strip meta-data comment
                if ((match = getMatch(line, metas[3])) == null) {
                    continue; // failed to extract to-value
                }
                long valueFrom = maapiGetLeafLong(worker, mm, fromTh, "from", metas[1], -1);
                if (valueFrom == -1) {
                    continue; // value did not exist before, keep it first
                }
                long valueTo =  Long.parseLong(match);
                traceVerbose(worker, "meta-data "+metaTag+" :: from="+valueFrom+" to="+valueTo);

                // extract block
                String block = lines[toptag];
                StringBuilder sbmove =  new StringBuilder();
                for (j = toptag; j < lines.length; j++) {
                    if (lines[j].isEmpty()) {
                        continue;
                    }
                    String moveline = lines[j];
                    lines[j] = "";
                    sbmove.append(moveline+"\n");
                    if (isTopExit(moveline)) {
                        break;
                    }
                }

                if (valueFrom < valueTo && !trimmed.startsWith("no ")) {
                    traceMeta(worker, metaTag, "moved '"+block+"' first");
                    sbfirst.append(sbmove); // value raised, move first
                } else {
                    traceMeta(worker, metaTag, "moved '"+block+"' last");
                    sblast.append(sbmove); // value lowered, move last
                }
            }

            // diff-interface-move
            // ===================
            //    A :: after|before :: B
            // Move line A before or after line B within interface boundaries
            // metas[3] = line A to move (regexp)
            // metas[4] = after|before
            // metas[5] = line B to stay
            // metas[6] = device regexp [OPTIONAL] (if no match, toggle move direction)
            // example:
            // tailf:meta-data "diff-interface-move-1" {
            //  tailf:meta-value "no ip route-cache :: before :: switchport";
            // }
            else if (metaTag.startsWith("diff-interface-move")) {
                boolean before = "before".equals(metas[4]);
                if (metas.length > 6 && !model.matches(".*"+metas[6]+".*")) {
                    traceVerbose(worker,"meta-data :: "+metaTag+" :: model != "+metas[6]+" -> toggled move direction");
                    before = !before;
                }
                lines = trimDuplicateInterfaceMetaTags(worker, lines, i, meta, before); // if before, keep first occurrence
                if (lines[i].isEmpty()) {
                    continue;
                }
                lines[i] = ""; // Strip meta-data comment
                for (;;) {
                    int move = -1, stay = -1, exit = -1;

                    // First find stay and exit (note: stay may have moved since last loop)
                    for (j = lastif; j < lines.length; j++) {
                        String command = lines[j].trim();
                        if (command.matches("^"+metas[5].trim()+"$")) {
                            stay = j;
                        } else if ("exit".equals(lines[j])) {
                            exit = j;
                            break;
                        }
                    }
                    if (stay == -1 || exit == -1) {
                        break;
                    }

                    // Then find best move (depends on after or before)
                    if (before) {
                        for (j = stay + 1; j < exit; j++) {
                            String command = lines[j].trim();
                            if (command.matches("^"+metas[3].trim()+"$")) {
                                move = j;
                                break;
                            }
                        }
                    } else {
                        for (j = lastif + 1; j < stay; j++) {
                            String command = lines[j].trim();
                            if (command.matches("^"+metas[3].trim()+"$")) {
                                move = j;
                                break;
                            }
                        }
                    }
                    if (move == -1) {
                        break;
                    }

                    // Move the 'move' entry by shifting lines
                    if (before == true && move > stay) {
                        traceMeta(worker, metaTag, "moved '"+lines[move]+"' before '"+lines[stay]+"'");
                        String moveLine = lines[move];
                        for (j = move; j > i; j--) {
                            lines[j] = lines[j-1];
                        }
                        lines[i] = moveLine;
                    }
                    else if (!before && move < stay) {
                        traceMeta(worker, metaTag, "moved '"+lines[move]+"' after '"+lines[stay]+"'");
                        String moveLine = lines[move];
                        for (j = move; j < stay; j++) {
                            lines[j] = lines[j+1];
                        }
                        lines[stay] = moveLine;
                        i--; // must subtract i in order to look at next meta tag
                    }
                }
            }

            // shutdown-container-before-change
            // ===================
            // Inject shutdown and no shutdown around all changes inside container/list
            // metas[3] = ID (used to find exit)
            // Example:
            // tailf:cli-run-template-enter "pm-agent\n ! meta-data :: $(.ipath)
            //                               :: shutdown-container-before-change :: pm-agent\n";
            // tailf:cli-exit-command "! exit-meta-data-pm-agent";
            else if (metaTag.startsWith("shutdown-container-before-change")) {
                String exitTag = "! exit-meta-data-"+metas[3];

                // Empty container/list (no modified commands in it)
                if (lines[i+1].trim().equals(exitTag)) {
                    lines[i] = "";   // Strip meta-data comment
                    lines[i+1] = ""; // Strip meta-data-exit comment
                    continue;
                }

                // Deleted entry, do not insert shutdown
                if (lines[i-1].trim().startsWith("no ")) {
                    lines[i] = "";   // Strip meta-data comment
                    continue;
                }

                // Entry with at least one modified sub-entry
                traceMeta(worker, metaTag, "injected shutdown in " + lines[i-1]);
                lines[i] = lines[i].replace(meta, "shutdown");

                // Clean exit (trim extra shutdown and insert no shutdown)
                for (j = i + 1; j < lines.length; j++) {
                    if (lines[j].trim().equals(exitTag)) {
                        if ("shutdown".equals(lines[j-1].trim()) || "no shutdown".equals(lines[j-1].trim())) {
                            lines[j-1] = ""; // strip native [no ]shutdown
                        }
                        if (maapiExists(worker, mm, toTh, "to", metas[1])
                            && !maapiExists(worker, mm, toTh, "to", metas[1]+"/shutdown")) {
                            lines[j] = lines[j].replace(exitTag, "no shutdown");
                        } else {
                            lines[j] = ""; // shutdown already injected first
                        }
                        break;
                    }
                }
            }

            // inactivate-container-before-change
            // ==================================
            // Inject "no activate" and "activate" around all changes inside container/list
            // metas[3] = ID (used to find exit)
            // Example:
            // tailf:cli-run-template-enter "pm-agent\n ! meta-data :: $(.ipath)
            //                               :: inactivate-container-before-change :: virtual-service\n";
            // tailf:cli-exit-command "! exit-meta-data-virtual-service";
            else if (metaTag.startsWith("inactivate-container-before-change")) {
                int tag;

                // Find exit tag and strip tags
                lines[i] = "";   // Strip meta-data comment
                for (tag = i + 1; tag < lines.length; tag++) {
                    if (lines[tag].trim().equals("! exit-meta-data-"+metas[3])) {
                        lines[tag] = "exit"; // replace exit-tag
                        break;
                    }
                }

                // Empty container/list (no modified commands in it)
                if (tag == i + 1 || tag == lines.length) {
                    continue;
                }
                // Did not exist or was not activated, no need to inject 'no activate'
                if (!maapiExists(worker, mm, fromTh, "from", metas[1]+"/activate")) {
                    continue;
                }

                // Previously activated entry with at least one modified sub-entry
                traceMeta(worker, metaTag, "injected 'no activate' in " + lines[i-1]);
                lines[i] = " no activate";

                // Clean exit (trim extra [no ]activate and inject activate)
                if ("no activate".equals(lines[tag-1].trim())) {
                    lines[tag-1] = ""; // strip NSO 'no activate'
                } else if ("activate".equals(lines[tag-1].trim())) {
                    // Already got activate
                }
                else if (maapiExists(worker, mm, toTh, "to", metas[1]+"/activate")) {
                    lines[tag] = " activate"; // re-activate
                }
            }
        }

        // Make single string again
        sb = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            if (lines[i] != null && !lines[i].isEmpty()) {
                sb.append(lines[i]+"\n");
            }
        }

        data = "\n" + sbfirst.toString() + sb.toString() + sblast.toString();
        //traceVerbose(worker, "AFTER_META:\n"+data);
        return data;
    }


    /*
     * Write info in NED trace
     *
     * @param info - log string
     */
    private void traceInfo(NedWorker worker, String info) {
        owner.traceInfo(worker, info);
    }
    private void traceMeta(NedWorker worker, String metaTag, String info) {
        traceInfo(worker, "meta-data "+metaTag+" :: transformed => "+info);
    }

    /*
     * Write info in NED trace if verbose output
     *
     * @param info - log string
     */
    private void traceVerbose(NedWorker worker, String info) {
        owner.traceVerbose(worker, info);
    }


    private String getMatchAll(String text, String regexp) {
        Pattern pattern = Pattern.compile(regexp, Pattern.DOTALL);
        Matcher matcher = pattern.matcher(text);
        if (!matcher.find()) {
            return null;
        }
        return matcher.group(1);
    }


    private int getCmd(String[] lines, int i) {
        for (int cmd = i; cmd < lines.length; cmd++) {
            String trimmed = lines[cmd].trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (trimmed.startsWith(METADATA)) {
                continue;
            }
            return cmd;
        }
        return -1;
    }

    private String[] insertCmdAfter(String[] lines, int i, int cmd, String insert) {
        for (int n = i; n < cmd; n++) {
            lines[n] = lines[n+1];
        }
        lines[cmd] = insert;
        return lines;
    }

    /*
     * Trim cmd and all meta-data tags that goes with it
     */
    private String[] trimCmd(String[] lines, int i, int cmd) {
        for (int n = i; n <= cmd; n++) {
            lines[n] = "";
        }
        return lines;
    }

    /*
     * Trim all identical tags (including this one)
     */
    private String[] trimMetaTags(NedWorker worker, String[] lines, int i, String meta) {
        for (int n = i; n < lines.length; n++) {
            if (lines[n].trim().equals(meta)) {
                traceVerbose(worker, "meta-data :: trimmed tag["+n+"]: " + meta);
                lines[n] = "";
            }
        }
        return lines;
    }

    /*
     * Trim all duplicate interface MetaTags except the last or first one.
     */
    private String[] trimDuplicateInterfaceMetaTags(NedWorker worker, String[] lines, int i, String meta, boolean keepfirst) {
        int n, last = -1;
        int count = -1;
        for (n = i; n < lines.length; n++) {
            if ("exit".equals(lines[n].trim())) {
                break;
            }
            if (lines[n].trim().equals(meta)) {
                lines[n] = "";
                last = n;
                count++;
            }
        }
        if (keepfirst) {
            lines[i] = meta;
        } else {
            lines[last] = meta;
        }
        if (count > 0) {
            traceVerbose(worker, "meta-data :: trimmed "+count+" tag(s): " + meta);
        }
        return lines;
    }

    private String[] trimMetaTagsAndCmd(String[] lines, int i, String meta) {
        int j;
        for (int n = i; n < lines.length - 1; n++) {
            if (lines[n].trim().equals(meta)) {
                lines[n] = ""; // Trim this meta-data tag
                for (j = n + 1; j < lines.length; j++) {
                    if (lines[j].trim().startsWith("! meta-data :: /ncs:devices/device{")) {
                        // Trim other meta-data tag
                        lines[j] = "";
                        continue;
                    }
                    // Trim this command
                    lines[j] = "";
                    break;
                }
            }
        }
        return lines;
    }

    /*
     * Remove last duplicate "no switchport" caused by "show-no" (NCS BUG)
     * Strip all ip address additions before vrf change
     */
    private String[] ncsPatchInterface(NedWorker worker, String[] lines, int lastif, boolean isNetsim) {
        int no_switchport = -1;
        for (int j = lastif + 1; j < lines.length; j++) {
            if ("exit".equals(lines[j])) {
                break;
            }
            String trimmed = lines[j].trim();
            if (!isNetsim && trimmed.matches("^(no )?(ip )?vrf forwarding \\S+$")) {
                for (int n = j - 1; n > lastif; n--) {
                    if (lines[n].startsWith(" ip address ") || lines[n].startsWith(" ipv6 address ")) {
                        lines[n] = ""; // trim previous ip address additions
                    }
                }
            }
            if ("no switchport".equals(trimmed)) {
                if (no_switchport == -1) {
                    no_switchport = j;
                } else {
                    // Trim cmd and it's meta tag
                    traceInfo(worker, "NCSPATCH: removing duplicate 'no switchport' (NCS bug)");
                    lines[j] = "";
                    for (int n = j - 1; n > lastif; n--) {
                        if (!lines[n].trim().startsWith("! meta-data :: /ncs:devices/device{")) {
                            break;
                        }
                        lines[n] = "";
                    }
                }
            }
        }
        return lines;
    }

    private String duplicateToX(String lprefix, String values, String postfix, int x, String sep) {
        String[] val = values.split(sep+"+");
        if (val.length <= x) {
            return lprefix + " " + values + postfix + "\n";
        }
        return duplicateToX2(lprefix, val, postfix, x, sep);
    }

    private String duplicateToX2(String lprefix, String[] val, String postfix, int x, String sep) {
        String buf = "";
        for (int n = 0; n < val.length; n = n + x) {
            String line = "";
            for (int j = n; (j < n + x) && (j < val.length); j++) {
                if (j != n) {
                    line += sep;
                }
                line += val[j];
            }
            buf = buf + lprefix + " " + line + postfix + "\n";
        }
        return buf;
    }

    private int NindexOf(String text, String str, int num) {
        int n, i = 0;
        for (n = 0; n < num - 1; n++) {
            i = text.indexOf(str, i);
            if (i < 0) {
                return -1;
            }
            i++;
        }
        return text.indexOf(str, i);
    }

    private boolean isTop(String line) {
        return Character.isLetter(line.charAt(0));
    }

    private boolean isTopExit(String line) {
        if ("!".equals(line)) {
            return true;
        }
        if ("exit".equals(line)) {
            return true;
        }
        return false;
    }

    private int getInterfaceExit(String[] lines, int i) {
        for (; i < lines.length; i++) {
            if (isTopExit(lines[i])) {
                return i;
            }
        }
        return -1;
    }

    private boolean isInterfaceDeleted(String[] lines, int i, int lastif) {
        int exit = getInterfaceExit(lines, i);
        if (exit == -1 || exit + 1 == lines.length) {
            return false;
        }
        if (lines[exit+1].trim().equals("no "+lines[lastif].trim())) {
            return true;
        }
        return false;
    }

    /*
     * getInterfaceLine
     */
    private int getInterfaceLine(String[] lines, int lastif, String line) {
        if (lastif < 0) {
            return -1;
        }
        String noline = line.replace(line.trim(), "no "+line.trim());
        for (int i = lastif; i < lines.length; i++) {
            if (isTopExit(lines[i])) {
                return -1;
            }
            if (lines[i].startsWith(line)) {
                return i;
            }
            if (lines[i].startsWith(noline)) {
                return i;
            }
        }
        return -1;
    }

    /*
     * getLine - look up line forward
     */
    private int getLine(String[] lines, int i, String lookup) {
        String[] tokens = lookup.split("/");
        String line = tokens[0];
        String noline = line.replace(line.trim(), "no "+line.trim());
        for (; i < lines.length; i++) {
            if (lines[i].startsWith(line)) {
                return i;
            }
            if (lines[i].startsWith(noline)) {
                return i;
            }
            if (lines[i].startsWith(tokens[1])) {
                return -1;
            }
        }
        return -1;
    }

    /*
     * maapiExists
     */
    private boolean maapiExists(NedWorker worker, Maapi mm, int th, String dir, String path)
        throws NedException {
        try {
            if (mm.exists(th, path)) {
                traceVerbose(worker, "maapiExists("+dir+","+path+") = true");
                return true;
            }
        } catch (Exception e) {
            throw new NedException("maapiExists("+dir+","+path+") - ERROR :: " + e.getMessage(), e);
        }
        traceVerbose(worker, "maapiExists("+dir+","+path+") = false");
        return false;
    }

    /*
     * maapiGetLeafString
     */
    private String maapiGetLeafString(NedWorker worker, Maapi mm, int th, String dir, String path) {
        // Trim to absolute path
        int up;
        while ((up = path.indexOf("/../")) > 0) {
            int slash = path.lastIndexOf('/', up-1);
            path = path.substring(0, slash) + path.substring(up + 3);
        }
        // Get leaf
        try {
            if (mm.exists(th, path)) {
                String val = ConfValue.getStringByValue(path, mm.getElem(th, path));
                traceVerbose(worker, "maapiGetLeafString("+dir+","+path+") = "+val);
                return val;
            }
            traceVerbose(worker, "maapiGetLeafString("+dir+","+path+") exists() = false");
        } catch (Exception e) {
            // Ignore Exception
            traceVerbose(worker, "maapiGetLeafString("+dir+","+path+") Exception: "+e.getMessage());
        }
        return null;
    }

    /*
     * maapiGetLeafLong
     */
    private long maapiGetLeafLong(NedWorker worker, Maapi mm, int th, String dir, String path, long defaultValue) {
        long val = defaultValue;
        String string = maapiGetLeafString(worker, mm, th, dir, path);
        if (string != null) {
            val = Long.parseLong(string);
        }
        traceVerbose(worker, "maapiGetLeafLong("+dir+","+path+") = "+val);
        return val;
    }


    /**
     * Get addresses on interface
     * @param
     * @return
     */
    private String navuGetIfAddrs(NedWorker worker,
                                  NavuContext context, Maapi mm, int th,
                                  String ifpath, boolean v4only) {

        //
        // Init NAVU interface container ifroot
        //
        NavuContainer ifroot;
        try {
            ConfPath cp = new ConfPath(ifpath);
            ifroot = (NavuContainer)new NavuContainer(context).getNavuNode(cp);
            if (ifroot == null || !ifroot.exists()) {
                return "";
            }
        } catch (Exception ignore) {
            return ""; // interface deleted
        }

        //
        // interface * / ipv4 address
        //
        StringBuilder sb = new StringBuilder();
        try {
            // interface * / ip address
            String ip = maapiGetLeafString(worker, mm, th, "to", ifpath+"/ip/address/primary/address");
            if (ip != null) {
                String mask = maapiGetLeafString(worker, mm, th, "to", ifpath+"/ip/address/primary/mask");
                sb.append(" ip address "+ip+" "+mask+"\n");
            }
            /*
            NavuContainer ip = ifroot.container(PFX,"ip").container(PFX,"address").container(PFX,"primary");
            if (ip != null && ip.exists()) {
                String address = ip.leaf(PFX,"address").valueAsString().trim();
                String mask = ip.leaf(PFX,"mask").valueAsString().trim();
                sb.append(" ip address "+address+" "+mask+"\n");
            }
            */

            // interface * / ip address * secondary
            NavuList list = ifroot.container(PFX,"ip").container(PFX,"address").list(PFX,"secondary");
            if (list != null && !list.isEmpty()) {
                for (NavuContainer addr : list.elements()) {
                    String address = addr.leaf(PFX,"address").valueAsString().trim();
                    String mask = addr.leaf(PFX,"mask").valueAsString().trim();
                    sb.append(" ip address "+address+" "+mask+" secondary\n");
                }
            }

            // interface * / ip address dhcp
            NavuContainer dhcp = ifroot.container(PFX,"ip").container(PFX,"address").container(PFX,"dhcp");
            if (dhcp != null && dhcp.exists()) {
                String opt = "";
                NavuLeaf leaf = dhcp.leaf(PFX,"hostname");
                if (leaf.exists()) {
                    String hostname = leaf.valueAsString().trim();
                    opt += " hostname " + hostname;
                }
                sb.append(" ip address dhcp"+opt+"\n");
            }
        } catch (Exception e) {
            owner.logError(worker, "navuGetIfAddrs("+ifpath+") Exception ERROR: ", e);
        }
        if (v4only) {
            // interface * / ip vrf forwarding - only affects ipv4, return before ipv6
            return sb.toString();
        }

        //
        // interface * / ipv6 address
        //
        try {
            // interface * / ipv6 enable
            if (maapiExists(worker, mm, th, "to", ifpath+"/ipv6/enable")) {
                sb.append(" ipv6 enable\n");
            }

            // interface * / ipv6 address autoconfig
            if (maapiExists(worker, mm, th, "to", ifpath+"/ipv6/address/autoconfig")) {
                sb.append(" ipv6 address autoconfig\n");
            }

            // interface * / ipv6 address dhcp
            if (maapiExists(worker, mm, th, "to", ifpath+"/ipv6/address/dhcp")) {
                if (maapiExists(worker, mm, th, "to", ifpath+"/ipv6/address/dhcp/rapid-commit")) {
                    sb.append(" ipv6 address dhcp rapid-commit\n");
                } else {
                    sb.append(" ipv6 address dhcp\n");
                }
            }

            // interface * / ipv6 address *
            NavuList list = ifroot.container(PFX,"ipv6").container(PFX,"address").list(PFX,"prefix-list");
            if (list != null && !list.isEmpty()) {
                for (NavuContainer addr : list.elements()) {
                    String prefix = addr.leaf(PFX,"prefix").valueAsString().trim();
                    String opt = "";
                    if (addr.leaf(PFX,"eui-64").exists()) {
                        opt += " eiu-64";
                    }
                    if (addr.leaf(PFX,"anycast").exists()) {
                        opt += " anycast";
                    }
                    if (addr.leaf(PFX,"link-local").exists()) {
                        opt += " link-local";
                    }
                    sb.append(" ipv6 address "+prefix+opt+"\n");
                }
            }
        } catch (Exception e) {
            owner.logError(worker, "navuGetIfAddrs("+ifpath+") Exception ERROR: ", e);
        }

        // Done
        return sb.toString();
    }

}
