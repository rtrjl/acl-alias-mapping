package com.tailf.packages.ned.ios;

import com.tailf.packages.ned.nedcom.NedComCliBase;
import static com.tailf.packages.ned.nedcom.NedString.getMatches;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.ArrayList;
import java.util.HashMap;

import com.tailf.ned.NedWorker;
import com.tailf.ned.NedException;

import com.tailf.conf.ConfPath;
import com.tailf.maapi.Maapi;

import com.tailf.navu.NavuContext;
import com.tailf.navu.NavuContainer;
import com.tailf.navu.NavuList;

/**
 * NedAcl
 *
 * IOS NOTES:
 * remark rule statements can remain when access-list is deleted and created again
 * remark rule statements are not given a sequence number and can't be resequenced
 * => remark statements can't be supported with this method
 *
 * ipv6 access-list resequence does not exist
 * => only ipv4 is supported
 *
 * ip access-list standard always insert entries last, regardless of lower seqno
 * => resequence only works for "ip access-list extended <name>"
 */
@SuppressWarnings("deprecation")
public class NedAcl {

    private static final int SEQ = 1000;

    /*
     * Local data
     */
    private NedComCliBase owner;
    private String configRoot;

    /**
     * Constructor
     */
    NedAcl(NedComCliBase owner) {
        this.owner = owner;
        this.configRoot = "/ncs:devices/ncs:device{"+owner.device_id+"}/config/ios:";
    }


    /**
     *
     * @param
     * @return
     * @throws NedException
     */
    public String modify(NedWorker worker, String data, int fromTh, int toTh, Maapi mm)
        throws NedException {

        String name = null;
        String[] lines = data.split("\n");
        StringBuilder sb = new StringBuilder();
        HashMap<String, ArrayList<String[]>> aclCache = new HashMap<>();
        ArrayList<String[]> aclList = null;
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];

            // Non 'ip access-list extended entry', add and continue
            if (!line.startsWith("ip access-list extended ")) {
                sb.append(line+"\n");
                continue;
            }

            // Cache previous aclList with name as key
            if (aclList != null && name != null) {
                aclCache.put(name, aclList);
            }

            // ip access-list entry, get current 'from' list from CDB using NAVU
            Pattern p = Pattern.compile("ip access-list extended (\\S+)");
            Matcher m = p.matcher(line);
            if (!m.find()) {
                throw new NedException("ACL: malformed line: "+line);
            }
            name = m.group(1);
            String path = this.configRoot + "ip/access-list/resequence/extended{"+name+"}";

            // Retrieve access-list from CDB or cache (hashmap)
            if ((aclList = aclCache.get(name)) != null) {
                traceVerbose(worker, "ACL: Retrieved access-list "+name+" from hashmap");
            } else {
                traceVerbose(worker, "ACL: Reading access-list "+name+" from CDB");
                aclList = listGet(worker, path, fromTh, mm);
            }

            //
            // New access-list
            //
            if (aclList == null || aclList.size() == 0) {
                traceVerbose(worker, "ACL: creating access-list "+name);
                for (; n < lines.length; n++) {
                    line = lines[n];
                    if (line.startsWith(" ! move")) {
                        throw new NedException("ACL: malformed obu: "+line);
                    }
                    if (line.startsWith(" ! insert")) {
                        continue;  // trim: NSO adds unnecessary ! insert instructions
                    }

                    traceVerbose(worker, "ACL: adding '"+line+"'");
                    ruleAdd(line, sb);

                    // End of access-list
                    if (isExit(line)) {
                        break;
                    }
                }
                continue;
            }

            //
            // NETSIM - Resetting access-list
            //
            if (owner.isNetsim()) {
                // Delete access-list and add back entries
                sb.append("no "+line+"\n");

                // Get current (to-transaction) access-list
                aclList = listGet(worker, path, toTh, mm);
                if (aclList == null) {
                    traceVerbose(worker, "ACL: deleting access-list "+name);
                    continue;
                }

                // Add back remaining entries
                traceVerbose(worker, "ACL: resetting access-list "+name+" [size="+aclList.size()+"]");
                listToTrace(worker, aclList, "to");
                sb.append(line+"\n");
                for (int i = 0; i < aclList.size(); i++) {
                    String[] entry = aclList.get(i);
                    sb.append(" "+entry[1]+"\n");
                }

                // Flush all ACL command(s) from NSO
                for (n = n + 1; n < lines.length; n++) {
                    if (isExit(lines[n])) {
                        break;
                    }
                }
                continue;
            }

            //
            // Modifying existing access-list, apply changes
            //
            traceVerbose(worker, "ACL: modifying access-list "+name+" [size="+aclList.size()+"]");
            listToTrace(worker, aclList, "from");

            // Add access-list header
            ArrayList<String> cmdList = new ArrayList<>();
            cmdAdd(line, cmdList);

            // Apply access-list changes
            int index = -1;
            for (n = n + 1; n < lines.length; n++) {
                line = lines[n];
                String trimmed = line.trim();
                if (isExit(line)) {
                    break;
                }

                // ! insert after|before <line>
                // ! move after|before <line>
                if (trimmed.startsWith("! ")) {
                    String nextline = (n + 1 < lines.length) ? lines[n+1] : "";
                    n = n + 1;
                    String[] group = getMatches(line, "! (move|insert) (after|before) (.*)");
                    if (group == null || Integer.parseInt(group[0]) != 3) {
                        throw new NedException("ACL: malformed obu: "+nextline);
                    }
                    String rule = nextline.trim();

                    // If moving a rule, first remove it from ACL cache and generate no-command
                    if (group[1].equals("move")) {
                        traceVerbose(worker, "ACL: moving '"+rule+"' "+group[2]+" '"+group[3]+"'");
                        index = listIndexOf(aclList, rule);
                        if (index == -1) {
                            throw new NedException("ACL: finding rule to move: '"+rule+"'");
                        }
                        aclList.remove(index);
                        cmdAdd(" no "+rule, cmdList);
                    } else {
                        traceVerbose(worker, "ACL: inserting '"+rule+"' "+group[2]+" '"+group[3]+"'");
                    }

                    // WORKAROUND for NSO sending 'insert before' on the following (yet non-existing) rule
                    if (aclList.isEmpty()) {
                        traceInfo(worker, "ACL: WARNING superfluous obu '"+trimmed+"', inserting '"+rule+"' last [NCSPATCH]");
                        listAdd(aclList, index, rule);
                        continue;
                    }

                    // Now look up where to insert it
                    index = listIndexOf(aclList, group[3]);
                    if (index == -1) {
                        throw new NedException("ACL: finding rule for: '"+line+"'");
                    }
                    if (group[2].contains("after")) {
                        index++;
                    }

                    // Add entry the internal ACL cache
                    listAdd(aclList, index, rule);
                    index = -1; // Reset index to add next entry last
                }

                // no <rule>
                else if (trimmed.startsWith("no ")) {
                    String rule = trimmed.substring(3);
                    index = listIndexOf(aclList, rule);
                    if (index == -1) {
                        throw new NedException("ACL: finding '"+rule+"' to delete");
                    }
                    traceVerbose(worker, "ACL: deleting '"+rule+"'");
                    aclList.remove(index);
                    cmdAdd(" no "+rule, cmdList);
                    index = -1; // Only nextline is inserted/moved, next one added last
                }

                // <rule>
                else {
                    String rule = trimmed;
                    int current = listIndexOf(aclList, rule);
                    if (current != -1 && ruleEquals(aclList, current, rule)) {
                        traceVerbose(worker, "ACL: WARNING: ignoring duplicate '"+rule+"' (index="+index+")");
                        index = current + 1;
                        continue;
                    } else if (index != -1) {
                        traceVerbose(worker, "ACL: adding '"+rule+"' at index="+index);
                        listAdd(aclList, index, rule);
                        index++;
                    } else {
                        traceVerbose(worker, "ACL: adding '"+line+"'");
                        listAdd(aclList, -1, rule);
                    }
                }
            }
            listToTrace(worker, aclList, "to");

            // Insert new entries in command list
            listToCmd(aclList, cmdList);
            if (cmdList.size() == 1) {
                // NSO bug [TRAC 16770]. Change lost it's !move statement
                // throw new NedException("ACL: malformed access-list change on "+name);
            }

            // Add exit and resequence (if list > 0)
            cmdAdd("exit", cmdList);
            if (aclList.size() > 0) {
                cmdAddFirst("ip access-list resequence "+name+" "+SEQ+" "+SEQ, cmdList);
                cmdAdd("ip access-list resequence "+name+" 10 10", cmdList);
            }
            cmdToTrace(worker, cmdList);

            // Copy over to stringbuilder
            cmdToStringBuilder(cmdList, sb);
        }
        data = sb.toString();

        return data;
    }


    /**
     *
     * @param
     * @return
     */
    private boolean isExit(String line) {
        if (line.equals("exit")) {
            return true;
        }
        if (line.equals("!")) {
            return true;
        }
        return false;
    }


    /**
     *
     * @param
     */
    private void traceVerbose(NedWorker worker, String info) {
        owner.traceVerbose(worker, info);
    }


    /**
     *
     * @param
     */
    private void traceInfo(NedWorker worker, String info) {
        owner.traceInfo(worker, info);
    }


    /**
     * Retrieve access-list from CDB
     * @param
     * @return
     * @throws NedException
     */
    private ArrayList<String[]> listGet(NedWorker worker, String path, int th, Maapi mm)
        throws NedException {

        // Get list root
        NavuContext context = null;
        try {
            NavuContainer root;
            try {
                context = new NavuContext(mm, th);
                ConfPath cp = new ConfPath(path);
                root = (NavuContainer)new NavuContainer(context).getNavuNode(cp);
                if (root == null || !root.exists()) {
                    traceVerbose(worker, "access-list "+path+" not found");
                    return null;
                }
            } catch (Exception e) {
                traceVerbose(worker, "access-list "+path+" does not exist");
                return null;
            }

            // Get Rules
            try {
                ArrayList<String[]> aclList = new ArrayList<>();
                NavuList list = root.list("ios", "rule-list");
                if (list == null || list.isEmpty()) {
                    traceInfo(worker, "access-list "+path+" is empty");
                    return aclList;
                }

                int index = SEQ;
                for (NavuContainer rule : list.elements()) {
                    String[] entry = new String[2];
                    entry[0] = Integer.toString(index);
                    entry[1] = rule.leaf("ios", "rule").valueAsString().trim();
                    aclList.add(entry);
                    index += SEQ;
                }
                return aclList;

            } catch (Exception e) {
                throw new NedException("ACL: listGet: "+e.getMessage());
            }
        } finally {
            if (context != null) {
                context.removeCdbSessions();
            }
        }
    }


    /**
     *
     * @param
     */
    private void listAdd(ArrayList<String[]> aclList, int index, String rule) {
        String[] entry = new String[2];
        entry[0] = null;
        entry[1] = rule;
        if (index == -1) {
            aclList.add(entry);
        } else {
            aclList.add(index, entry);
        }
    }


    /**
     *
     * @param
     */
    private void listToTrace(NedWorker worker, ArrayList<String[]> aclList, String pfx) {
        for (int n = 0; n < aclList.size(); n++) {
            String[] entry = aclList.get(n);
            String seq = entry[0] != null ? entry[0] : "x";
            traceVerbose(worker, " "+pfx+"ACL: ["+seq+"] "+entry[1]);
        }
    }


    /**
     * Find access-list rule, look up backwards to optimize for insert after
     * @param
     * @return
     */
    private int listIndexOf(ArrayList<String[]> aclList, String rule) {
        String key = rule.trim();
        for (int n = aclList.size() - 1; n >= 0; n--) {
            String[] entry = aclList.get(n);
            String keyx = entry[1];
            if (key.equals(keyx)) {
                return n;
            }
        }
        return -1;
    }


    /**
     *
     * @param
     */
    private void listToCmd(ArrayList<String[]> aclList, ArrayList<String> cmdList) {
        int seqno = 0;
        for (int n = 0; n < aclList.size(); n++) {
            String[] entry = aclList.get(n);
            if (entry[0] != null) {
                seqno = Integer.parseInt(entry[0]);
                continue;
            }
            seqno++;
            cmdAdd(" "+seqno+" "+entry[1], cmdList);
        }
    }


    /**
     *
     * @param
     * @return
     */
    private boolean ruleEquals(ArrayList<String[]> aclList, int index, String rule) {
        String[] entry = aclList.get(index);
        String rulex = entry[1];
        return rulex.equals(rule);
    }


    /**
     *
     * @param
     */
    private void ruleAdd(String rule, StringBuilder sb) {
        sb.append(rule+"\n");
    }


    /**
     *
     * @param
     */
    private void cmdAdd(String line, ArrayList<String> cmdList) {
        cmdList.add(line);
    }
    private void cmdAddFirst(String line, ArrayList<String> cmdList) {
        cmdList.add(0, line);
    }


    /**
     *
     * @param
     */
    private void cmdToTrace(NedWorker worker, ArrayList<String> cmdList) {
        for (int n = 0; n < cmdList.size(); n++) {
            traceVerbose(worker, "ACL: cmd ["+n+"] = "+cmdList.get(n));
        }
    }


    /**
     *
     * @param
     */
    private void cmdToStringBuilder(ArrayList<String> cmdList, StringBuilder sb) {
        for (int n = 0; n < cmdList.size(); n++) {
            sb.append(cmdList.get(n)+"\n");
        }
    }

}
