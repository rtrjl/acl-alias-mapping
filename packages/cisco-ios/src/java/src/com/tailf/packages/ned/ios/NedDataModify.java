package com.tailf.packages.ned.ios;

import com.tailf.packages.ned.nedcom.NedComCliBase;
import static com.tailf.packages.ned.nedcom.NedString.getMatch;
import static com.tailf.packages.ned.nedcom.NedString.stringQuote;

import java.util.EnumSet;

import com.tailf.ned.NedWorker;
import com.tailf.ned.NedException;

import com.tailf.maapi.Maapi;
import com.tailf.maapi.MaapiInputStream;
import com.tailf.maapi.MaapiConfigFlag;

/**
 * Utility class for cisco-ios, e.g. unlock data etc
 *
 * @author lbang
 * @version 20170302
 */

@SuppressWarnings("deprecation")
public class NedDataModify {

    /*
     * Local data
     */
    private NedComCliBase owner;
    private String configRoot;


    /**
     * Constructor
     */
    NedDataModify(NedComCliBase owner) {
        this.owner = owner;
        this.configRoot = "/ncs:devices/ncs:device{"+owner.device_id+"}/config/ios:";
    }


    /**
     * Modify locked config
     * @param
     * @return
     * @throws NedException
     */
    public String modifyLocked(NedWorker worker, String data, int toTh, int fromTh, Maapi mm) throws NedException {
        String id;

        String toptag = "";
        String[] lines = data.split("\n");
        StringBuilder sb = new StringBuilder();
        StringBuilder last = new StringBuilder();
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (isTopExit(line)) {
                toptag = "";
            } else if (Character.isLetter(line.charAt(0))) {
                toptag = trimmed;
            }

            //
            // ip sla * - locked by ip sla schedule *
            //
            if (toptag.startsWith("ip sla ")
                && (id = getMatch(trimmed, "ip sla (\\d+)")) != null) {

                //
                // Temporarily remove "ip sla schedule" to unlock "ip sla"
                //
                String root = this.configRoot;
                try {
                    if (mm.exists(fromTh, root + "ip/sla/schedule{"+id+"}")
                        && mm.exists(toTh, root + "ip/sla/schedule{"+id+"}")) {
                        String schedule = maapiGetConfig(worker, mm, toTh, "ip/sla/schedule{"+id+"}");
                        if (schedule != null) {
                            schedule = schedule.trim();
                            traceInfo(worker, "PATCH: temporarily removing ip sla schedule "+id);
                            traceVerbose(worker, "transformed => injected 'no "+schedule+"'");
                            traceVerbose(worker, "transformed => injected '"+schedule+"' last");
                            sb.append("no "+schedule+"\n");
                            last.append(schedule+"\n");
                        }
                    }
                } catch (Exception e) {
                    traceInfo(worker, "NedDataModify() : exception ERROR: "+ e.getMessage());
                }

                //
                // Add back dynamically removed "ip sla reaction-configuration" entry/entries
                //
                try {
                    String react = maapiGetConfig(worker, mm, toTh, "ip/sla/reaction-configuration");
                    if (react != null) {
                        String[] entries = react.split("\n");
                        for (int e = 0; e < entries.length; e++) {
                            if (getMatch(entries[e], "(ip sla reaction-configuration "+id+" )") != null) {
                                traceVerbose(worker, "transformed => injected '"+entries[e]+"' last");
                                last.append(entries[e]+"\n");
                            }
                        }
                    }
                } catch (Exception e) {
                    traceInfo(worker, "NedDataModify() : exception ERROR: "+ e.getMessage());
                }

                //
                // Replace "ip sla" (can't modify operation line once set)
                //
                try {
                    if (mm.exists(fromTh, root + "ip/sla/ip-sla-list{"+id+"}")) {
                        String sla = maapiGetConfig(worker, mm, toTh, "ip/sla/ip-sla-list{"+id+"}");
                        if (sla != null) {
                            // Cache old ip sla config in sla0
                            String sla0 = "";
                            for (;n < lines.length; n++) {
                                String slaop = slaOperation(lines[n]);
                                if (slaop == null || !slaop.trim().startsWith("no ")) {
                                    sla0 += (lines[n] + "\n"); // trim no-operation line
                                }
                                if (isTopExit(lines[n])) {
                                    break;
                                }
                            }
                            // If new entry contains operation, replace all ip sla config
                            if (slaOperation(sla0) != null) {
                                traceInfo(worker, "PATCH: modified operation, replacing ip sla "+id);
                                sb.append("no ip sla "+id+"\n");
                                sb.append(sla);
                            } else {
                                sb.append(sla0);
                            }
                            continue;
                        }
                    }
                } catch (Exception e) {
                    traceInfo(worker, "NedDataModify() : exception ERROR: "+ e.getMessage());
                }
            }

            // Add line (may be empty due to stripped deleted address)
            if (!lines[n].trim().isEmpty()) {
                sb.append(lines[n]+"\n");
            }
        }

        return "\n" + sb.toString() + last.toString();
    }


    /**
     * Get config from CDB
     * @param
     * @return
     * @throws NedException
     */
    private String maapiGetConfig(NedWorker worker, Maapi mm, int th, String path) {
        StringBuilder sb = new StringBuilder();
        try {
            path = this.configRoot + path;
            if (!mm.exists(th, path)) {
                return null;
            }

            MaapiInputStream in = mm.saveConfig(th,
                                                EnumSet.of(MaapiConfigFlag.MAAPI_CONFIG_C_IOS,
                                                           MaapiConfigFlag.CISCO_IOS_FORMAT),
                                                path);
            if (in == null) {
                traceInfo(worker, "maapiGetConfig ERROR: failed to get "+ path);
                return null;
            }

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buffer, 0, buffer.length)) > 0) {
                sb.append(new String(buffer).substring(0, bytesRead));
                if (bytesRead < buffer.length) {
                    break;
                }
            }
        } catch (Exception e) {
            traceInfo(worker, "maapiGetConfig ERROR: read exception "+ e.getMessage());
            return null;
        }

        String[] lines = sb.toString().split("\n");
        if (lines.length < 5) {
            return null; // output does not contain 'devices device <device-id>\n config\n' + ' !\n!\n'
        }

        sb = new StringBuilder();
        for (int n = 2; n < lines.length - 2; n++) {
            String line = lines[n].substring(2);
            if (line.trim().startsWith("ios:") || line.trim().startsWith("no ios:")) {
                line = line.replaceFirst("ios:", "");
            }
            sb.append(line+"\n");
        }

        String data = sb.toString();
        traceVerbose(worker, "MAAPI_GET_AFTER=\n"+data);
        return data;
    }


    /**
     * Check if line is top exit
     * @param
     * @return
     */
    private boolean isTopExit(String line) {
        line = line.replace("\r", "");
        if (line.equals("exit")) {
            return true;
        }
        if (line.equals("!")) {
            return true;
        }
        return false;
    }


    /**
     * Check if line is sla operation
     * @param
     * @return
     */
    private String slaOperation(String line) {
        if (line.contains(" icmp-echo ")){
            return line;
        }
        if (line.contains(" tcp-connect ")) {
            return line;
        }
        if (line.contains(" udp-jitter ")) {
            return line;
        }
        if (line.contains(" udp-echo ")) {
            return line;
        }
        if (line.contains(" http get ")) {
            return line;
        }
        return null;
    }


    /**
     * Wrappers to write to trace
     * @param
     */
    private void traceInfo(NedWorker worker, String info) {
        owner.traceInfo(worker, info);
    }
    private void traceVerbose(NedWorker worker, String info) {
        owner.traceVerbose(worker, info);
    }

}
