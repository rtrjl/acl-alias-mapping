package com.tailf.packages.ned.ios;
import com.tailf.packages.ned.nedcom.NedComCliBase;
import com.tailf.packages.ned.nedcom.NedCommonLib.PlatformInfo;
import com.tailf.packages.ned.nedcom.NedSecrets;
import com.tailf.packages.ned.nedcom.livestats.NedLiveStats;
import com.tailf.packages.ned.nedcom.livestats.NedLiveStatsException;
import com.tailf.packages.ned.nedcom.livestats.NedLiveStatsShowHandler;
import static com.tailf.packages.ned.nedcom.NedString.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.text.StringCharacterIterator;
import java.text.CharacterIterator;

import java.net.InetAddress;
import java.net.NetworkInterface;

import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.SCPClient;
import ch.ethz.ssh2.SCPInputStream;

import com.tailf.conf.Conf;
import com.tailf.conf.ConfBuf;
import com.tailf.conf.ConfPath;
import com.tailf.conf.ConfValue;
import com.tailf.conf.ConfXMLParam;
import com.tailf.conf.ConfXMLParamValue;

import com.tailf.maapi.MaapiCrypto;
import com.tailf.maapi.MaapiException;

import com.tailf.ned.NedCmd;
import com.tailf.ned.NedExpectResult;
import com.tailf.ned.NedException;
import com.tailf.ned.NedMux;
import com.tailf.ned.NedWorker;
import com.tailf.ned.CliSession;
import com.tailf.ned.SSHSessionException;



/**
 * Implements the cisco-ios CLI NED
 * @author lbang
 *
 */
@SuppressWarnings("deprecation")
public class IOSNedCli extends NedComCliBase {

    // Constants
    private static final String EXTENDED_PARSER = "extended-parser";
    private enum Echo { WAIT, DONTWAIT, TEXT }

    // Prompts

    // start of input, > 0 non-# and ' ', one #, >= 0 ' ', eol
    private static final String PRIVEXEC_PROMPT = "\\A[^\\# ]+#[ ]?$";
    private static final String PROMPT = "\\A\\S+#";
    private static final String CONFIG_PROMPT = "\\A\\S+\\(\\S+\\)#[ ]?$";

    // print_line_wait() pattern
    private static final Pattern[] PLW0 = new Pattern[] {
        // 0 prompts:
        Pattern.compile("\\A.*\\(cfg\\)#"),
        Pattern.compile("\\A.*\\(config\\)#"),
        Pattern.compile("\\A.*\\(.*\\)#"),
        Pattern.compile("\\A\\S*#"),
        // 4 standard questions:
        Pattern.compile("\\?[ ]{0,2}\\(yes/\\[no\\]\\)"),  // ? (yes/[no])
        Pattern.compile("\\?[ ]{0,2}\\[[Yy]es/[Nn]o\\]"),  // ? [yes/no]
        Pattern.compile("\\?[ ]{0,2}\\[[Yy]es\\]"),        // ? [yes]
        Pattern.compile("\\?[ ]{0,2}\\[[Nn]o\\]"),         // ? [no]
        Pattern.compile("\\?[ ]{0,2}\\[confirm\\]")        // ? [confirm]
        // 9 additional patterns from inject-answer
    };

    private static final Pattern[] EC = new Pattern[] {
        Pattern.compile("Do you want to kill that session and continue"),
        Pattern.compile("\\A\\S*\\(config\\)#"),
        Pattern.compile("\\A.*\\(.*\\)#"),
        Pattern.compile("Aborted.*\n"),
        Pattern.compile("Error.*\n"),
        Pattern.compile("syntax error.*\n"),
        Pattern.compile("error:.*\n")
    };

    private static final Pattern[] EC2 = new Pattern[] {
        Pattern.compile("\\A.*\\(cfg\\)#"),
        Pattern.compile("\\A.*\\(config\\)#"),
        Pattern.compile("\\A.*\\(.*\\)#"),
        Pattern.compile("Aborted.*\n"),
        Pattern.compile("Error.*\n"),
        Pattern.compile("syntax error.*\n"),
        Pattern.compile("error:.*\n")
    };

    // NEDLIVESTATS prompts
    private static final Pattern[] NEDLIVESTATS_PROMPT = new Pattern[] {
        Pattern.compile("\\A.*\\(.*\\)#"),
        Pattern.compile("\\A[^\\# ]+#[ ]?$")
    };

    /**
     * Warnings, regular expressions. NOTE: Lowercase!
     */
    private static final String[] staticWarning = {
        // general
        "warning[:,] \\S+.*",
        "warning:",
        ".?note:",
        "info:",
        "aaa: warning",
        "success",  //  " added successfully",
        "enter text message",
        "enter macro commands one per line",
        "this commmand is deprecated",
        "this command requires a reload to take effect",
        "will take effect after reload",
        "this command is an unreleased and unsupported feature",
        "this cli will be deprecated soon",
        "command accepted but obsolete, unreleased or unsupported",
        "redundant .* statement",
        "elapsed time was \\d+ seconds",
        "configuring anyway",

        // remove || delete
        "hqm_tablemap_inform: class_remove error",
        "all rsa keys will be removed",
        "all router certs issued using these keys will also be removed",
        "not all config may be removed and may reappear after",
        "removed .* policy from .* interface",
        "this will remove previously",
        "removing ssp group",
        "remote  deleted",
        "tunnel interface was deleted",
        "mac address.*has been deleted from the bridge table",
        "non-fr-specific configuration, if not yet explicitly deconfigured",
        "can't delete last \\d+ vty lines",

        // in case of some device flavors the entry is not deleted
        // "bridge-domain \\d+ cannot be deleted because it is not empty",  // no bridge-domain *
        "\\S+ profile is removed",
        "service removed for domain .*",
        "will be removed from .* due to removal of",
        "warning: \\S+ is the default fax protocol, it can not be removed",
        "removed \\d+ (entry|entries)",
        "removing .+ configuration on all interfaces",
        "can't delete view \\S+",
        "can not find view \\S+",
        "entry not configured",

        // change
        "changes to .* will not take effect until the next",
        "security level for .* changed to",
        "connection name is changed",
        "changes to the running .* have been stored",
        "you are about to \\S+grade",
        "use 'write' command to make", // license boot level security
        "no change in the configuration",
        "same config is entered which has no effect",
        "a system reload is required before .+ change", // subscriber templating
        "changing media to \\S+", // interface * / media-type
        ".+ set to default configuration", // default

        // VRF
        "removed due to \\S+abling vrf",
        "removed due to vrf change",
        "the static routes in vrf .*with outgoing interface .*will be",
        "ip.* addresses from all interfaces in vrf .*have been removed",
        "number of vrfs \\S+graded",
        "vrf .*exists but is not enabled",
        "a new tunnel id may be used if the default mdt is reconfigured for this vrf",
        "for vrf .* scheduled for deletion",
        "vrf \\S+ not configured, invalid vrf name",
        "unable to remove extended community", // ip vrf * / no route-target
        "vrf \\S+ is now bound to default vrf parameter map",

        // vlan
        "vlan.* does not exist.* creating vlan",
        "please refer to documentation on configuring ieee 802.1q vlans",
        "vlan mapping is also changed",
        ".*vlan .* does not exist, creating vlan.*",
        "vlan mapping is also changed",
        "vlan  mod/ports",
        "applying vlan changes may take few minutes",
        "access vlan does not exist",
        "the .+ in slot \\S+ is currently offline",

        // interface
        "if .*interface does.* support baby giant frames",
        "no cef interface information",
        "unrecognized virtual interface .* treat it as loopback stub",
        "ipv4 and ipv6 addresses from all",
        "ip\\S+ addresses from all interfaces",
        "pim configuration for interface",
        "interface .* hsrp [a-f0-9:]* removed due to vrf change",
        "(\\S+): informational: \\S+ is in use on",
        "is reverting to router mode configuration, and remains disabled",
        "ospf will not operate on this interface until ip is configured on it",
        "command will have no effect with this interface",
        "portfast has been configured on ",  // spanning-tree portfast
        "creating a port-channel interface port-channel", // interface * / channel-group 3 mode active
        "speed auto-negotiation also needs to be set for auto-mdix to take effect", // mdix auto
        "the multilink group configuration will be removed from all the member links", // no interface Multilink
        "removal of channelized sonet/sdh interface configuration is not permitted", // no interface Serial
        "xconnect configuration on this circuit is incomplete", // interface * / xconnect
        "not found . using global defaults",
        "configured platform supported protocols",
        "is .+ fragmentation may occur", // interface * / ip mtu

        // router
        "peer-group \\S+ is not present, but will go ahead and delete",
        "peergroups are automatically activated when parameters are configured",
        // router lisp / service * / encapsulation
        "setting the encapsulation of ipv(4|6) to \\S+. encapsulation cannot be different",
        "all bgp sessions must be reset to take the new", // bgp graceful-restart restart-time
        "only classful networks will be redistributed", // router ospf * / redistribute static
        "removing wide metrics also removes mpls te on", // router isis / no metric-style wide
        "reference bandwidth is changed", // router ospf / auto-cost reference-bandwidth
        ".* set use own .* address for the nexthop not supported", // MPLS-OUT

        // tunnel
        "tunnel mpls traffic-eng fast-reroute",
        "attach member tunnel to a master",
        "\\S+ tunnels are not enabled on this router", // interface * / mpls traffic-eng tunnels

        // mpls
        "pce disjoint-path source \\S+ type \\S+ group-id", // mpls traffic-eng lsp attributes * / pce
        "^record-route$", // mpls traffic-eng lsp attributes * / record-route

        // AppNav / virtual-service
        "ac with local ip is being removed\\. service context cannot be enabled",
        "service context must have a appnav controller group attached to it before it can be enabled",
        "last vrf removed\\. disable this service-context",
        "activating virtual-service .* this might take a few minutes", //  virtual-service * / activate
        "virtual service .* install has not completed",
        "virtual service \\S+ was not activated",
        "acg must contain ip that is local to the device and interface should be up",

        // utd
        "please ensure .* is configured to use",
        "filtering will now be disabled on exiting the submode",
        "source db config has now been removed",
        "utd deregistered with appnav", // no utd
        "utd successfully registered with appnav", // utd engine standard multi-tenancy
        "utd redirect interface set to \\S+ internally", // utd engine standard multi-tenancy
        "utd appnav.*registration",  // utd engine standard multi-tenancy

        // SSH & certificate
        "enter the certificate",
        "certificate accepted",
        "certificate request sent",
        "ssh:publickey disabled.overriding rfc",
        "ssh:no auth method configured.incoming connection will be dropped",
        "please create rsa keys to enable ssh",
        "generating \\d+ bit rsa keys",   // ip http secure-server, crypto pki server * / no shutdown etc.
        "the certificate has been deleted", // no certificate self-signed X
        "cannot delete certificate server certificates", // no crypto pki certificate chain

        // crypto
        "ikev2 \\S+ must have",
        "crypto-6-isakmp_on_off: isakmp is",
        "be sure to ask the ca administrator to revoke your certificates",
        "overriding already existing source with priority",
        "updated group cp to ", // crypto gkm group * / server address ipv4
        "this will remove all existing \\S+ on this map", // crypto map ** ipsec-isakmp / reverse-route static
        // crypto map ** ipsec-isakmp / no reverse-route static
        "removing \\S+ will delete all routes and clear current ipsec",
        "ikev2 proposal must either have a set of an encryption algorithm", // crypto ikev2 proposal *
        "event has been queued for processing", // crypto pki server * / shutdown
        "the .* change will take effect after existing .* expire", // crypto pki server * / lifetime
        "can't find policy \\S+",  // no crypto pki trustpoint
        "re-enter password:", // crypto pki server * / no shutdown
        "certificate server enabled", // crypto pki server * / no shutdown
        "removing rri will delete all routes and", // crypto map * / no reverse-route
        "remove the trustpoint to remove the cert chain", // no crypto pki certificate chain
        "enrollment url must be configured", // crypto pki trustpoint * / vrf
        "remember that, to permamently enforce", // no crypto ipsec optional

        // nat
        "global .* will be port address translated",
        "outside interface address added",
        "pool nat-pool mask .* too small",
        "the active \\S+ status is not known",  // do clear ip nat translation vrf

        // policy-map & class-map
        "no specific protocol configured in class (.*) for inspection",
        "conform burst size \\S+creased to",
        // policy map .* not configured
        //class-map .* being used
        //service policy .* not attached

        // routing
        "reload or use .* command, for this to take effect",
        // ip routing table .* does not exist. create first
        //no matching route to delete

        // queue | cos
        ".*propagating cos-map configuration to.*",
        ".*propagating queue-limit configuration to.*",
        "cos mutation map",
        "(cos-map|queue-limit) configured on all .* ports on slot .*",
        "please change queue-limit setting",

        // cable
        "minislot size set to", // no us-channel
        "the minislot size is now changed to", // no cable service class
        "response of applying upstream controller-profile", // no cable service class
        "fiber node \\d+ is valid",
        "port \\S+ admin change to (down|up)",
        "caution[:] .+ may result in .+",
        "\\S+ profile group \\S+ is reset to default",
        "setup depi class automatically", // cable rpd *

        // call-home
        // call-home / profile * / destination transport-method http
        "profile cannot enable more than one transport method",
        // call-home / profile * / no destination transport-method http
        "call-home profile need to have at least one transport-method",
        //"removal of cisco tac profile is not allowed. it can be disabled by issuing", // call-home / no profile *
        "the email address configured in .* will be used as", // call-home / contact-email-addr
        "please configure .* under call-home mode", // call-home / profile * / no anonymous-reporting-only
        "the specified .* is removed", // call-home / no mail-server *
        "configuration succeed, but fail to parse the address", // call-home / mail-server *

        // snmp
        "user cannot belong to an auto-configured group",

        // misc
        "remove mapping of trigger id",
        "cts device id and password have been inserted in the local keystore", // cts credentials id [EXEC]
        "class set to .+ for redundancy group",  // redundancy / linecard-group * / class
        "restarting lc in slot .+ as it is being added as a secondary to", // redundancy / linecard-group * / member
        "warning\\S+ auto discovery already ", // service-insertion * / node-discovery enable
        "enabling mls qos globally",
        "name length exceeded the recommended length of .* characters",
        "a profile is deemed incomplete until it has .* statements",
        "address aliases with",
        "explicit path name",
        "global ethernet mtu is set to",
        "restarting .* service",
        "the .* command will also show the fingerprint",
        "encapsulation dot1q",
        "icmp redirect",
        "\\S+abling learning on",
        "\\S+abling failover",
        "the threshold option has been accepted",
        "added .*to the bridge table",
        " and mac table will be flushed",
        "arp inspection \\S+abled on",
        "configurations are no longer synchronized",
        "pix-[.]-",
        "secured .* cleared from",
        "current activity time is .* seconds",
        "rm entries aging is turned o",
        "zoning is currently not configured for interface",
        "propagating wred configuration to",
        "selected country",
        "is not a legal lat node name",
        "affinity \\S+ mask \\S+", // mpls traffic-eng lsp attributes * / affinity
        "changing vtp domain name from",
        "setting device to vtp .*",
        "wait for .* license request to succeed", // platform hardware throughput level
        "logging of %snmp-3-authfail is (dis|en)abled", // logging snmp-authfail
        "translating \\S+",  // ntp server
        "previously established ldp sessions may not have graceful restart protection", // mpls ldp graceful-restart
        "user configured would overwrite defaults", // parameter-map * / resolver
        "et-analytics destination .* combination does not exist", // et-analytics / no ip flow-export destination
        "delete policy map", // domain * / vrf * / no class
        "label range change will cause",
        "enabling .+ on sub interfaces will have unpredictable results", // cdp tlv-list * / port-id
        "please make sure \\S+ \\S+ is configured", // l2 vfi * / neighbor *
        "react configured but inactive for monitor rtp", // policy-map type performance-monitor * / class * / react *

        // dial-peer
        "bind command will take effect after the bound interface is up", // dial-peer voice * / voice-class sip bind control source-interface

        // telephony-service
        "fac standard (is set|has been disabled)!", // telephony-service / fac
        "reload the system to remove ephone.*", // telephony-service / max-ephones

        // ephone *
        "the ephone template tag has been changed under this ephone.*" // ephone * / ephone-template
    };

    // Utility classes
    protected MaapiCrypto mCrypto = null;
    protected NedCommand nedCommand;
    private MetaDataModify metaData;
    private NedDataModify nedData;
    private NedSecrets secrets;
    private NedDefaults defaults;
    private NedAcl nedAcl;
    private ConfigArchive configArchive;

    // devices info
    private String iosname = "ios";
    private String iosversion = "unknown";
    private String iosmodel = "unknown";
    private String iosserial = "unknown";
    private String xeversion = "";
    private String iospolice = "unknown";
    private String licenseLevel = null;
    private String licenseType = null;
    private String confRoot;
    private ArrayList<String[]> cachedShowInventory = new ArrayList<>();
    private String deviceProfile = "null";

    // nso info
    private String rollBackOctal;

    // States
    private long lastTimeout;
    private String lastTransformedConfig = null;
    private String lastGetConfig = null;
    private Echo waitForEcho = Echo.WAIT;
    protected boolean inConfig = false;
    private int num_reordered;
    private String lastOKLine = "";
    private String warningsBuf = "";
    private boolean showRaw = false;
    private String syncFile = null;
    private boolean ignoreNextWrite = false;
    protected int lastTransactionId = 0;

    // have show command:
    private boolean haveShowBoot = true;
    private boolean haveShowVtpStatus = true;
    private boolean haveShowVlan = true;
    private boolean haveShowVlanSwitch = true;
    private boolean haveShowSnmpUser = true;

    // NED-SETTINGS
    private ArrayList<String> dynamicWarning = new ArrayList<>();
    private ArrayList<String[]> interfaceConfig = new ArrayList<>();
    private ArrayList<String[]> injectConfig = new ArrayList<>();
    private ArrayList<String[]> injectCommand = new ArrayList<>();
    private ArrayList<String[]> injectAnswer = new ArrayList<>();
    private ArrayList<String[]> replaceConfig = new ArrayList<>();
    private ArrayList<String[]> replaceCommit = new ArrayList<>();
    private String writeMemory;
    private String writeMemoryMode;
    private boolean writeTransferViaFile;
    private int applyRebootTimer;
    private String policeFormat;
    private int deviceOutputDelay;
    private int configOutputMaxRetries;
    private int chunkSize;
    private String transIdMethod;
    private String showRunningConfig;
    private boolean useIpMrouteCacheDistributed;
    private boolean newIpACL;
    private String ipACLunorderedRegex;
    private boolean newSnmpServerHost;
    private boolean resequenceACL;
    private boolean includeCachedShowVersion;
    private boolean includeCachedShowInventory;
    private boolean autoInterfaceSwitchportStatus;
    private boolean autoIfAddressDeletePatch;
    private String devPrepareDryModel;
    private Pattern[] plw;


    /*
     **************************************************************************
     * Constructors
     **************************************************************************
     */

    /**
     * NED cisco-ios constructor
     */
    public IOSNedCli() {
        super();
    }


    /**
     * NED cisco-ios constructor
     * @param device_id
     * @param mux
     * @param trace
     * @param worker
     */
    public IOSNedCli(String device_id,
                     NedMux mux,
                     boolean trace,
                     NedWorker worker) throws Exception {
        super(device_id, mux, trace, worker);
        confRoot = "/ncs:devices/device{"+device_id+"}/config/ios:";
    }


    /*
     **************************************************************************
     * nedSettingsDidChange
     **************************************************************************
     */

    /**
     * Called when ned-settings changed
     * @param
     * @throws Exception
     */
    @Override
    public void nedSettingsDidChange(NedWorker worker, Set<String> changedKeys, boolean isConnected) throws Exception {
        final long start = tick(0);
        logInfo(worker, "BEGIN nedSettingsDidChange");
        try {
            List<Map<String,String>> entries;

            // cisco-ios auto interface-switchport-status - FIRST because read by other settings
            autoInterfaceSwitchportStatus = nedSettings.getBoolean("auto/interface-switchport-status");

            //
            // read
            //
            transIdMethod = nedSettings.getString("read/transaction-id-method");
            showRunningConfig = nedSettings.getString("read/show-running-method");
            if (showRunningConfig.startsWith("scp-transfer") && proto != null && !proto.equals("ssh")) {
                throw new NedException("Must use CLI protocol ssh for read/show-running-method scp-transfer");
            }

            /*
             * read/replace-config
             */
            entries = nedSettings.getListEntries("read/replace-config");
            for (Map<String,String> entry : entries) {
                String[] newEntry = new String[4];
                newEntry[0] = entry.get("__key__"); // "id"
                newEntry[1] = entry.get("regexp");
                newEntry[2] = entry.get("replacement");
                newEntry[3] = entry.get("when");
                String buf = "read/replace-config "+newEntry[0];
                buf += " regexp "+stringQuote(newEntry[1]);
                if (newEntry[1] == null) {
                    throw new NedException("ned-settings: read/replace-config "+newEntry[0]+" missing regexp");
                }
                if (newEntry[2] != null) {
                    buf += " to "+stringQuote(newEntry[2]);
                } else {
                    newEntry[2] = "";
                    buf += " filtered";
                }
                if (newEntry[3] != null) {
                    buf += " " + newEntry[3];
                }
                traceVerbose(worker, buf);
                replaceConfig.add(newEntry);
            }

            /*
             * read/inject-config
             */
            entries = nedSettings.getListEntries("read/inject-config");
            for (Map<String,String> entry : entries) {
                String[] newEntry = new String[4];
                newEntry[0] = entry.get("__key__"); // "id"
                newEntry[1] = entry.get("regexp");
                newEntry[2] = entry.get("config");
                newEntry[3] = entry.get("where");
                String buf = "read/inject-config "+newEntry[0];
                if (newEntry[2] == null) {
                    throw new NedException("ned-settings: "+buf+" missing config");
                }
                if (newEntry[1] != null) {
                    buf += " regexp "+stringQuote(newEntry[1]);
                }
                buf += " cfg "+stringQuote(newEntry[2]);
                if (newEntry[3] != null) {
                    buf += " " + newEntry[3];
                }
                traceVerbose(worker, buf);
                injectConfig.add(newEntry);
            }

            /*
             * read/inject-interface-config
             */

            // Add a static global default 'no switchport' setting
            // Used for devices/interfaces which do not support switchport
            // or for devices which hide 'no switchport' when disabled, eg:
            // WS-C6504-E or CISCO7606-S or CISCO2901/K9
            if (!autoInterfaceSwitchportStatus) {
                String[] staticEntry = new String[3];
                staticEntry[0] = "Ethernet|Port-channel";
                staticEntry[1] = "no switchport";
                staticEntry[2] = "globstat-sp";
                traceVerbose(worker, "read/inject-interface-config "+staticEntry[2]
                             +" if "+stringQuote(staticEntry[0])
                             +" cfg "+stringQuote(staticEntry[1]));
                interfaceConfig.add(staticEntry);
            }
            entries = nedSettings.getListEntries("read/inject-interface-config");
            for (Map<String,String> entry : entries) {
                String[] newEntry = new String[3];
                newEntry[0] = entry.get("interface");
                newEntry[1] = entry.get("config");
                newEntry[2] = entry.get("__key__"); // "id"
                if (newEntry[0] == null || newEntry[1] == null) {
                    throw new NedException("ned-settings: read/inject-interface-config "+newEntry[2]
                                           +" missing interface or config");
                }
                traceVerbose(worker, "read/inject-interface-config "+newEntry[2]
                             +" if "+stringQuote(newEntry[0])
                             +" cfg "+stringQuote(newEntry[1]));
                interfaceConfig.add(newEntry);
            }

            //
            // write
            //
            writeMemory = nedSettings.getString("write/memory-method");
            writeMemoryMode = nedSettings.getString("write/memory-setting");
            configOutputMaxRetries = nedSettings.getInt("write/config-output-max-retries");
            chunkSize = nedSettings.getInt("write/number-of-lines-to-send-in-chunk");
            deviceOutputDelay = nedSettings.getInt("write/device-output-delay");
            writeTransferViaFile = nedSettings.getBoolean("write/transfer-via-file");
            applyRebootTimer = nedSettings.getInt("write/apply-reboot-timer");

            /*
             * write/config-warning
             */
            entries = nedSettings.getListEntries("write/config-warning");
            for (Map<String,String> entry : entries) {
                String key = entry.get("__key__");
                traceVerbose(worker, "write/config-warning "+key);
                dynamicWarning.add(stringDequote(key));
            }

            /*
             * write/replace-commit
             */
            entries = nedSettings.getListEntries("write/replace-commit");
            for (Map<String,String> entry : entries) {
                String[] newEntry = new String[4];
                newEntry[0] = entry.get("__key__"); // "id"
                newEntry[1] = entry.get("regexp");
                newEntry[2] = entry.get("replacement");
                String buf = "write/replace-commit "+newEntry[0];
                buf += " regexp "+stringQuote(newEntry[1]);
                if (newEntry[1] == null) {
                    throw new NedException("ned-settings: write/replace-commit "+newEntry[0]+" missing regexp");
                }
                if (newEntry[2] != null) {
                    buf += " to "+stringQuote(newEntry[2]);
                } else {
                    newEntry[2] = "";
                    buf += " filtered";
                }
                traceVerbose(worker, buf);
                replaceCommit.add(newEntry);
            }

            /*
             * write/inject-command
             */
            entries = nedSettings.getListEntries("write/inject-command");
            for (Map<String,String> entry : entries) {
                String[] newEntry = new String[4];
                newEntry[0] = entry.get("__key__"); // "id"
                newEntry[1] = entry.get("config-line");
                newEntry[2] = entry.get("command");
                newEntry[3] = entry.get("where");
                if (newEntry[1] == null || newEntry[3] == null) {
                    throw new NedException("ned-settings: write/inject-command "+newEntry[0]
                                           +" missing config-line or where");
                }
                String buf = "write/inject-command "+newEntry[0]+" cfg "+stringQuote(newEntry[1]);
                if (newEntry[2] != null) {
                    buf += " cmd "+stringQuote(newEntry[2]);
                } else {
                    newEntry[2] = "";
                    buf += " filtered";
                }
                buf += " "+newEntry[3];
                traceVerbose(worker, buf);
                injectCommand.add(newEntry);
            }

            /*
             * write/inject-answer
             */
            entries = nedSettings.getListEntries("write/inject-answer");
            for (Map<String,String> entry : entries) {
                String[] newEntry = new String[4];
                newEntry[0] = entry.get("__key__"); // "id"
                newEntry[1] = entry.get("question");
                newEntry[2] = entry.get("answer");
                newEntry[3] = entry.get("ml-question");
                if (newEntry[1] == null || newEntry[2] == null) {
                    throw new NedException("ned-settings: write/inject-answer "+newEntry[0]+" missing question or answer");
                }
                String buf = "write/inject-answer "+newEntry[0]
                    + " q " +stringQuote(newEntry[1])
                    + " a " +stringQuote(newEntry[2]);
                if (newEntry[3] != null) {
                    buf += " ml-q " +stringQuote(newEntry[3]);
                }
                traceVerbose(worker, buf);
                injectAnswer.add(newEntry);
            }

            // Create print_line_wait() pattern 'plw'
            plw = new Pattern[PLW0.length + injectAnswer.size()];
            for (int i = 0; i < PLW0.length; i++) {
                plw[i] = PLW0[i];
            }
            for (int i = 0; i < injectAnswer.size(); i++) {
                String[] entry = injectAnswer.get(i);
                plw[PLW0.length + i] = Pattern.compile(entry[1]);
            }

            //
            // auto
            //
            useIpMrouteCacheDistributed = nedSettings.getBoolean("auto/use-ip-mroute-cache-distributed");
            autoIfAddressDeletePatch = nedSettings.getBoolean("auto/if-address-delete-patch");

            //
            // api
            //
            policeFormat = nedSettings.getString("api/police-format");
            if (policeFormat == null) {
                policeFormat = "auto";  // Note: leaf-list does not support default statement
            }
            newIpACL = nedSettings.getBoolean("api/new-ip-access-list");
            resequenceACL = nedSettings.getBoolean("api/access-list-resequence");
            ipACLunorderedRegex = nedSettings.getString("api/unordered-ip-access-list-regex");
            newSnmpServerHost = nedSettings.getBoolean("api/new-snmp-server-host");

            // developer
            devPrepareDryModel = nedSettings.getString("developer/prepare-dry-model");

            //
            // deprecated
            //
            includeCachedShowVersion = nedSettings.getBoolean("deprecated/cached-show-enable/version");
            includeCachedShowInventory = nedSettings.getBoolean("deprecated/cached-show-enable/inventory");

            // write config-archive *
            configArchive = new ConfigArchive(this);
            configArchive.init(worker);

        } catch (Exception e) {
            throw new NedException("Failed to read ned-settings"+e.getMessage(), e);
        }
        logInfo(worker, "DONE nedSettingsDidChange "+tickToString(start));
    }


    /*
     **************************************************************************
     * setupDevice
     **************************************************************************
     */

    /**
     * Setup device
     * @param
     * @return PlatformInfo
     * @throws Exception
     */
    protected PlatformInfo setupDevice(NedWorker worker) throws Exception {
        tracer = trace ? worker : null;
        final long start = tick(0);
        logInfo(worker, "BEGIN PROBE");

        //
        // Logged in, set terminal settings and check device type
        //
        try {
            // Set terminal settings
            print_line_exec(worker, "terminal length 0");
            print_line_exec(worker, "terminal width 0");

            // Show version
            String version = print_line_exec(worker, "show version");
            version = version.replace("\r", "");

            // Verify that this is an IOS device
            traceInfo(worker, "Inspecting version string");
            if (!version.contains("Cisco IOS Software")
                && !version.contains("Cisco Internetwork Operating")
                && !version.contains("Cisco Wide Area Application Services Software")) {
                throw new NedException("Unknown device :: " + version);
            }

            // Found IOS device, init NED
            traceVerbose(worker, "Found IOS device");

            // NETSIM
            if (version.contains("NETSIM")) {
                this.iosmodel = "NETSIM";
                this.iosversion = "cisco-ios-" + nedVersion;
                this.iosserial = device_id;

                // Show CONFD & NED version used by NETSIM in ned trace
                print_line_exec(worker, "show confd-state version");
                print_line_exec(worker, "show confd-state loaded-data-models data-model tailf-ned-cisco-ios");

                // Disable show commands for device only:
                traceInfo(worker, "Disabling all device show checks");
                haveShowBoot = haveShowVtpStatus = haveShowVlan = haveShowVlanSwitch = haveShowSnmpUser = false;
                showRunningConfig = "show running-config"; // Override SCP or other bad global setting
            }

            // REAL DEVICE
            else {

                // Cache show version License Type & Level
                licenseType = findLine(version, "License Type:");
                if (licenseType != null) {
                    licenseType = licenseType.substring(14);
                }
                licenseLevel = findLine(version, "License Level:");
                if (licenseLevel != null) {
                    licenseLevel = licenseLevel.substring(15).trim();
                    int b;
                    if ((b = licenseLevel.indexOf("Type:")) > 0) {
                        licenseType = licenseLevel.substring(b+6).trim();
                        licenseLevel = licenseLevel.substring(0,b).trim();
                    }
                }
                if (licenseType != null && licenseType.contains(" ")) {
                    licenseType = "\"" + licenseType + "\"";
                }

                // cached-show inventory (name and serial numbers)
                if (includeCachedShowInventory) {
                    cacheShowInventory(worker);
                }

                // Show current configuration id for debug purposes
                if ("config-id".equals(transIdMethod)) {
                    print_line_exec(worker, "show configuration id");
                }
            }

            //
            // Get iosname
            //
            if (version.contains("Cisco IOS XE Software")
                || version.contains("IOS-XE Software")
                || version.contains("Cisco IOS-XE software")) {
                this.iosname = "ios-xe";
            }

            //
            // Get iosmodel
            //
            Pattern p = Pattern.compile("\n[Cc]isco (\\S+) .*(?:processor |revision )");
            Matcher m = p.matcher(version);
            if (m.find()) {
                this.iosmodel = m.group(1);
            }

            //
            // Get iosversion (pick IOS version before XE version)
            //
            p = Pattern.compile("Cisco.*IOS Software.*Version ([0-9]+[A-Za-z0-9\\.():-]+[0-9a-zA-Z)]+)");
            m = p.matcher(version);
            if (m.find()) {
                this.iosversion = m.group(1);
            } else {
                // cat3550 and cat6500 version extraction do not trigger on the above regexp
                p = Pattern.compile("(?:Cisco)?.*IOS.*Software.*Version ([0-9]+[A-Za-z0-9\\.():-]+[0-9a-zA-Z)]+)");
                m = p.matcher(version);
                if (m.find()) {
                    this.iosversion = m.group(1);
                }
            }

            //
            // Get xeversion
            //
            p = Pattern.compile("Version(?:[:])? (03\\S+) ");
            m = p.matcher(version);
            if (m.find()) {
                this.xeversion = m.group(1);
            }

            //
            // Get iosserial
            //
            p = Pattern.compile("Processor board ID (\\S+)");
            m = p.matcher(version);
            if (m.find()) {
                this.iosserial = m.group(1);
            }

        } catch (Exception e) {
            logError(worker, "Failed to setup NED :: ", e);
            throw new NedException("Failed to setup NED :: "+e.getMessage(), e);
        }

        logInfo(worker, "DONE PROBE "+tickToString(start));
        return new PlatformInfo(iosname, iosversion, iosmodel, iosserial);
    }


    /**
     *
     * @param
     * @throws Exception
     */
    private void cacheShowInventory(NedWorker worker) throws Exception {
        setReadTimeout(worker);
        String res = print_line_exec(worker, "show inventory");
        String[] lines = res.split("NAME: ");
        for (int i = 0; i < lines.length; i++) {
            Pattern pattern = Pattern.compile("(\\\".*?\\\"), .*,\\s+SN: (.*)", Pattern.DOTALL);
            Matcher matcher = pattern.matcher(lines[i]);
            if (matcher.find()) {
                String[] entry = new String[2];
                entry[0] = matcher.group(1);
                entry[1] = matcher.group(2).trim();
                traceInfo(worker, "Adding cached-show inventory: NAME="+entry[0]+" SN="+entry[1]);
                cachedShowInventory.add(entry);
            }
        }
    }


    /*
     **************************************************************************
     * setupInstance
     **************************************************************************
     */

    /**
     * Setup NED instance
     * @param
     * @throws Exception
     */
    protected void setupInstance(NedWorker worker, PlatformInfo platformInfo) throws Exception {
        final long start = tick(0);
        logInfo(worker, "BEGIN SETUP");

        if (this.writeTimeout < this.readTimeout) {
            traceInfo(worker, "WARNING: write-timeout too low, reset to read-timeout value");
            this.writeTimeout = this.readTimeout; // API CHANGE helper
        }

        this.iosname = platformInfo.name;
        this.iosmodel = platformInfo.model;
        this.iosversion = platformInfo.version;
        this.iosserial = platformInfo.serial;

        setUserSession();
        int th = maapi.startTrans(Conf.DB_RUNNING, Conf.MODE_READ);

        // Get iospolice
        this.iospolice = getIosPolice(worker, th, true);

        traceInfo(worker, "DEVICE:"
                  +" name="+iosname+" model="+iosmodel+" version="+iosversion
                  +" serial="+iosserial+" xe-version="+xeversion+" police="+iospolice);

        // Trace device profile
        try {
            String p = "/ncs:devices/device{"+device_id+"}/device-profile";
            if (maapi.exists(th, p)) {
                this.deviceProfile = ConfValue.getStringByValue(p, maapi.getElem(th, p));
            }
        } catch (MaapiException ignore) {
            // Ignore Exception
        }
        traceInfo(worker, "device-profile = " + this.deviceProfile);

        // Trace NSO features
        rollBackOctal = nsoCapabilityProps.getProperty("rollback-files-octal", "no");
        traceInfo(worker, "nso-features/rollback-files-octal = "+rollBackOctal);

        // Close transaction
        maapi.finishTrans(th);

        // Create utility classes used by IOS NED
        metaData = new MetaDataModify(this);
        nedData = new NedDataModify(this);
        secrets = new NedSecrets(this);
        defaults = new NedDefaults(this);
        nedAcl = new NedAcl(this);
        mCrypto = new MaapiCrypto(maapi);

        // ned-settings cisco-ios live-status exec-done-pattern
        String execDonePattern = nedSettings.getString("live-status/exec-done-pattern");
        if (execDonePattern == null) {
            // [cisco-ios] 'issu runversion'
            execDonePattern = "(Initiating active RP failover)|(Target RP will now reload)";
        }

        // NedCommand default auto-prompts:
        String[][] defaultAutoPrompts = new String[][] {
            { execDonePattern, "<exit>" },
            { "([!]{20}|[C]{20}|[.]{20})", "<timeout>" },
            { "\\[OK\\]", null },
            { "\\[Done\\]", null },
            { "timeout is \\d+ seconds:", null },  // ping
            { "Key data:", null }, // crypto key export rsa
            { " has the following attributes:", null }, // crypto pki authenticate
            { ":\\s*$", "<prompt>" },
            { "\\][\\?]?\\s*$", "<prompt>" }
        };
        nedCommand = new NedCommand(this, "ios-stats", "ios", PRIVEXEC_PROMPT, CONFIG_PROMPT,
                                    " Invalid input detected at ", defaultAutoPrompts);

        // Only setup liveStats for connected devices
        if (session != null) {

            // Setup custom show handler
            nedLiveStats.setupCustomShowHandler(new ShowHandler(this, session, NEDLIVESTATS_PROMPT));

            // Make NedLiveStats aware of the ietf-interface and ietf-ip modules.
            nedLiveStats.installParserInfo("if:interfaces-state/interface",
                                           "{'show':'show interfaces',"+
                                           "'template':'if:interfaces-state_interface.gili',"+
                                           "'show-entry':{'cmd':'show interfaces %s',"+
                                           "'template':'if:interfaces-state_interface.gili',"+
                                           "'trim-top-node':true,'run-after-show':false}}");

            nedLiveStats.installParserInfo("if:interfaces-state/if:interface/ip:ipv4/ip:address",
                                    "{'show':{'cmd':'show run interface %s | include ip address','arg':['../../name']},"+
                                    "'template':'if:interfaces-state_interface_ip:ipv4_address.gili'}");

            nedLiveStats.installParserInfo("if:interfaces-state/if:interface/ip:ipv6/ip:address",
                                    "{'show':{'cmd':'show run interface %s | include ipv6 address','arg':['../../name']},"+
                                    "'template':'if:interfaces-state_interface_ip:ipv6_address.gili'}");
        }

        logInfo(worker, "DONE SETUP "+tickToString(start));
    }


    /**
     * NedLiveStatsShowHandler
     * @param
     * @throws Exception
     */
    private class ShowHandler extends NedLiveStatsShowHandler {
        private NedComCliBase owner;
        private CliSession session;
        private Pattern[] prompts;

        public ShowHandler(NedComCliBase owner, CliSession session, Pattern[] prompts)
            throws NedLiveStatsException {
            super(owner, session, prompts);
            this.owner = owner;
            this.session = session;
            this.prompts = prompts;
        }

        public String execute(NedWorker worker, String cmd) throws Exception {

            traceInfo(worker, "ShowHandler: "+stringQuote(cmd));

            // '!noop' used for dummy show-entry
            if (cmd.startsWith("!")) {
                return "";
            }

            // ned-setting cisco-ios developer simulate-show *
            HashMap<String,String> map = new HashMap<>();
            String path = "developer/simulate-show{\""+cmd+"\"}/file";
            nedSettings.getMatching(map, path);
            if (map.size() > 0) {
                String filename = map.get(path);
                if (filename != null) {
                    String output = readFile(filename);
                    if (output != null) {
                        traceInfo(worker, "ShowHandler: Simulated output from '"+filename+"':\n"+output);
                        return output;
                    }
                }
            }

            // NETSIM show command massage
            if (this.owner != null && this.owner.isNetsim()) {
                // Split interface name
                Pattern p = Pattern.compile("show run interface ([A-Za-z]+)([0-9]+\\S*)");
                Matcher m = p.matcher(cmd);
                if (m.find()) {
                    cmd = cmd.replace(m.group(1)+m.group(2), m.group(1)+" "+m.group(2));
                }

                // Insert "" around the include|exclude <regex>
                String[] args = cmd.split(" [|] (include|exclude) ");
                for (int i = 1; i < args.length; i++) {
                    cmd = cmd.replace(args[i], "\""+args[i]+"\"");
                }
            }

            // General show command massage
            if (cmd.startsWith("show bgp vpnv4 unicast all neighbors ")) {
                if (cmd.endsWith(" -")) {
                    // Strip any vrf, signified by "-" in the code
                    cmd = cmd.substring(0, cmd.length() - 2);
                } else {
                    Pattern p = Pattern.compile("show bgp vpnv4 unicast all neighbors (\\S+) (\\S+)");
                    Matcher m = p.matcher(cmd);
                    if (m.find()) {
                        cmd = "show bgp vpnv4 unicast vrf "+m.group(2)+" neighbors "+m.group(1);
                    }
                }
            }

            session.println(cmd);
            session.expect(Pattern.quote(cmd), worker);
            NedExpectResult res = session.expect(prompts, worker);

            // Modify show input
            String[] lines = res.getText().split("\n");
            StringBuilder sb = new StringBuilder();
            for (int n = 0; n < lines.length; n++) {
                String line = lines[n];
                String match;

                // bgp vpnv4 unicast all neighbors *
                if ((match = getMatch(line, "BGP neighbor is (\\S+),[ ]+remote AS ")) != null) {
                    line = line.replace(match, match+",  vrf -");
                }

                sb.append(line+"\n");
            }
            return sb.toString();
        }
    }


    /**
     * Get data from devices device platform or cached config (deprecated)
     * @param
     * @return Value or "unknown
     * @throws Exception
     */
    protected String getPlatformData(int thr, String leaf) throws Exception {

        // First try devices device platform
        String p = "/ncs:devices/device{"+device_id+"}/platform/" + leaf;
        try {
            if (maapi.exists(thr, p)) {
                return ConfValue.getStringByValue(p, maapi.getElem(thr, p));
            }
        } catch (MaapiException ignore) {
            // Ignore Exception
        }

        // Second try config cached-show version
        if (includeCachedShowVersion) {
            p = confRoot + "cached-show/version/" + leaf;
            try {
                if (maapi.exists(thr, p)) {
                    return ConfValue.getStringByValue(p, maapi.getElem(thr, p));
                }
            } catch (MaapiException ignore) {
                // Ignore Exception
            }
        }

        return "unknown";
    }


    /**
     * Get data police mode setting
     * @param
     * @return Value or "unknown
     */
    private String getIosPolice(NedWorker worker, int thr, boolean cdbLookupOk) {
        String police;

        // (1) Specified in ned-setting cisco-ios api police-format
        if (!policeFormat.equals("auto")) {
            police = policeFormat.replace(" ", "-");
            traceInfo(worker, "iospolice (ned-setting) = " + police);
            return police;
        }

        // (2) Specified in 'tailfned police'
        if (cdbLookupOk) {
            String p = confRoot + "tailfned/police";
            try {
                if (maapi.exists(thr, p)) {
                    police = ConfValue.getStringByValue(p, maapi.getElem(thr, p));
                    traceInfo(worker, "iospolice (tailfned) = " + police);
                    return police;
                }
            } catch (Exception ignore) {
                // Ignore Exception
            }
        }

        // (3) Auto-detect from iosmodel
        police = null;
        if (iosmodel.contains("ME-3400")) {
            police = "cirmode";
        } else if (iosmodel.contains("C3550")) {
            police = "numflat";
        } else if (iosmodel.contains("C3750")) {
            police = "cirflat";
        } else if (getMatch(iosmodel, "(C45(?:0[0-9]))") != null) {
            police = "cirmode-bpsflat";
        } else if (iosmodel.contains("ME-4924")) {
            police = "cirmode-bpsflat";
        } else if (getMatch(iosmodel, "(C65(?:0[3469]|13))") != null) {
            police = "cirflat";
        } else if (iosmodel.contains("12404")) {
            police = "cirflat";
        } else if (iosmodel.contains("Catalyst")) {
            police = "bpsflat";
        } else if (iosmodel.contains("vios-")) {
            this.iosname = "ViOS";
        } else if (iosmodel.contains("vios_l2")) {
            this.iosname = "ViOS";
            police = "cirflat";
        } else if (iosmodel.contains("10000")) {
            police = "numflat";
        }
        if (police != null) {
            traceInfo(worker, "iospolice (auto-detected) = " + police);
        } else {
            police = "cirmode";
            traceInfo(worker, "iospolice (default) = " + police);
        }
        return police;
    }


    /*
     **************************************************************************
     * show
     **************************************************************************
     */

    /**
     * Retrieve running config from device
     * @param
     * @throws Exception
     */
    @Override
    public void show(NedWorker worker, String toptag) throws Exception {

        // Only respond to the first toptag
        if (!toptag.equals("interface")) {
            worker.showCliResponse("");
            return;
        }

        final long start = tick(0);
        if (trace) {
            session.setTracer(worker);
        }
        logInfo(worker, "BEGIN SHOW");

        // Get config from device
        lastGetConfig = getConfig(worker);
        String res = modifyInput(worker, true, -1, lastGetConfig);
        lastTransformedConfig = null;

        // cisco-ios extended-parser
        try {
            if (this.turboParserEnable) {
                traceInfo(worker, "Parsing config using turbo-mode");
                if (parseAndLoadXMLConfigStream(maapi, worker, schema, res)) {
                    res = ""; // Turbo-parser succeeded, clear config to bypass CLI
                }
            } else if (this.robustParserMode) {
                traceInfo(worker, "Parsing config using robust-mode");
                res = filterConfig(res, schema, maapi, worker, null, false).toString();
            }
        } catch (Exception e) {
            logError(worker, "extended-parser "+nedSettings.getString(EXTENDED_PARSER)+" exception ERROR: ", e);
            this.turboParserEnable = false;
            this.robustParserMode = false;
        }

        syncFile = null;
        logInfo(worker, "DONE SHOW "+tickToString(start));
        worker.showCliResponse(res);
    }


    /**
     * Get running-config from device
     * @param
     * @return
     * @throws Exception
     */
    private String getConfig(NedWorker worker) throws Exception {

        // Reset timeout and get current time
        final long start = setReadTimeout(worker);

        // syncFile
        String res = null;
        if (syncFile != null) {
            logInfo(worker, "BEGIN reading config (file = "+syncFile+")");
            res = print_line_exec(worker, "file show " + syncFile);
            if (res.contains("Error: failed to open file")) {
                throw new NedException("failed to sync from file " + syncFile);
            }
            res = res.replace("\r\r\r\n", "\r\n");
            res = res.replace("\r\r\n", "\r\n");
        }

        // scp-transfer
        else if (showRunningConfig.startsWith("scp-transfer")) {
            logInfo(worker, "BEGIN reading config ("+showRunningConfig+")");
            if (nedSettings.getString("proxy/remote-connection") != null) {
                throw new NedException("read/show-running-method scp-transfer is not supported with proxy mode");
            }
            try {
                res = scpGetConfig(worker);
            } catch (Exception e) {
                if (!showRunningConfig.equals("scp-transfer-fallback")) {
                    throw e;
                }
                logInfo(worker, "WARNING: SCP transfer failed '"+e.getMessage()+"' - fallback to show run");
                res = print_line_exec(worker, "show running-config");
            }
        }

        // <command>
        else {
            logInfo(worker, "BEGIN reading config ("+showRunningConfig+")");
            res = print_line_exec(worker, showRunningConfig);
            if (res.contains("Invalid input detected")) {
                throw new NedException("failed to show config using '"+showRunningConfig+"'");
            }
        }

        //
        // Trim running-config
        //
        res = trimConfig(worker, res);

        //
        // NETSIM, don't call additional show commands
        //
        if (isNetsim()) {
            logInfo(worker, "DONE reading config "+tickToString(start));
            return res;
        }


        //
        // Get config from other show commands
        //
        lastTimeout = setReadTimeout(worker);

        // Insert missing 'show boot' config from show boot
        if (haveShowBoot) {
            traceInfo(worker, "reading config - show boot");
            String boot = print_line_exec(worker, "show boot");
            if ((boot = findLine(boot, "BOOT path-list:")) != null) {
                boot = boot.substring(15).trim();
                if (!boot.isEmpty()) {
                    res = res + "boot system " + boot;
                }
            } else {
                traceInfo(worker, "Disabling 'show boot' check");
                haveShowBoot = false;
            }
        }

        // Insert config shown in "show version"
        res = res + getConfigVersion(worker);

        // Insert 'logging console X' shown in "show logging"
        res = getConfigLogging(worker) + res;

        // Insert missing VLAN config from show vlan
        res = res + getConfigVlan(worker, res);

        // Return config
        logInfo(worker, "DONE reading "+tickToString(start));
        return res;
    }


    /**
     * Show logging config
     * @param
     * @return
     * @throws Exception
     */
    private String getConfigLogging(NedWorker worker) throws Exception {

        traceInfo(worker, "reading config - show logging");

        // NOTE: Not supported on older IOS versions [12.2(33)]
        String showbuf = print_line_exec(worker, "show logging xml");
        if (showbuf.contains("Invalid input")) {
            traceInfo(worker, "WARNING: unable to determine logging status due to too old IOS");
            return "";
        }

        String res = "";
        res += getConfigLoggingType(showbuf, "console");
        res += getConfigLoggingType(showbuf, "monitor");
        res += getConfigLoggingType(showbuf, "buffer");
        traceInfo(worker, "transformed <= inserted "+stringQuote(res)+" from 'show logging xml'");
        return "\n" + res;
    }


    /**
     *
     * @param
     * @return
     * @throws Exception
     */
    private String getConfigLoggingType(String showbuf, String type)
        throws Exception {
        String name = type + "-logging";
        String line = findLine(showbuf, "<"+name);
        if (line == null) {
            return "";
        }
        if (line.trim().startsWith("<"+name+">disabled<")) {
            return "";
        }
        Pattern pattern = Pattern.compile("<"+name+" level=\"(\\S+?)\" ");
        Matcher matcher = pattern.matcher(line);
        if (matcher.find()) {
            if (type.equals("buffer")) {
                type = "buffered";
            }
            String logging = "logging " + type + " " + matcher.group(1);
            return logging + "\n";
        }
        return "";
    }


    /**
     *
     * @param
     * @return
     * @throws Exception
     */
    private String getConfigVersion(NedWorker worker) throws Exception {

        traceInfo(worker, "reading config - show version");

        String showbuf = print_line_exec(worker, "show version | include password-recovery");
        if (!showbuf.contains("password-recovery")) {
            return "";
        }
        if (showbuf.contains("enabled")) {
            traceInfo(worker, "transformed <= inserted 'service password-recovery' from 'show version'");
            return "\nservice password-recovery\n";
        }
        if (showbuf.contains("disabled")) {
            traceInfo(worker, "transformed <= inserted 'no service password-recovery' from 'show version'");
            return "\nno service password-recovery\n";
        }

        return "";
    }


    /**
     * Extract vlan config from show vlan
     * @param
     * @return
     * @throws Exception
     */
    private String getConfigVlan(NedWorker worker, String dump) throws Exception {
        String res;
        int i;
        String vtpResult = "\n";
        boolean vtpClient = false;

        if (haveShowVtpStatus) {
            traceInfo(worker, "reading config - show vtp status");

            String vtpStatus = print_line_exec(worker, "show vtp status");
            if (vtpStatus.contains("Invalid input")) {
                traceInfo(worker, "Disabling 'show vtp status' check");
                haveShowVtpStatus = false;
            }

            // Extract VTP "config" from 'show vtp status'
            else {
                // vtp mode
                if ((res = findLine(vtpStatus, "VTP Operating Mode")) != null) {
                    String mode = res.replaceAll("VTP Operating Mode\\s+:\\s+(\\S+)", "$1").trim().toLowerCase();
                    vtpResult += "vtp mode " + mode + "\n";
                    if (mode.equals("client")) {
                        vtpClient = true;
                    }
                }

                // vtp domain
                if ((res = findLine(vtpStatus, "VTP Domain Name")) != null
                    && (i = res.indexOf(':')) > 0) {
                    String value = res.substring(i+1).trim();
                    if (!value.isEmpty()) {
                        vtpResult += "vtp domain " + value + "\n";
                    }
                }

                // vtp version
                if (((res = findLine(vtpStatus, "VTP version running")) != null // 2960 & 7600
                     || (res = findLine(vtpStatus, "VTP Version")) != null) // 4500
                    && (i = res.indexOf(':')) > 0) {
                    String value = res.substring(i+1).trim();
                    if (!value.isEmpty()) {
                        vtpResult += "vtp version " + value + "\n";
                    }
                }

                // vtp pruning
                if ((res = findLine(vtpStatus, "VTP Pruning Mode")) != null) {
                    String value = res.replaceAll("VTP Pruning Mode\\s+:\\s+(\\S+)", "$1").trim();
                    if (value.equals("Enabled")) {
                        vtpResult += "vtp pruning\n";
                    }
                }

                traceInfo(worker, "transformed <= inserted "+stringQuote(vtpResult)+" from 'show vtp status'");
            }
        }

        // If VTP Client, do not add vlan's to config.
        if (vtpClient) {
            traceInfo(worker, "Found VTP Client, do not list vlan(s) using show vlan");
            return vtpResult;
        }

        //
        // Add vlan entries:
        //

        // First try 'show vlan'
        res = "";
        if (haveShowVlan) {
            traceInfo(worker, "reading config - show vlan");
            res = print_line_exec(worker, "show vlan");
            if (res.indexOf("\n----") < 0) {
                traceInfo(worker, "Disabling 'show vlan' check");
                haveShowVlan = false;
            }
        }

        // If that fails, then try 'show vlan-switch'
        if (haveShowVlanSwitch && !haveShowVlan) {
            traceInfo(worker, "reading config - show vlan-switch");
            res = print_line_exec(worker, "show vlan-switch");
            if (res.contains("Invalid input")) {
                traceInfo(worker, "Disabling 'show vlan-switch' check");
                haveShowVlanSwitch = false;
                return vtpResult;
            }
        }

        // No support for either show vlan or show vlan-switch
        if (res.isEmpty() || (!haveShowVlanSwitch && !haveShowVlan)) {
            return vtpResult;
        }

        // Strip all text before first entry
        if ((i = res.indexOf("\n----")) < 0) {
            return vtpResult;
        }
        if ((i = res.indexOf('\n', i+1)) < 0) {
            return vtpResult;
        }
        res = res.substring(i+1);

        // Parse lines, create:
        // vlan #
        //  name <name>
        // !
        //todo: mtu <mtu>
        String[] vlans = res.split("\r\n");
        StringBuilder sb = new StringBuilder();
        for (i = 0; i < vlans.length; i++) {
            if (vlans[i] == null || vlans[i].equals("")) {
                break;
            }
            // Skip multi line entries. Each new starts with a digit
            if (!Character.isDigit(vlans[i].trim().charAt(0))) {
                continue;
            }
            String[] tokens = vlans[i].split(" +");
            if (tokens.length < 3) {
                break;
            }
            int status = vlans[i].indexOf(" active ");
            if (status < 0) {
                continue;
            }
            String vlan = "vlan " + tokens[0];
            if (dump.contains("\n"+vlan+"\r") || dump.contains("\n"+vlan+" \r")) {
                continue;
            }
            sb.append(vlan + "\n");

            // vlan * / name
            String name = vlans[i].substring(tokens[0].length(), status).trim();
            if (!name.isEmpty()
                && !(name.startsWith("VLAN") && name.endsWith(tokens[0]))) { // ignore default names
                sb.append(" name "+name+"\n");
            }

            sb.append("!\n");
        }
        if (sb.length() > 0) {
            traceInfo(worker, "transformed <= inserted "+stringQuote(sb.toString())+" from 'show vlan[-switch]'");
        }

        return vtpResult + sb.toString();
    }


    /**
     *
     * @param
     * @return
     * @throws Exception
     */
    private String scpGetConfig(NedWorker worker) throws Exception {

        final int retryCount = nedSettings.getInt("connection/number-of-retries");
        final int waitTime = nedSettings.getInt("connection/time-between-retry");

        // Connect using SSH
        Connection scpConn = new Connection(ip.getHostAddress(), port);
        for (int retries = retryCount; retries >= 0; retries--) {
            traceInfo(worker, "SCP connecting to " + ip.getHostAddress()
                      +":"+port+" ["+(1+retryCount-retries)+"/"+retryCount+"]");
            try {
                scpConn.connect(null, 0, connectTimeout);
                break;
            } catch (Exception e) {
                if (retries == 0) {
                    throw new NedException("read/show-running-method scp-transfer failed to open SCP connection", e);
                } else {
                    resetTimeout(worker, this.connectTimeout + (waitTime * 1000), 0);
                    sleep(worker, waitTime * (long)1000, true);
                }
            }
        }

        // Authenticate SSH connection
        scpConn.authenticateWithPassword(ruser, pass);
        if (!scpConn.isAuthenticationComplete()) {
            throw new NedException("read/show-running-method scp-transfer isAuthenticationComplete() = false");
        }
        traceInfo(worker, "SCP authenticated");

        // Send SCP get command
        final String file = "running-config";
        traceInfo(worker, "SCP fetching file: " + file);
        ch.ethz.ssh2.Session scpSession = scpConn.openSession();
        scpSession.execCommand("scp -f " + file);

        // Get running-config file
        BufferedReader reader = null;
        StringBuilder sb = new StringBuilder();
        try {
            SCPClient scpClient = new SCPClient(scpConn);
            InputStream in = new SCPInputStream(scpClient, scpSession);
            reader = new BufferedReader(new InputStreamReader(in));
            String line;
            lastTimeout = setReadTimeout(worker);
            while ((line = reader.readLine()) != null) {
                sb.append(line+"\r\n");
                lastTimeout = resetReadTimeout(worker, lastTimeout);
            }
        } catch (Exception e) {
            throw new NedException("SCP download Exception: "+e.getMessage(), e);
        } finally {
            if (reader != null) {
                reader.close();
            }
            if (scpSession != null) {
                scpSession.close();
            }
            //FIXME: close 'in'?
            scpConn.close();
        }

        String res = sb.toString();
        traceInfo(worker, "SCP got "+res.length()+" bytes");

        // Replace single char '^C' with two char ^C
        byte[] bytes = res.getBytes();
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < res.length(); ++i) {
            if (bytes[i] == 3) {
                result.append("^");
                result.append("C");
            } else {
                result.append(res.charAt(i));
            }
        }
        res = result.toString();
        traceVerbose(worker, "\nSHOW_SCP:\n'"+res+"'");
        return res;
    }


    /**
     *
     * @param
     * @return
     */
    private String trimConfig(NedWorker worker, String res) {
        int d;

        // Strip everything before and including the following comments:
        int i = res.indexOf("Current configuration");
        if (i >= 0 && (d = res.indexOf('\n', i)) > 0) {
            res = res.substring(d+1);
        }

        i = res.indexOf("Last configuration change");
        if (i >= 0 && (d = res.indexOf('\n', i)) > 0) {
            res = res.substring(d+1);
        }

        i = res.indexOf("No configuration change since last restart");
        if (i >= 0 && (d = res.indexOf('\n', i)) > 0) {
            res = res.substring(d+1);
        }

        i = res.indexOf("No entries found.");
        if (i >= 0 && (d = res.indexOf('\n', i)) > 0) {
            res = res.substring(d+1);
        }

        i = res.lastIndexOf("NVRAM config last updated"); // multiple entries
        if (i >= 0 && (d = res.indexOf('\n', i)) > 0) {
            res = res.substring(d+1);
        }

        // Strip all text after and including the last 'end'
        i = res.lastIndexOf("\nend");
        if (i >= 0) {
            res = res.substring(0,i);
        }

        // Strip clock-period, device may change it, i.e. not config
        res = stripLineAll(worker, res, "ntp clock-period");

        // Strip console log messages
        res = stripLineAll(worker, res, "%");

        // Strip incomplete comments (e.g. crypto ikev2 profile)
        res = stripLineAll(worker, res, "! Profile incomplete");
        res = stripLineAll(worker, res, "! This profile is incomplete");

        // After reading/stripping device config, trim for consistency
        res = res.trim() + "\r\n";

        return res;
    }


    /**
     * NETSIM line-by-line input transformations
     * @param
     * @return
     * @throws Exception
     */
    private String modifyInputNetsim(NedWorker worker, String res) throws Exception {
        String toptag = "";
        StringBuilder sb = new StringBuilder();
        String[] lines = res.split("\n");
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String ninput = null;

            // Update toptag
            if (isTopExit(line)) {
                toptag = "";
            } else if (Character.isLetter(line.charAt(0))) {
                toptag = trimmed;
            }

            //
            // ! meta-data ::
            // ! exit-meta-data-
            if (trimmed.startsWith("! meta-data :: ") || trimmed.startsWith("! exit-meta-data-")) {
                ninput = "";
            }

            //
            // ' description '
            //
            else if (line.contains(" description ")) {
                ninput = quoteDescription(toptag, line);
            }

            //
            // voice translation-rule * / rule
            //
            else if ("no".equals(rollBackOctal)
                     && toptag.startsWith("voice translation-rule ") && trimmed.startsWith("rule ")) {
                ninput = line.replace("\\", "\\\\");
            }

            //
            // Append (modified) line to buffer
            //
            if (ninput != null && !ninput.equals(lines[n])) {
                if (ninput.isEmpty()) {
                    traceVerbose(worker, "transformed <= stripped '"+trimmed+"'");
                    continue;
                }
                traceVerbose(worker, "transformed <= '"+trimmed+"' to '"+ninput.trim()+"'");
                sb.append(ninput+"\n");
            } else if (lines[n] != null && !lines[n].isEmpty()) {
                sb.append(line+"\n");
            }
        }

        return sb.toString();
    }


    /**
     *
     * @param
     * @return
     * @throws Exception
     */
    private String modifyInput(NedWorker worker, boolean isShow, int toTh, String res) throws Exception {
        final long start0 = tick(0);
        int i;
        String match;
        String[] group;

        logInfo(worker, "BEGIN in-transforming");
        lastTransformedConfig = null;
        res = "\n" + res;

        //
        // Inject config
        //
        res = injectInput(worker, isShow, toTh, res);

        //
        // NETSIM - transform and leave early
        //
        if (isNetsim() && syncFile == null) {
            res = modifyInputNetsim(worker, res);
            logInfo(worker, "DONE in-transforming (NETSIM) "+tickToString(start0));
            traceVerbose(worker, "\nSHOW_AFTER:\n"+res);
            return res;
        }

        //
        // REAL DEVICES BELOW
        //

        //
        // Quote multi-line texts
        //   group(1) = command
        //   group(3) = text to quote
        //   group(4) = additional unquoted append (optional)
        //
        traceInfo(worker, "in-transforming - quoting multi-line texts");
        String[] quoteTexts = {
            // menu <name> title ^C
            // <title text>
            // ^C
            "\n(menu \\S+ title) (\\^C)(.*?)\\^C",

            // aaa authentication fail-message
            "\n(aaa authentication fail-message) (\\^C)(.*?)\\^C",

            //   macro name <name>
            //    xxx
            //    yyy
            //   @
            "\n(macro name \\S+)(\r\n)(.*?\r\n)@",

            // banner <name>
            "\n(banner \\S+) (\\S\\S)(.*?)\\2\\S*?\r",

            // certificate <name>
            //  aaa bbb ccc
            //  ... ... ...
            //  xxx yyy zzz
            // \tquit
            "\n( certificate .*?(\r\n))(.*?\r\n)[ \t]+(quit)"
        };
        for (int n = 0; n < quoteTexts.length; n++) {
            Pattern p = Pattern.compile(quoteTexts[n], Pattern.DOTALL);
            Matcher m = p.matcher(res);
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                String line = m.group(1);
                String quoted = stringQuote(m.group(3));
                if (m.groupCount() == 4) {
                    quoted += ("\r\n" + m.group(4));
                }
                traceVerbose(worker, "transformed <= quoted '"+line+"' text");
                m.appendReplacement(sb, Matcher.quoteReplacement("\n"+line+" "+quoted));
            }
            m.appendTail(sb);
            res = sb.toString();
        }

        //
        // MAIN LINE-BY-LINE LOOP
        //
        traceInfo(worker, "in-transforming - line-by-line patches");
        String toptag = "";
        String[] lines = res.split("\n");
        StringBuilder sbin = new StringBuilder();
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String input = null;

            // Update toptag
            if (isTopExit(line)) {
                toptag = "";
            } else if (Character.isLetter(line.charAt(0))) {
                toptag = trimmed;
            }

            //
            // ' description '
            //
            if (line.contains(" description ")) {
                input = quoteDescription(toptag, line);
            }

            //
            // errdisable
            //
            else if (toptag.startsWith("errdisable")) {
                input = line.replace("channel-misconfig (STP)", "channel-misconfig");
            }

            //
            // interface * / ntp broadcast key <key> destination <address>
            //
            else if (toptag.startsWith("interface ")
                     && trimmed.startsWith("ntp broadcast ") && trimmed.contains(" destination ")) {
                // Move destination address (list key) first.
                input = line.replaceFirst("ntp broadcast (.*?) (destination \\S+)",
                                          "ntp broadcast $2 $1");
            }

            //
            // interface * / service-policy in|out
            //
            else if (toptag.startsWith("interface ")
                     && (line.startsWith("  service-policy in ") || line.startsWith("  service-policy out "))) {
                input = line.replace("  service-policy in ", "  service-policy input ");
                input = input.replace("  service-policy out ", "  service-policy output ");
            }

            //
            // controller SONET *
            //
            else if (toptag.startsWith("controller SONET ")) {
                // controller SONET * / sts-1 x - y mode sts-3c
                input = line.replaceFirst("sts-1 (.*?) mode ", "sts-1 \"$1\" mode ");
            }

            //
            // crypto pki server
            //
            else if (toptag.startsWith("crypto pki server ") && trimmed.startsWith("issuer-name ")) {
                input = line.replaceFirst("issuer-name (.*)", "issuer-name \"$1\"");
            }

            //
            // ip explicit-path
            //
            else if (toptag.startsWith("ip explicit-path")) {
                // insert missing 'index <value>' (not shown in running-config)
                int index = 1;
                for (i = n + 1; i < lines.length; i++, index++) {
                    if (lines[i].startsWith(" index ")) {
                        String indexbuf = getMatch(lines[i], " index (\\d+) ");
                        if (indexbuf != null) {
                            index = Integer.parseInt(indexbuf);
                        }
                    }
                    else if (lines[i].startsWith(" next-address ")
                             || lines[i].startsWith(" exclude-address ")) {
                        String entry = " index " + index + lines[i];
                        traceVerbose(worker, "transformed <= '"+lines[i].trim()+"' to '"+entry.trim());
                        lines[i] = entry;
                    }
                    else {
                        break;
                    }
                }
            }

            //
            // ip access-list unordered standard|extended *
            //
            else if ((line.startsWith("ip access-list extended ") || line.startsWith("ip access-list standard "))
                && getMatch(trimmed, "^ip access-list (?:standard|extended) ("+ipACLunorderedRegex+")\\s*$") != null) {
                input = line.replace("ip access-list ", "ip access-list unordered ");
            }

            //
            // ip access-list - ned-settings cisco-ios api access-list-resequence
            //
            else if (resequenceACL && line.startsWith("ip access-list extended ")) {
                sbin.append(lines[n]+"\n");
                for (n = n + 1; n < lines.length; n++) {
                    if (lines[n].trim().equals("!")) {
                        break;
                    }
                    if (lines[n].trim().startsWith("remark ")) {
                        traceVerbose(worker, "transformed <= stripped '"+lines[n].trim()+"'");
                        continue;
                    }
                    if ((match = getMatch(lines[n], "^( \\d+) .*$")) != null) {
                        String stripped = lines[n].replace(match, "");
                        traceVerbose(worker, "transformed <= '"+lines[n]+"' to '"+stripped+"'");
                        sbin.append(stripped+"\n");
                    } else {
                        sbin.append(lines[n]+"\n");
                    }
                }
            }

            //
            // ipv6 access-list - ned-settings cisco-ios api new-ip-access-list
            //
            else if (newIpACL && line.startsWith("ipv6 access-list ")) {
                // Note: device trims sequence numbers spaced 10 from the previous
                sbin.append(lines[n]+"\n");
                int sequence = 0;
                for (n = n + 1; n < lines.length; n++) {
                    if (lines[n].trim().equals("!")) {
                        break;
                    }
                    if ((match = getMatch(lines[n], "^ sequence (\\d+) ")) != null) {
                        sequence = Integer.parseInt(match);
                        sbin.append(lines[n]+"\n");
                    } else {
                        sequence = sequence + 10;
                        traceVerbose(worker, "transformed <= injected sequence number "+sequence+" in '"+lines[n]+"'");
                        sbin.append(" sequence "+sequence+lines[n]+"\n");
                    }
                }
            }

            //
            // ip source binding *
            //
            else if (trimmed.startsWith("ip source binding ")
                     && (match = getMatch(trimmed, "interface ([A-Za-z]+)\\d+")) != null) {
                String ifname = expandInterfaceName(match);
                input = line.replace("interface "+match, "interface "+ifname);
            }

            //
            // logging discriminator
            //
            else if (toptag.startsWith("logging discriminator")) {
                // logging discriminator * [mnemonics drops|includes *] msg-body drops|includes *
                if (trimmed.contains("mnemonics") && trimmed.contains("msg-body")) {
                    input = line.replaceFirst("mnemonics (\\S+) (.*) msg-body (\\S+) (.*)",
                                              "mnemonics $1 \"$2\" msg-body $3 \"$4\"");
                } else if (trimmed.contains("mnemonics")) {
                    input = line.replaceFirst("mnemonics (\\S+) (.*)", "mnemonics $1 \"$2\"");
                } else {
                    input = line.replaceFirst("msg-body (\\S+) (.*)", "msg-body $1 \"$2\"");
                }
            }

            //
            // username * algorithm-type
            /*
              else if (line.startsWith("username ") && trimmed.contains(" secret 8 ")) {
              // Add back because some NSO does not handle: tailf:ned-ignore-compare-config;
              input = line.replace(" secret 8 ", " algorithm-type sha256 secret 8 ");
              }
            */

            //
            // tailf:cli-range-list-syntax
            //   class-map * / match vlan *
            //
            else if (toptag.startsWith("class-map ") && trimmed.startsWith("match vlan ")) {
                input = line.replaceAll("([0-9])( )([0-9])", "$1,$3");
            }

            //
            // policy-map
            //
            else if (toptag.startsWith("policy-map ")) {

                // policy-map * / class * / random-detect drops 'precedence-based' name
                if (trimmed.startsWith("random-detect aggregate")) {
                    input = line.replace("random-detect aggregate",
                                         "random-detect precedence-based aggregate");
                }
                else if (trimmed.equals("random-detect")) {
                    input = line.replace("random-detect", "random-detect precedence-based");
                }

                // 'policy-map * / class * / police' string replacement
                else if (trimmed.startsWith("police ")) {
                    if (trimmed.startsWith("police cir ")
                        || trimmed.startsWith("police rate ")
                        || trimmed.startsWith("police aggregate ")
                        || trimmed.matches("police (\\d+) bps (\\d+) byte.*")) {
                        // Ignore police cir/rate/aggregate and "bpsflat " bps&byte (Catalyst)
                        sbin.append(lines[n]+"\n");
                        continue;
                    }
                    if (hasPolice("cirmode") || hasPolice("cirflat")) {
                        // Insert missing [cir|bc|be]
                        input = line.replaceAll("police (\\d+) (\\d+) (\\d+)",
                                                "police cir $1 bc $2 be $3");
                        input = input.replaceAll("police (\\d+) (\\d+)",
                                                 "police cir $1 bc $2");
                        input = input.replaceAll("police (\\d+)",
                                                 "police cir $1");
                    }
                }
            }

            //
            // spanning-tree mst configuration / instance * vlan <val>, <val2>
            //
            else if (toptag.startsWith("spanning-tree mst configuration")
                     && findString(" instance [0-9]+ vlan ", line) >= 0) {
                input = line.replace(", ", ",");
            }

            //
            // monitor session * filter vlan *
            // monitor session * source vlan *
            // monitor session * source remote vlan *
            // monitor session * destination remote vlan *
            //
            else if (toptag.startsWith("monitor session ") && trimmed.contains(" vlan ")) {
                input = line.replace(" , ",",").replace(" - ","-");
            }

            //
            // l2tp-class / password encryption aes
            //
            else if (toptag.startsWith("l2tp-class ") && trimmed.equals("password encryption aes")) {
                input = "";
            }

            //
            // crypto keyring / ! Keyring unusable for nonexistent vrf
            //
            else if (toptag.startsWith("crypto keyring ")
                     && trimmed.contains("! Keyring unusable for nonexistent vrf")) {
                input = line.replace("! Keyring unusable for nonexistent vrf", "");
            }

            //
            // parameter-map type regexp * / pattern *
            //
            else if (toptag.startsWith("parameter-map type regex ")
                     && trimmed.startsWith("pattern ")
                     && (match = getMatch(trimmed, "pattern (.*)")) != null) {
                input = line.replace(match, stringQuote(match));
            }

            //
            // router bgp * / address-family ipv4 vrf *
            //
            else if (toptag.startsWith("router bgp ")
                     && (trimmed.startsWith("address-family ipv4 vrf ")
                         || trimmed.startsWith("address-family ipv6 vrf "))) {
                input = line.replaceFirst(" vrf ", " unicast vrf ");
            }

            //
            // track * ipv6 route
            //
            else if (toptag.startsWith("track ") && trimmed.contains(" ipv6 route :: ")) {
                input = line.replace(" :: ", " ::/0 ");
            }

            //
            // et-analytics / inactive-timeout
            //
            else if (toptag.startsWith("et-analytics")
                     && trimmed.startsWith("inactive_timeout ")) {
                input = line.replace("inactive_timeout", "inactive-timeout");
            }

            //
            // snmp-server host * and ned-settings cisco-ios api new-snmp-server-host true
            //
            else if (newSnmpServerHost
                     && toptag.startsWith("snmp-server host ")
                     && (match = getMatch(trimmed, "snmp-server host \\S+ (\\S+)")) != null
                     && (!match.equals("informs") && !match.equals("traps"))) {
                input = line.replace(match, "traps " + match);
            }

            //
            // string-quote strings
            //
            else if (toptag.startsWith("snmp-server ")
                     && (match = getMatch(trimmed, "snmp-server (?:contact|location) (.+)")) != null) {
                input = line.replace(match, stringQuote(match));
            } else if (toptag.startsWith("alias ")
                       && (match = getMatch(trimmed, "alias \\S+ \\S+ (.*)")) != null) {
                input = line.replace(match, stringQuote(match));
            } else if (toptag.startsWith("crypto isakmp key ")
                       && (match = getMatch(trimmed, "crypto isakmp key (\\S+) (?:address|hostname|address ipv6) \\S+")) != null) {
                input = line.replace(match, stringQuote(match));
            } else if (toptag.startsWith("event manager applet ") && trimmed.startsWith("action ")
                       && (match = getMatch(trimmed, "action \\d+ regexp (.*)")) != null) {
                input = line.replace(match, stringQuote(match));
            } else if (toptag.startsWith("crypto pki profile enrollment ")
                       && trimmed.startsWith("authentication command ")
                       && (match = getMatch(trimmed, "authentication command (.*)")) != null) {
                input = line.replace(match, stringQuote(match));
            } else if (toptag.startsWith("utd ")
                       && (match = getMatch(trimmed, "signature id \\d+ comment (.*)")) != null) {
                input = line.replace(match, stringQuote(match));
            } else if (toptag.startsWith("utd ")
                       && (match = getMatch(trimmed, "^(?:content )?text (.*)")) != null) {
                input = line.replace(match, stringQuote(match));
            }
            else if (toptag.startsWith("chat-script ") && trimmed.startsWith("chat-script ")
                     && (match = getMatch(trimmed, "chat-script \\S+ (.+)")) != null) {
                input = line.replace(match, stringQuote(match));
            }
            else if (toptag.startsWith("kron policy-list ") && trimmed.startsWith("cli ")
                     && (match = getMatch(trimmed, "cli (.+)")) != null) {
                input = line.replace(match, stringQuote(match));
            }
            else if (toptag.startsWith("crypto pki trustpoint ") && trimmed.startsWith("subject-name ")
                     && (match = getMatch(trimmed, "subject-name (.+)")) != null) {
                input = line.replace(match, stringQuote(match));
            }

            //
            // password-quote strings
            //
            else if (toptag.startsWith("voice translation-rule ") && trimmed.startsWith("rule ")
                     && (group = getMatches(trimmed, "rule (\\d+) ([/].*[/]) ([/].*[/])")) != null
                     && Integer.parseInt(group[0]) == 3) {
                // voice translation-rule * / rule
                input = " rule "+group[1]+" "+passwordQuote(group[2])+" "+passwordQuote(group[3]);
            }

            //
            // quote password
            //
            else if (trimmed.startsWith("crypto isakmp key 6 ")
                     && (match = getMatch(trimmed, "crypto isakmp key 6 (\\S+) (?:address|hostname|address ipv6) \\S+")) != null) {
                // crypto isakmp key 6
                input = line.replace(match, passwordQuote(match));

            } else if (trimmed.startsWith("authentication-key 6 ")
                       && (match = getMatch(trimmed, "authentication-key 6 (\\S+)")) != null) {
                // router lisp * / authentication-key 6
                input = line.replace(match, passwordQuote(match));

            } else if (trimmed.startsWith("ipv4 etr map-server ")
                       && (match = getMatch(trimmed, "ipv4 etr map-server \\S+ key 6 (\\S+)")) != null) {
                // router lisp * / ipv4 etr map-server
                input = line.replace(match, passwordQuote(match));

            } else if (toptag.startsWith("crypto ") && trimmed.startsWith("pre-shared-key ")
                       && (match = getMatch(trimmed, "pre-shared-key(?: local| remote)? 6 (\\S+)")) != null) {
                // crypto ikev2 keyring / peer * / pre-shared-key
                input = line.replace(match, passwordQuote(match));

            } else if (toptag.startsWith("crypto ") && trimmed.startsWith("aaa authorization group ")
                       && (match = getMatch(trimmed, "aaa authorization group (?:psk|eap) list \\S+ password 6 (\\S+)")) != null) {
                // crypto ikev2 profile * / aaa authorization group
                input = line.replace(match, passwordQuote(match));

            } else if (toptag.startsWith("crypto ") && trimmed.startsWith("authentication ")
                       && (match = getMatch(trimmed, "authentication (?:local|remote) pre-share key 6 (\\S+)")) != null) {
                // crypto ikev2 profile * / authentication
                input = line.replace(match, passwordQuote(match));

            } else if (toptag.startsWith("crypto isakmp client configuration group")
                       && (match = getMatch(trimmed, "\\s+key 6 (\\S+)")) != null) {
                // crypto isakmp client configuration group * /
                input = line.replace(match, passwordQuote(match));

            } else if (toptag.startsWith("crypto keyring ") && trimmed.startsWith("pre-shared-key address ")
                       && (match = getMatch(trimmed, "pre-shared-key address \\S+(?: \\S+)? key 6 (\\S+)")) != null) {
                // crypto keyring * / pre-shared-key address
                input = line.replace(match, passwordQuote(match));
            }
            else if (toptag.startsWith("router bgp ")
                     && (match = getMatch(trimmed, "neighbor \\S+ password(?: [0-7])? (.*)")) != null) {
                // router bgp * / neighbor * password *
                input = line.replace(match, passwordQuote(match));
            }

            //
            // transform single lines
            //
            else if (trimmed.startsWith("ip domain-name")) {
                input = line.replace("ip domain-name", "ip domain name");
            } else if (trimmed.startsWith("ip domain-list")) {
                input = line.replace("ip domain-list", "ip domain list");
            } else if (trimmed.startsWith("no ip domain-lookup")) {
                input = line.replace("no ip domain-lookup", "no ip domain lookup");
            } else if (trimmed.equals("line con 0")) {
                input = "line console 0";
            } else if (trimmed.startsWith("aaa authorization ")) {
                input = line.replaceAll("aaa authorization (.*)local if-authenticated",
                                        "aaa authorization $1if-authenticated local");
            }

            //
            // transform no-list lists/leaves
            //
            if (trimmed.startsWith("no ip forward-protocol udp ")) {
                input = line.replaceAll("no ip forward-protocol udp (\\S+)",
                                        "ip forward-protocol udp $1 disabled");
            } else if (trimmed.startsWith("no cable cm-status enable ")) {
                input = line.replace("no cable cm-status enable ",
                                     "cable cm-status enable no-list ");
            } else if (trimmed.startsWith("no passive-interface ")) {
                input = line.replace("no passive-interface ",
                                     "disable passive-interface ");
            } else if (trimmed.startsWith("no network-clock-participate wic ")) {
                input = line.replace("no network-clock-participate wic ",
                                     "network-clock-participate wic wic-disabled ");
            } else if (trimmed.startsWith("no wrr-queue random-detect ")) {
                input = line.replace("no wrr-queue random-detect ",
                                     "no-list wrr-queue random-detect ");
            } else if (trimmed.startsWith("no rcv-queue random-detect ")) {
                input = line.replace("no rcv-queue random-detect ",
                                     "no-list rcv-queue random-detect ");
            } else if (trimmed.startsWith("no spanning-tree vlan ")) {
                input = line.replace("no spanning-tree vlan ",
                                     "spanning-tree vlan no-list ");
            } else if (trimmed.startsWith("no mac-address-table learning vlan ")) {
                input = line.replace("no mac-address-table learning vlan ",
                                     "mac-address-table learning vlan no-list ");
            } else if (trimmed.startsWith("no ip igmp snooping vlan ")) {
                input = line.replace("no ip igmp snooping vlan ",
                                     "ip igmp snooping vlan no-list ");
            } else if (trimmed.startsWith("no ip next-hop-self eigrp ")) {
                input = line.replace("no ip next-hop-self eigrp ",
                                     "ip next-hop-self eigrp no-list ");
            } else if (trimmed.startsWith("no ip split-horizon eigrp ")) {
                input = line.replace("no ip split-horizon eigrp ",
                                     "ip split-horizon eigrp no-list ");
            } else if (toptag.startsWith("parameter-map type ") && trimmed.startsWith("no application-inspect ")) {
                input = line.replace("no application-inspect ",
                                     "application-inspect no-list ");
            }

            //
            // strip single lines
            //
            else if (trimmed.equals("boot-start-marker") || trimmed.equals("boot-end-marker")) {
                lines[n] = ""; // silent
            } else if (trimmed.startsWith("radius-server source-ports ")) {
                input = "";
            } else if (trimmed.startsWith("license udi")) {
                input = ""; // not config
            } else if (trimmed.startsWith("! Incomplete")) {
                input = ""; // comments
            } else if (toptag.equals("ip msdp cache-sa-state")) {
                input = ""; // config? (can't be disabled)
            }

            //
            // Convert space to comma for range-list-syntax leaf-list's
            //
            if (input == null) {
                String[] spaceToComma = {
                    // Fix cable rf-channels channel-list x-y z bandwidth-percent
                    // Fix cable rf-channels controller ? channel-list x-y z bandwidth-percent
                    " channel-list (.+) bandwidth-percent",
                    " downstream sg-channel (.+) profile \\S+",

                    " downstream sg-channel (.+) rf-bandwidth-percent \\d+",
                    " downstream sg-channel .+ profile \\S+ upstream (.+)"
                };
                for (int j = 0; j < spaceToComma.length; j++) {
                    Pattern p = Pattern.compile(spaceToComma[j]);
                    Matcher m = p.matcher(line);
                    if (m.find()) {
                        if (input == null) {
                            input = line;
                        }
                        String replacement = m.group(1).replace(" ", ","); // type leaf-list
                        if (j >= 2) {
                            replacement = "\"" + m.group(1) + "\""; // type string
                        }
                        input = input.substring(0,m.start(1))+replacement+input.substring(m.end(1));
                    }
                }
            }

            //
            // Transform lines[n] -> XXX
            //
            if (input != null && !input.equals(lines[n])) {
                if (input.isEmpty()) {
                    traceVerbose(worker, "transformed <= stripped '"+trimmed+"'");
                    continue;
                }
                traceVerbose(worker, "transformed <= '"+trimmed+"' to '"+input.trim()+"'");
                sbin.append(input+"\n");
            } else if (lines[n] != null && !lines[n].isEmpty()) {
                sbin.append(lines[n]+"\n");
            }

        } // for (line-by-line)
        res = sbin.toString();


        //
        // Update secrets - replace (unchanged) encrypted secrets with cleartext
        //
        traceInfo(worker, "in-transforming - updating secrets");
        res = secrets.update(worker, res, false);


        //
        // APPEND TRANSFORMATIONS (may add, delete or reorder lines)
        //
        traceInfo(worker, "in-transforming - appending config");
        lines = res.split("\n");
        sbin = new StringBuilder();
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String nexttrim = (n + 1 < lines.length) ? lines[n+1].trim() : "";
            boolean split = false;

            // Update toptag
            if (isTopExit(line)) {
                toptag = "";
            } else if (Character.isLetter(line.charAt(0))) {
                toptag = trimmed; // Strip '\r'
            }

            // autoInterfaceSwitchportStatus = true
            if (autoInterfaceSwitchportStatus && line.startsWith("interface ")) {
                sbin.append(line+"\n");
                if (trimmed.contains("Ethernet") || trimmed.contains("Port-channel")) {
                    res = print_line_exec(worker,"show " + trimmed + " switchport | i Switchport");
                    if (res.contains("Switchport: Enabled")) {
                        sbin.append(" switchport\n");
                    } else if (res.contains("Switchport: Disabled")) {
                        sbin.append(" no switchport\n");
                    }
                }
                continue;
            }

            //
            // interface * / switchport trunk allowed vlan
            //
            else if (toptag.startsWith("interface ")
                     && trimmed.startsWith("switchport trunk allowed vlan ")
                     && nexttrim.startsWith("switchport trunk allowed vlan add ")) {
                traceVerbose(worker, "transformed <= joined '"+toptag+"' switchport trunk allowed vlan entries");
                String vlans = " " + trimmed;
                for (n = n + 1; n < lines.length; n++) {
                    trimmed = lines[n].trim();
                    if ((match = getMatch(trimmed, "switchport trunk allowed vlan add (.*)")) == null) {
                        break;
                    }
                    vlans += ("," + match);
                }
                sbin.append(vlans + "\n");
                // fall through to add break line
            }

            //
            // interface * / ipv6 nd inspection vlan
            //
            else if (toptag.startsWith("interface ")
                     && trimmed.startsWith("ipv6 nd inspection vlan ")
                     && nexttrim.startsWith("ipv6 nd inspection vlan add ")) {
                traceVerbose(worker, "transformed <= joined '"+toptag+"' ipv6 nd inspection vlan entries");
                String vlans = " " + trimmed;
                for (n = n + 1; n < lines.length; n++) {
                    trimmed = lines[n].trim();
                    if ((match = getMatch(trimmed, "ipv6 nd inspection vlan add (.*)")) == null) {
                        break;
                    }
                    vlans += ("," + match);
                }
                sbin.append(vlans + "\n");
                // fall through to add break line
            }

            //
            // route-map * / set extcommunity rt
            //
            else if (toptag.startsWith("route-map ")
                     && trimmed.matches("^set extcommunity rt [0-9: ]+ additive$")) {
                // Join 'set extcommunity rt ... additive' lines, split by device (e.g. asr1k)
                traceVerbose(worker, "transformed <= joined '"+toptag+"' set extcommunity rt additive entries");
                sbin.append(" set extcommunity rt");
                for (; n < lines.length; n++) {
                    trimmed = lines[n].trim();
                    if ((match = getMatch(trimmed, "set extcommunity rt( [0-9: ]+) additive$")) == null) {
                        break;
                    }
                    sbin.append(match);
                }
                sbin.append(" additive\n");
                continue;
            }

            //
            // route-map * / match interface
            //
            else if (toptag.startsWith("route-map ")
                     && trimmed.startsWith("match interface ")
                     && nexttrim.startsWith("match interface ")) {
                // Join lines
                traceVerbose(worker, "transformed <= joined '"+toptag+"' match interface entries");
                sbin.append(" "+trimmed);
                for (n = n + 1; n < lines.length; n++) {
                    trimmed = lines[n].trim();
                    if ((match = getMatch(trimmed, "match interface( .+)")) == null) {
                        break;
                    }
                    sbin.append(match);
                }
                sbin.append("\n");
                continue;
            }

            //
            // aaa accounting
            //
            else if (line.startsWith("aaa accounting ") && nexttrim.startsWith("action-type")) {
                traceVerbose(worker, "transformed <= compacted '"+trimmed+"'");
                // action-type
                line = trimmed + nexttrim.replace("action-type", "");
                nexttrim = (++n + 1 < lines.length) ? lines[n+1].trim() : "";
                // optional broadcast
                if (nexttrim.equals("broadcast")) {
                    line += " broadcast";
                    nexttrim = (++n + 1 < lines.length) ? lines[n+1].trim() : "";
                }
                // optional group
                if (nexttrim.startsWith("group ")) {
                    line += (" " + nexttrim);
                    n++;
                }
                sbin.append(line + "\n");
                continue;
            }

            //
            // call-home * / profile * / [no ]active
            // call-home * / profile * / [no ]reporting smart-call-home-data
            //
            else if (toptag.startsWith("call-home") && line.startsWith(" profile ")) {
                sbin.append(line+"\n");
                String callprof = print_line_exec(worker, "show call-home "+trimmed);
                if (!callprof.contains("Invalid input")) {
                    if (callprof.contains("Profile status: ACTIVE")) {
                        sbin.append("  active\n");
                    } else {
                        sbin.append("  no active\n");
                    }
                    if (callprof.contains("Smart Licensing")) {
                        sbin.append("  reporting smart-licensing-data\n");
                    } else {
                        sbin.append("  no reporting smart-licensing-data\n");
                    }
                }
                continue;
            }

            //
            // monitor session * source vlan *
            //
            else if (toptag.startsWith("monitor session ")
                     && trimmed.contains(" source vlan ")
                     && (group = getMatches(trimmed, "((?:monitor session \\d+)? source vlan )(\\S+)( \\S+)?")) != null) {
                String suffix = group[3] != null ? group[3] : "";
                String[] vlans = group[2].split(",");
                for (i = 0; i < vlans.length; i++) {
                    String[] entry;
                    if ((entry = getMatches(vlans[i], "(\\d+)-(\\d+)")) != null) {
                        split = true;
                        int start = Integer.parseInt(entry[1]);
                        int end = Integer.parseInt(entry[2]);
                        for (int j = start; j <= end; j++) {
                            sbin.append(group[1] + j + suffix + "\n");
                        }
                    } else {
                        sbin.append(group[1] + vlans[i] + suffix + "\n");
                    }
                }
                if (split || vlans.length > 1) {
                    traceVerbose(worker, "transformed <= split '"+trimmed+"'");
                }
                continue;
            }

            //
            // monitor session * source|destination interface *
            // monitor session * type local / source|destination interface *
            // monitor session * type erspan-source / source interface *
            //
            else if (toptag.startsWith("monitor session ")
                     && (group = getMatches(line, "((?:monitor session \\d+)? (?:source|destination) interface) (.*)")) != null) {
                String suffix;
                String interfaceString = group[2];
                if ((suffix = getMatch(interfaceString, "( rx| tx| both|(?: encapsulation .*)|(?: ingress vlan .*))")) != null) {
                    interfaceString = interfaceString.replace(suffix, "");
                } else {
                    suffix = "";
                }
                String[] interfaces = interfaceString.split(" , ");
                for (i = 0; i < interfaces.length; i++) {
                    String[] entry;
                    if ((entry = getMatches(interfaces[i].trim(), "(\\S+)/(\\d+) - (\\d+)")) != null) {
                        split = true;
                        int start = Integer.parseInt(entry[2]);
                        int end = Integer.parseInt(entry[3]);
                        for (int j = start; j <= end; j++) {
                            sbin.append(group[1] + " " + entry[1] + "/" + j + suffix + "\n");
                        }
                    } else {
                        sbin.append(group[1] + " " + interfaces[i].trim() + suffix + "\n");
                    }
                }
                if (split || interfaces.length > 1) {
                    traceVerbose(worker, "transformed <= split '"+trimmed+"'");
                }
                continue;
            }

            // monitor session * filter address-type
            else if (toptag.startsWith("monitor session ") && trimmed.contains("filter address-type")
                     && !trimmed.endsWith(" rx") && !trimmed.endsWith(" tx")) {
                sbin.append(trimmed+" rx\n");
                sbin.append(trimmed+" tx\n");
                continue;
            }

            //
            // qos map dscp policed * to dscp
            // qos map dscp * to tx-queue
            // qos map dscp * to cos
            // qos map cos * to dscp
            //
            else if (trimmed.startsWith("qos map dscp policed ")) {
                String[] tokens = trimmed.split(" +");
                split = appendLines(sbin, tokens, 4, 3, 1);
            }
            else if (trimmed.startsWith("qos map ") && trimmed.contains(" to ")) {
                String[] tokens = trimmed.split(" +");
                split = appendLines(sbin, tokens, 3, 3, 1);
            }

            //
            // mls qos map policed-dscp *
            //
            else if (trimmed.startsWith("mls qos map policed-dscp ") && trimmed.contains(" to ")) {
                String[] tokens = trimmed.split(" +");
                split = appendLines(sbin, tokens, 4, 2, 1);
            }

            //
            // ip name-server [vrf <vrf>] <address 1> .. [address N]
            //
            if (trimmed.startsWith("ip name-server ")) {
                String[] tokens = trimmed.split(" +");
                if (tokens[2].equals("vrf")) {
                    split = appendLines(sbin, tokens, 4, 0, 1);
                } else {
                    split = appendLines(sbin, tokens, 2, 0, 1);
                }
            }

            //
            // router ospf * / discard-route
            //
            else if (toptag.startsWith("router ospf ") && trimmed.equals("no discard-route")) {
                sbin.append(" discard-route external disabled\n");
                sbin.append(" discard-route internal disabled\n");
                continue;
            } else if (toptag.startsWith("router ospf ") && trimmed.equals("no discard-route external")) {
                sbin.append(" discard-route external disabled\n");
                continue;
            } else if (toptag.startsWith("router ospf ") && trimmed.equals("no discard-route internal")) {
                sbin.append(" discard-route internal disabled\n");
                continue;
            }

            //
            // table-map *
            //
            else if (toptag.startsWith("table-map ") && trimmed.startsWith("map from ")) {
                String[] tokens = trimmed.split(" +");
                split = appendLines(sbin, tokens, 2, 2, 1);
            }

            //
            // line / exec-timeout 10 0
            //
            else if (toptag.startsWith("line ") && line.startsWith("line ")) {
                // Inject default exec-timeout value
                sbin.append(lines[n]+"\n");
                traceVerbose(worker, "transformed <= injected: 'exec-timeout 10 0' first in "+trimmed);
                sbin.append(" exec-timeout 10 0\n");
                continue;
            }

            //
            // Log or add if not split
            //
            if (split) {
                traceVerbose(worker, "transformed <= split '"+trimmed+"'");
            } else {
                sbin.append(lines[n]+"\n");
            }
        }
        res = sbin.toString();


        //
        // SINGLE BUFFER TRANSFORMATIONS:
        //

        //
        // Split line ranges into multiple single lines with config, e.g. line 0/2/15 0/3/0
        //
        Pattern p = Pattern.compile("\n(line (\\d+)/(\\d+)/(\\d+) \\2/(\\d+)/(\\d+))\r(.*?)?(?=\nline |\n!)", Pattern.DOTALL);
        Matcher m = p.matcher(res);
        StringBuffer sb = new StringBuffer();
        boolean logonce = true;
        while (m.find()) {
            if (logonce) {
                traceInfo(worker, "in-transforming - splitting range terminal lines");
                logonce = false;
            }
            String slot = m.group(2);
            int subslotStart = Integer.parseInt(m.group(3));
            int portStart = Integer.parseInt(m.group(4));
            int subslotEnd = Integer.parseInt(m.group(5));
            int portEnd = Integer.parseInt(m.group(6));
            String config = "";
            if (m.groupCount() == 7) {
                config = m.group(7);
            }
            String buf = "";
            int num = 0;
            if (subslotStart == subslotEnd) {
                // Single subslot, portStart and portEnd on same line
                for (int port = portStart; port <= portEnd; port++, num++) {
                    buf += "\nline "+slot+"/"+subslotStart+"/"+port+"\r"+config;
                }
            } else {
                // Range of multiple subslots, need to look up min & max lines
                for (int s = subslotStart; s <= subslotEnd; s++) {
                    String root = slot+"/"+s+"/";
                    String linebuf = print_line_exec(worker, "show line | i "+root);
                    if (!linebuf.contains(root)) {
                        traceInfo(worker, "ERROR: failed to look up line "+root);
                        break;
                    }
                    lines = linebuf.trim().split("\n");
                    // Get start
                    if ((match = getMatch(lines[0], root+"(\\d+) ")) == null) {
                        break;
                    }
                    int start = Integer.parseInt(match);
                    if (s == subslotStart) {
                        start = Math.max(start, portStart);
                    }
                    // Get end
                    if ((match = getMatch(lines[lines.length-1], root+"(\\d+) ")) == null) {
                        break;
                    }
                    int end = Integer.parseInt(match);
                    if (s == subslotEnd) {
                        end = Math.min(end, portEnd);
                    }
                    // Create single line
                    for (int port = start; port <= end; port++, num++) {
                        buf += "\nline "+root+port+"\r"+config;
                    }
                }
            }
            if (num > 0) {
                traceVerbose(worker, "transformed <= split '"+m.group(1)+"' into "+num+" lines");
                m.appendReplacement(sb, buf);
            } else {
                traceInfo(worker, "ERROR: failed to split up terminal line "+stringQuote(m.group(0)));
                m.appendReplacement(sb, m.group(0));
            }
        }
        m.appendTail(sb);
        res = sb.toString();

        //
        // Dirty trick to force top mode before each interface config
        //
        res = res.replace("\ninterface ", "\nxxyyzztop 0\ninterface ");

        //
        // DONE
        //
        logInfo(worker, "DONE in-transforming "+tickToString(start0));
        if (syncFile != null) {
            traceVerbose(worker, "\nSHOW_AFTER_FILE:\n"+res);
        } else {
            traceVerbose(worker, "\nSHOW_AFTER:\n"+res);
        }

        // Respond with updated show buffer
        return res;
    }


    /**
     * Expand abbrevitated interface name
     * @param
     * @return Full interface name
     */
    private String expandInterfaceName(String abbrevName) {
        String[][] ifNameMap = {
            { "Gi", "GigabitEthernet" },
            { "Fa", "FastEthernet" },
            { "Et", "Ethernet" },
            { "Te", "TenGigabitEthernet" },
            { "Po", "Port-Channel" },
            { "Vl", "Vlan" }
        };
        for (int i = 0; i < ifNameMap.length; i++) {
            if (abbrevName.equals(ifNameMap[i][0])) {
                return ifNameMap[i][1];
            }
        }
        return abbrevName;
    }


    /**
     * Quote description string
     * @param
     * @return Quoted description
     */
    private String quoteDescription(String toptag, String line) {

        // Ignore quoting the following service-insertion descriptions
        if (toptag.startsWith("service-insertion ")) {
            return line;
        }

        int i = line.indexOf(" description ");

        // Special case for: ip msdp description <hostname> <description>
        int offset = 13;
        if (line.trim().startsWith("ip msdp description ")) {
            int space = line.indexOf(' ', i + offset);
            if (space > 0) {
                offset = space - i + 1;
            }
        }

        // Quote description string
        String desc = stringQuote(line.substring(i+offset).trim());
        return line.substring(0,i+offset) + desc;
    }


    /**
     *
     * @param x = max values per line
     * @return
     */
    private boolean appendLines(StringBuilder buffer, String[] tokens, int start, int end, int x) {
        if (tokens.length - start <= x) {
            return false;
        }
        int n;
        int length = tokens.length - end;

        String prefix = tokens[0];
        for (n = 1; n < start; n++) {
            prefix += " " + tokens[n];
        }

        String postfix = "";
        for (n = length; n < tokens.length; n++) {
            postfix += " " + tokens[n];
        }

        for (n = start; n < length; n = n + x) {
            String values = "";
            for (int j = n; (j < n + x) && (j < length); j++) {
                values += " " + tokens[j];
            }
            buffer.append(prefix + values + postfix + "\n");
        }
        return true;
    }


    /**
     * Inject config in input
     * @param
     * @return
     * @throws Exception
     */
    private String injectInput(NedWorker worker, boolean isShow, int toTh, String res)
        throws Exception {
        String match;
        int i, n;
        long start = tick(0);

        logVerbose(worker, "BEGIN in-injecting");

        // Start transaction if none open
        int th = toTh;
        if (th == -1) {
            setUserSession();
            th = maapi.startTrans(Conf.DB_RUNNING, Conf.MODE_READ);
        }

        //
        // tailfned api access-list-method
        //
        if (isDevice()) {
            if (newIpACL) {
                traceInfo(worker, "transformed <= inserted tailfned api new-ip-access-list");
                res = "\ntailfned api new-ip-access-list\n" + res;
            }
            if (resequenceACL) {
                traceInfo(worker, "transformed <= inserted tailfned api resequence-access-list");
                res = "\ntailfned api resequence-access-list\n" + res;
            }
            if (newSnmpServerHost) {
                traceInfo(worker, "transformed <= inserted tailfned api new-snmp-server-host");
                res = "\ntailfned api new-snmp-server-host\n" + res;
            }
        }

        //
        // tailfned police
        //
        String police = getIosPolice(worker, th, isShow);
        traceInfo(worker, "transformed <= inserted tailfned police "+police);
        if ((match = getMatch(res, "(tailfned police .*)")) != null) {
            res = res.replace(match, "tailfned police "+police);
        } else {
            res = "\ntailfned police "+police+"\n" + res;
        }

        //
        // read/replace-config ned-setting - inject/replace in running-config
        //
        if (replaceConfig.size() > 0) {
            traceInfo(worker, "in-transforming - replace-config ned-setting");
            for (n = 0; n < replaceConfig.size(); n++) {
                String[] entry = replaceConfig.get(n);
                if (entry[3] != null &&
                    ((isShow && entry[3].equals("trans-id-only")) ||
                     (!isShow && entry[3].equals("config-only")))) {
                    continue;
                }
                String regexp = entry[1];
                String replacement = entry[2];
                try {
                    Pattern p = Pattern.compile(regexp+"(?:[\r])?", Pattern.DOTALL);
                    Matcher m = p.matcher(res);
                    StringBuffer sb = new StringBuffer();
                    while (m.find()) {
                        traceInfo(worker, "transformed <= replaced "+stringQuote(m.group(0))
                                  +" with " + matcherToString(m, replacement));
                        m.appendReplacement(sb, replacement);
                    }
                    m.appendTail(sb);
                    res = sb.toString();
                } catch (Exception e) {
                    logError(worker, "ERROR in read/replace-config '"+entry[0]+"' regexp="
                             +stringQuote(regexp)+" replacement="+stringQuote(replacement), e);
                }
            }
        }

        //
        // Not isShow early exit
        //
        if (!isShow) {
            logVerbose(worker, "DONE in-injecting (checksum only) "+tickToString(start));
            if (toTh == -1) {
                maapi.finishTrans(th);
            }
            return res;
        }

        //
        // Insert cached-show 'config'
        //
        res = res + "\n";
        if (includeCachedShowVersion) {
            res += "cached-show version version " + iosversion + "\n";
            if (!xeversion.isEmpty()) {
                res += "cached-show version xe-version " + xeversion + "\n";
            }
            res += "cached-show version model " + iosmodel + "\n";
            if (licenseLevel != null) {
                res += "cached-show version license level " + licenseLevel + "\n";
            }
            if (licenseType != null) {
                res += "cached-show version license type " + licenseType + "\n";
            }
        }
        if (includeCachedShowInventory) {
            for (i = 0; i < cachedShowInventory.size(); i++) {
                String[] entry = cachedShowInventory.get(i);
                res += "cached-show inventory name " + entry[0];
                if (!entry[1].trim().isEmpty()) {
                    res += " sn " + entry[1];
                }
                res += "\n";
            }
        }

        //
        // read/inject-config ned-setting - inject config in running-config
        //
        if (injectConfig.size() > 0) {
            traceInfo(worker, "in-transforming - injecting config");
            for (n = injectConfig.size()-1; n >= 0; n--) {
                String[] entry = injectConfig.get(n);
                if (entry[1] == null) {
                    // no regexp given
                    if (entry[3] != null && entry[3].startsWith("after")) {
                        // inject last
                        traceVerbose(worker, "transformed <= injected: "+stringQuote(entry[2])+" last in config");
                        res = res + entry[2] + "\n";
                    } else {
                        // inject first [default]
                        traceVerbose(worker, "transformed <= injected: "+stringQuote(entry[2])+" first in config");
                        res = entry[2] + "\n" + res;
                    }
                }
                else {
                    // regexp inject (default to 'after-each')
                    if (entry[3] == null) {
                        entry[3] = "after-each";
                    }
                    res = injectData(worker, res, entry, "<=");
                }
            }
        }

        //
        // Insert inject interface config first in matching interface(s)
        //
        if (interfaceConfig.size() > 0) {
            traceInfo(worker, "in-transforming - injecting interface config");
            Pattern p = Pattern.compile("\ninterface (\\S+)");
            Matcher m = p.matcher(res);
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                String ifname = m.group(1);
                String inject = "";
                for (n = 0; n < interfaceConfig.size(); n++) {
                    String[] entry = interfaceConfig.get(n);
                    if (findString(entry[0], ifname) >= 0) {
                        inject += ("\r\n " + entry[1]);
                    }
                }
                if (!inject.isEmpty()) {
                    traceVerbose(worker, "transformed <= injected: "+stringQuote(inject)+ " first in interface "+ifname);
                }
                m.appendReplacement(sb, m.group(0) + inject);
            }
            m.appendTail(sb);
            res = sb.toString();
        }

        //
        // NETSIM early exit
        //
        if (isNetsim()) {
            logVerbose(worker, "DONE in-injecting (NETSIM) "+tickToString(start));
            if (toTh == -1) {
                maapi.finishTrans(th);
            }
            return res;
        }

        //
        // DEFAULTS - inject hidden defaults values set by NSO
        //
        traceInfo(worker, "in-transforming - injecting default values");
        res = defaults.inject(session, worker, res);

        //
        // Inject with CDB lookups
        //

        try {
            // Insert missing 'snmp-server ... v3 ...' config from show snmp user
            // WARNING: Can't inject from getTransId() with commit queues.
            res = res + injectSnmpUser(worker, th);

            // Inject from CDB:
            //  key config-key password-encrypt
            //  cts credentials id * password
            res = injectCachedExec(worker, res, th);
        } finally {
            if (toTh == -1) {
                maapi.finishTrans(th);
            }
        }

        // Return config
        logVerbose(worker, "DONE in-injecting "+tickToString(start));
        return res;
    }


    /**
     * Inject config in CDB not shown on device in show run to avoid diff
     * @param
     * @return
     */
    private String injectCachedExec(NedWorker worker, String res, int th) {

        //
        // key config-key password-encrypt
        //
        ConfValue val;
        try {
            val = maapi.safeGetElem(th, confRoot + "key/config-key/password-encrypt");
            if (val != null) {
                String password = val.toString();
                traceInfo(worker, "SECRETS - transformed <= injected 'key config-key password-encrypt "+password+"'");
                res = "key config-key password-encrypt " + password + "\n" + res;
            }
        } catch (Exception ignore) {
            // Ignore Exception
        }

        //
        //  cts credentials id * password
        //
        try {
            val = maapi.safeGetElem(th, new ConfPath(confRoot + "cts/credentials/id"));
            if (val != null) {
                String id = val.toString();
                val = maapi.safeGetElem(th, new ConfPath(confRoot + "cts/credentials/password"));
                if (val != null) {
                    String password = val.toString();
                    traceInfo(worker, "transformed <= injected 'cts credentials id "+id+" password <HIDDEN>'");
                    res = "cts credentials id "+id+" password "+password + "\n" + res;
                }
            }
        } catch (Exception ignore) {
            // Ignore Exception
        }

        return res;
    }


    /**
     *
     * @param
     * @return
     * @throws Exception
     */
    private String injectSnmpUser(NedWorker worker, int th)
        throws Exception {
        String res;
        String result = "\n";
        int b, e;
        ConfValue val;
        ConfPath path;

        if (!haveShowSnmpUser || syncFile != null) {
            return "";
        }

        //
        // Get snmp user info
        //
        traceInfo(worker, "reading config - show snmp user");
        res = print_line_exec(worker, "show snmp user");
        if (res.contains("Invalid input")) {
            traceInfo(worker, "Disabling 'show snmp user' check");
            haveShowSnmpUser = false;
            return "";
        }
        if (res.contains("SNMP agent not enabled")) {
            return "";
        }

        //
        // Parse output and inject passwords from CDB
        //
        try {
            b = res.indexOf("\nUser name: ");
            if (b < 0) {
                return "";
            }

            while (b >= 0) {
                String name = getString(res, b+12);

                e = res.indexOf("\nAuthentication Protocol: ", b);
                if (e < 0) {
                    break;
                }
                String auth = getString(res, e+26).toLowerCase();

                e = res.indexOf("\nPrivacy Protocol: ", b);
                if (e < 0) {
                    break;
                }
                String priv = getString(res, e+19).toLowerCase().trim();
                if (priv.indexOf("aes") == 0) {
                    priv = "aes " + priv.substring(3);
                }

                int end = res.indexOf("\nGroup-name: ", b);
                if (end < 0) {
                    break;
                }
                String group = getString(res, end+13);

                // Get access list info
                String acl = "";
                e = res.indexOf("IPv6 access-list: ", b);
                if (e > 0 && e < end) {
                    acl = "ipv6 " + getString(res, e+18);
                } else {
                    e = res.indexOf("access-list: ", b);
                    if (e > 0 && e < end) {
                        acl = getString(res, e+13);
                    }
                }

                // Begin making entry
                result = result + "\nsnmp-server user "+name+" "+group+" v3";

                // Add optional 'auth' params
                if (!auth.equals("none")) {
                    String authPw = "NOT-SET-IN-NCS";
                    path = new ConfPath(confRoot+"snmp-server/user{%s}/auth-password", name);
                    if ((val = maapi.safeGetElem(th, path)) != null) {
                        authPw = val.toString();
                    }
                    result = result + " auth " + auth + " " +authPw;
                }

                // Add optional 'priv' params
                if (!priv.equals("none")) {
                    String privPw = "NOT-SET-IN-NCS";
                    path = new ConfPath(confRoot+"snmp-server/user{%s}/priv-password", name);
                    if ((val = maapi.safeGetElem(th, path)) != null) {
                        privPw = val.toString();
                    }
                    result = result + " priv " + priv + " " + privPw;
                }

                // Add optional 'access' params
                if (!acl.isEmpty()) {
                    result = result + " access " + acl;
                }

                // Get next entry
                b = res.indexOf("\nUser name: ", b+12);
            }
        } catch (Exception ex) {
            throw new NedException("injectSnmpUser():", ex);
        }

        traceInfo(worker, "transformed <= inserted: "+stringQuote(result)+" from 'show snmp user'");
        return result;
    }


    /*
     **************************************************************************
     * showPartial
     **************************************************************************
     */

    /**
     * Retrieve partial running config from device
     * @param
     * @throws Exception
     */
    // @Override
    public void showPartial(NedWorker w, String[] cmdpaths)
        throws Exception {
        showPartialInternal(schema, maapi, turboParserEnable, w, cmdpaths);
    }


    /**
     * Retrieve partial running config from device
     * @param
     * @throws Exception
     */
    // @Override
    public void showPartial(NedWorker w, ConfPath[] paths)
        throws Exception {
        showPartialInternal(schema, maapi, turboParserEnable, w, paths);
    }


    /*
     **************************************************************************
     * getDeviceConfiguration
     **************************************************************************
     */

    /**
     * Get device configuration
     * @param
     * @return
     * @throws Exception
     */
    @Override
    protected String getDeviceConfiguration(NedWorker worker) throws Exception {
        String config = getConfig(worker);
        return modifyInput(worker, true, -1, config);
    }


    /*
     **************************************************************************
     * getTransId
     **************************************************************************
     */

    /**
     * Calculate transaction-id
     * @param
     * @throws Exception
     */
    @Override
    public void getTransId(NedWorker worker) throws Exception {
        final long start = tick(0);
        if (trace) {
            session.setTracer(worker);
        }

        // NETSIM, optionally use confd-state transaction id
        String res;
        if (isNetsim() && transIdMethod.equals("confd-state-trans-id")) {
            res = print_line_exec(worker, "show confd-state internal cdb datastore running transaction-id");
            if (res.contains("error")) {
                throw new NedException("Failed to run get confd running transaction-id");
            }
            res = res.substring(res.indexOf(' ')+1).trim();
            logInfo(worker, "DONE GET-TRANS-ID ("+res+")");
            worker.getTransIdResponse(res);
            return;
        }


        // Use last cached transformed config from applyConfig() secret code
        if (transIdMethod.startsWith("config-hash") && lastTransformedConfig != null) {
            logInfo(worker, "BEGIN GET-TRANS-ID (config-hash secrets)");
            res = lastTransformedConfig;
            lastGetConfig = null;
            lastTransformedConfig = null;
        }

        // config-hash-cached - use last cached config from show() if available
        else if (transIdMethod.equals("config-hash-cached") && lastGetConfig != null) {
            logInfo(worker, "BEGIN GET-TRANS-ID (config-hash-cached)");
            res = modifyInput(worker, false, -1, lastGetConfig);
            lastGetConfig = null;
        }

        // Use 'Last configuration change' string from running-config
        else if (transIdMethod.equals("last-config-change") && !isNetsim()) {
            logInfo(worker, "BEGIN GET-TRANS-ID (last-config-change)");
            res = print_line_exec(worker, "show running-config | include Last configuration change");
            if (!res.contains("Last configuration change")) {
                throw new NedException("Failed to get running-config 'Last configuration change' string");
            }
            res = res + res + res + res;
        }

        // Use 'show configuration id' command
        else if (transIdMethod.equals("config-id") && !isNetsim()) {
            logInfo(worker, "BEGIN GET-TRANS-ID (config-id)");
            res = print_line_exec(worker, "show configuration id");
            if (res.contains("Invalid input")) {
                throw new NedException("Failed to use 'show configuration id' for transaction id");
            }
            res = res + res + res + res;
        }

        // Use 'show configuration history' command
        else if (transIdMethod.equals("config-history") && !isNetsim()) {
            logInfo(worker, "BEGIN GET-TRANS-ID (config-history)");
            res = print_line_exec(worker, "show configuration history");
            if (res.contains("Invalid input")) {
                throw new NedException("Failed to use 'show configuration history' for transaction id");
            }
            res = res + res + res + res;
        }

        // Use running-config for string data
        else {
            logInfo(worker, "BEGIN GET-TRANS-ID (config-hash)");
            String config = getConfig(worker);
            res = modifyInput(worker, false, -1, config);
        }

        // Trim config of dynamic info
        res = stripLineAll(worker, res, "Load for ");
        res = stripLineAll(worker, res, "Time source is NTP");
        res = stripLineAll(worker, res, "No time source");
        res = res.trim();

        // Sort certain config since some IOS devices reorder entries after reboot
        res = checksumSortConfig(worker, res);

        traceVerbose(worker, "TRANS-ID-BUF=\n+++ begin\n"+res+"\n+++ end");

        // Calculate checksum of running-config
        byte[] bytes = res.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] thedigest = md.digest(bytes);
        BigInteger md5Number = new BigInteger(1, thedigest);
        String md5String = md5Number.toString(16);

        logInfo(worker, "DONE GET-TRANS-ID ("+md5String+") "+tickToString(start));
        worker.getTransIdResponse(md5String);
    }


    /**
     *
     * @param
     * @return
     */
    private String checksumSortConfig(NedWorker worker, String res) {

        //
        // Sort lines:
        //

        // top mode lines
        res = sortLines(worker, res, "ip route vrf ");
        res = sortLines(worker, res, "ipv6 route "); // including "ipv6 route vrf "
        res = sortLines(worker, res, "ip nat translation max-entries vrf ");

        // router bgp * /
        res = sortLines(worker, res, "aggregate-address ");
        res = sortLines(worker, res, "neighbor ");

        // route-map * / match policy-list *
        res = sortLines(worker, res, "match policy-list ");

        //
        // Sort words in lines:
        //
        String toptag = "";
        StringBuilder sb = new StringBuilder();
        String[] lines = res.split("\n");
        for (int n = 0; n < lines.length; n++) {
            String trimmed = lines[n].trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (isTopExit(lines[n])) {
                toptag = "";
            } else if (Character.isLetter(lines[n].charAt(0))) {
                toptag = lines[n].trim();
            }

            // route-map * / match interface *
            if (toptag.startsWith("route-map")
                && trimmed.startsWith("match interface ")) {
                String sortedline = sortWords(worker, trimmed, 2);
                sb.append(sortedline+"\n");
            }

            // Default, do not reorder
            else {
                sb.append(lines[n]+"\n");
            }
        }
        res = sb.toString();

        return res;
    }


    /**
     *
     * @param
     * @return
     */
    private String sortLines(NedWorker worker, String res, String sortline) {

        // Sort subsequent lines
        int numSorted = 0;
        StringBuilder sb = new StringBuilder();
        String[] lines = res.split("\n");
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            if (line.trim().isEmpty()) {
                continue;
            }
            if (!line.trim().startsWith(sortline)) {
                sb.append(line+"\n");
                continue;
            }

            // First matching line, assemble all subsequent matching lines
            ArrayList<String> arraylist = new ArrayList<>();
            arraylist.add(line);
            for (int s = n + 1; s < lines.length; s++) {
                if (!lines[s].trim().startsWith(sortline)) {
                    break;
                }
                arraylist.add(lines[s]);
                lines[s] = "";
            }

            // Only one line, continue
            if (arraylist.size() == 1) {
                sb.append(line+"\n");
                continue;
            }

            // Sort lines and add back in place sorted
            numSorted += arraylist.size();
            String[] sortlines = arraylist.toArray(new String[arraylist.size()]);
            Arrays.sort(sortlines);
            if (logVerbose) {
                sb.append("! sort begin\n");
            }
            for (int s = 0; s < sortlines.length; s++) {
                sb.append(sortlines[s]+"\n");
            }
            if (logVerbose) {
                sb.append("! sort end\n");
            }
        }
        if (numSorted < 1) {
            return res;
        }

        traceInfo(worker, "transformed <= sorted "+numSorted+" '"+sortline+"' lines for hash checksum");
        return sb.toString();
    }


    /**
     *
     * @param
     * @return
     */
    private String sortWords(NedWorker worker, String trimmed, int start) {
        String[] lines = trimmed.split(" +");
        Arrays.sort(lines, start, lines.length);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            sb.append(" "+lines[i]);
        }
        String sortedline = sb.toString();

        if (!sortedline.equals(trimmed)) {
            traceInfo(worker, "transformed <= sorted '"+trimmed+"' for hash checksum");
        }
        return sortedline;
    }


    /*
     **************************************************************************
     * prepareDry
     **************************************************************************
     */

    /**
     * Display config for commit dry-run
     * @param
     * @throws Exception
     */
    @Override
    public void prepareDry(NedWorker worker, String data) throws Exception {
        String originalIosModel = this.iosmodel;
        final long start = tick(0);
        if (trace && session != null) {
            session.setTracer(worker);
        }

        // ShowRaw used in debugging, to see cli commands before modification
        if (showRaw || data.contains("tailfned raw-run\n")) {
            logInfo(worker, "BEGIN PREPARE-DRY raw");
            showRaw = false;
            logInfo(worker, "DONE PREPARE-DRY "+tickToString(start));
            worker.prepareDryResponse(data);
            return;
        }

        int fromTh = -1;
        int toTh = -1;
        try {
            StringBuilder sb = new StringBuilder();
            fromTh = worker.getFromTransactionId();
            toTh = worker.getToTransactionId();

            // cisco-ios developer prepare-dry-model
            if (devPrepareDryModel != null) {
                if (logVerbose) {
                    sb.append("! Generated for "+devPrepareDryModel+" model\n");
                }
                this.iosmodel = devPrepareDryModel;
            }

            // log
            String log = "BEGIN PREPARE-DRY model="+iosmodel+" version="+iosversion;
            if (session == null) {
                log += " offline";
            }
            logInfo(worker, log);

            // Modify data buffer
            data = modifyOutput(worker, data, "PREPARE-DRY", toTh, fromTh);

            // Rebuild data buffer
            String[] lines = data.split("\n");
            if (session == null && logVerbose) {
                sb.append("! Generated offline");
            }
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].trim().startsWith("! meta-data :: ")) {
                    if (logVerbose) {
                        sb.append(lines[i]+"\n");
                    }
                    continue;
                }
                // Modify texts
                String line = modifyTexts(worker, lines[i]);
                sb.append(line+"\n");
            }
            data = sb.toString();

        } finally {
            this.iosmodel = originalIosModel;
            maapiDetach(fromTh, toTh);
        }

        logInfo(worker, "DONE PREPARE-DRY "+tickToString(start));
        worker.prepareDryResponse(data);
    }


    /*
     **************************************************************************
     * applyConfig
     **************************************************************************
     *
     * NSO PHASES:
     *          prepare (send data to device)
     *           /   \
     *          v     v
     *       abort | commit (send confirmed commit)
     *               /   \
     *              v     v
     *          revert | persist (send confirming commit)
     */

    /**
     * Apply config
     * @param
     * @throws Exception
     */
    @Override
    public void applyConfig(NedWorker worker, int cmd, String data)
        throws NedException, IOException, SSHSessionException, ApplyException {
        final long start = tick(0);
        if (trace) {
            session.setTracer(worker);
        }
        logInfo(worker, "BEGIN APPLY-CONFIG");

        // Apply the commit
        doApplyConfig(worker, cmd, data);

        logInfo(worker, "DONE APPLY-CONFIG "+tickToString(start));
    }


    /**
     *
     * @param
     * @throws Exception
     */
    private void doApplyConfig(NedWorker worker, int cmd, String data)
        throws NedException, IOException, SSHSessionException, ApplyException {
        String[] lines = null;

        // Clear cached data
        lastGetConfig = null;
        lastTransformedConfig = null;
        ignoreNextWrite = false;
        lastTransactionId = worker.getToTransactionId();

        int fromTh = worker.getFromTransactionId();
        int toTh = worker.getToTransactionId();
        try {
            // Modify data and split into lines
            long start = tick(0);
            logInfo(worker, "BEGIN out-transforming");
            data = modifyOutput(worker, data, "APPLY-CONFIG", toTh, fromTh);
            logInfo(worker, "DONE out-transforming "+tickToString(start));

            lines = data.split("\n");
            traceVerbose(worker, "\nAPPLY_AFTER:\n"+data);

            // Empty transaction
            if (lines.length == 0) {
                traceInfo(worker, "Empty transaction -> skip next writeMemory");
                ignoreNextWrite = true;
                return;
            }

            // Reconnect to device if remote end closed connection due to being idle
            if (session.serverSideClosed()) {
                traceInfo(worker, "Server side closed, reconnecting");
                connectorReconnectDevice(worker);
            }

            // Enter config mode
            enterConfig(worker);

            //
            // NETSIM
            //
            start = tick(0);
            if (isNetsim() && writeTransferViaFile && isLocalIp(this.ip)) {
                logInfo(worker, "BEGIN sending (transfer-via-file) "+lines.length+" line(s), write-timeout = "+writeTimeout);
                setWriteTimeout(worker);

                // Write config to /tmp temporary file
                String tmpfile = "/tmp/"+device_id+"-apply-config.txt";
                traceInfo(worker, "Writing config to " + tmpfile);
                if (!writeFile(data, tmpfile)) {
                    throw new ApplyException(tmpfile, "failed to write config to /tmp", true, true);
                }

                // Load config from /tmp temporary file
                traceInfo(worker, "Loading config from " + tmpfile);
                try {
                    String res = print_line_exec(worker, "load merge " + tmpfile);
                    if (res.contains("Error:")) {
                        if (cmd == NedCmd.ABORT_CLI || cmd == NedCmd.REVERT_CLI) {
                            traceInfo(worker, "load merge "+tmpfile+" ERROR: "+stringQuote(res));
                        } else {
                            throw new Exception(stringQuote(res));
                        }
                    }
                } catch (Exception e) {
                    throw new ApplyException(e.getMessage(), "load merge "+tmpfile+" ERROR", true, true);
                }
            }

            //
            // REAL DEVICE or remote NETSIM
            //
            else {
                logInfo(worker, "BEGIN sending "+lines.length+" line(s)");
                try {
                    sendConfig(worker, cmd, lines);
                } catch (ApplyException e) {
                    // We may have changed the config-key on device, restore it from old value
                    if (data.contains("\nkey config-key password-encrypt ")) {
                        restoreConfigKey(worker, cmd, lines, fromTh);
                    }
                    throw e;
                }
            }
            logInfo(worker, "DONE sending "+lines.length+" line(s) "+tickToString(start));

            // Exit config mode
            exitConfig(worker);

            //
            // All commands accepted by device
            //
            try {
                // Cache secrets
                if (secrets.apply(worker, data)) {
                    traceVerbose(worker, "SECRETS - new secrets, caching encrypted entries");
                    String config = getConfig(worker);
                    lastTransformedConfig = modifyInput(worker, false, toTh, config);
                }
            } catch (Exception e) {
                throw new NedException(e.getMessage(), e);
            }
        } finally {
            maapiDetach(fromTh, toTh);
        }

        //
        // Cache defaults
        //
        if (isDevice()) {
            try {
                defaults.cache(session, worker, lines, iosmodel);
            } catch (Exception e) {
                throw new NedException("DEFAULTS post-processing: "+e.getMessage(), e);
            }
        }
    }


    /**
     * Check if local ip address
     * @param
     * @return True if local ip address, else false
     */
    private boolean isLocalIp(InetAddress addr) {
        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress()) {
            return true;
        }
        try {
            return NetworkInterface.getByInetAddress(addr) != null;
        } catch (Exception e) {
            return false;
        }
    }


    /**
     * Restore key config-key value
     * @param
     */
    private void restoreConfigKey(NedWorker worker, int cmd, String[] lines, int fromTh) {
        if (cmd == NedCmd.ABORT_CLI || cmd == NedCmd.REVERT_CLI) {
            return;
        }
        String oldkey = maapiGetLeafString(fromTh, confRoot+"key/config-key/password-encrypt");
        if (oldkey == null) {
            return;
        }
        try {
            String[] newlines = new String[3];
            for (int n = 0; n < lines.length; n++) {
                if (lines[n].startsWith("no key config-key password-encrypt")) {
                    traceInfo(worker, "SECRETS - restoring 'key config-key password-encrypt");
                    newlines[0] = lines[n];
                    newlines[1] = lines[n+1];
                    newlines[2] = "key config-key password-encrypt "+oldkey;
                    enterConfig(worker);
                    sendConfig(worker, cmd, newlines);
                    exitConfig(worker);
                    return;
                }
            }
        } catch (Exception ignore) {
            // Ignore Exception
        }
    }


    /**
     *
     * @param
     * @return
     * @throws Exception
     */
    private String modifyTexts(NedWorker worker, String line) throws NedException {
        int i;
        String match;
        String trimmed = line.trim();

        //traceVerbose(worker, "modifyTexts() line="+line);

        if (isNetsim()) {
            return line;
        }

        //
        // REAL DEVICES BELOW
        //

        // banner motd|exec|login|prompt-timeout|etc.
        if (trimmed.startsWith("banner ")) {
            Pattern p = Pattern.compile("banner (\\S+)[ ]+(.*)");
            Matcher m = p.matcher(trimmed);
            if (m.find()) {
                String message = textDequote(m.group(2));
                message = message.replace("\r", "");  // device adds \r itself
                message = message.replace("\t", " ");  // can't include TAB
                traceVerbose(worker, "transformed => dequoted banner "+m.group(1));
                line = "banner "+m.group(1)+" ^"+message+"^";
                waitForEcho = Echo.TEXT;
            }
        }

        // aaa authentication fail-message
        else if ((match = getMatch(trimmed, "aaa authentication fail-message (.*)")) != null) {
            String message = stringDequote(match);
            message = message.replaceAll("\\r", "");  // device adds \r itself
            line = "aaa authentication fail-message " + "^" + message + "^";
            waitForEcho = Echo.TEXT;
        }

        // menu <name> title ^C <title text> \n^C
        else if (line.matches("^\\s*menu \\S+ title .*$")) {
            i = line.indexOf("title ");
            String title = stringDequote(line.substring(i+6).trim());
            title = title.replaceAll("\\r", "");  // device adds \r itself
            line = line.substring(0,i+6) + "^" + title + "^";
            waitForEcho = Echo.TEXT;
        }

        // macro name <name> "command1\r\ncommand2\r\ncommandN\r\n"
        else if (line.matches("^\\s*macro name .*$")) {
            i = line.indexOf("macro name ");
            i = line.indexOf(' ',i+11);
            String commands = stringDequote(line.substring(i+1).trim());
            commands = commands.replaceAll("\\r", "");  // device adds \r itself
            line = line.substring(0,i+1) + "\n" + commands + "@";
            waitForEcho = Echo.TEXT;
        }

        return line;
    }


    /**
     *
     * @param
     * @return
     * @throws Exception
     */
    private String modifyOutputLineNetsim(String data) throws NedException {
        int i;

        String[] lines = data.split("\n");
        StringBuilder sbout = new StringBuilder();
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            String trimmed = lines[n].trim();
            String noutput = null;

            // description patch for netsim, quote text and escape "
            if ((i = line.indexOf("description ")) >= 0) {
                String desc = line.substring(i+12).trim(); // Strip initial white spaces, added by NCS
                if (desc.charAt(0) != '"') {
                    desc = desc.replaceAll("\\\"", "\\\\\\\""); // Convert " to \"
                    noutput = line.substring(0,i+12) + "\"" + desc + "\""; // Quote string, add ""
                }
            }

            // voice translation-rule * / rule
            else if ("no".equals(rollBackOctal)
                     && getMatches(trimmed, "rule (\\d+) ((?:[\"])?[/].*?[/](?:[\"])?) ((?:[\"])?[/].*?[/](?:[\"])?)") != null) {
                noutput = line.replace("\\", "\\\\");
            }

            // Transform lines[n] -> XXX
            if (noutput != null && !noutput.equals(lines[n])) {
                sbout.append(noutput+"\n");
            } else if (lines[n] != null && !lines[n].isEmpty()) {
                sbout.append(lines[n]+"\n");
            }
        }

        return "\n" + sbout.toString();
    }


    /**
     * Modify line by line for output to real device
     * @param
     * @return
     * @throws Exception
     */
    private String modifyOutputLine(NedWorker worker, String data) throws NedException {
        String[] group;
        String match;

        String[] lines = data.split("\n");
        StringBuilder sb = new StringBuilder();
        String toptag = "";
        String meta = "";
        for (int n = 0; n < lines.length; n++) {
            String output = null;
            String line = lines[n];
            String trimmed = lines[n].trim();
            if (trimmed.isEmpty()) {
                continue;
            }

            String cmdtrim = trimmed.startsWith("no ") ? trimmed.substring(3) : trimmed;
            String nextline = (n + 1 < lines.length) ? lines[n+1] : "";

            // Update toptag
            if (isTopExit(line)) {
                toptag = "";
            } else if (Character.isLetter(line.charAt(0))) {
                toptag = trimmed;
            }

            //
            // key config-key password-encrypt - delete key before change
            //
            if (trimmed.contains("key/config-key/password-encrypt :: support-encrypted-password")) {
                traceInfo(worker, "transformed => injected 'no key config-key password-encrypt'");
                sb.append("no key config-key password-encrypt\n");
            }

            //
            // Collect all meta-data in 'meta'
            //
            if (trimmed.startsWith("! meta-data :: ")) {
                if (!line.equals(nextline)) {
                    // Ignore/strip duplicate meta-data annotation
                    meta += (line + "\n");
                    sb.append(line + "\n");
                }
                continue;
            }

            //
            // Ignore duplicate lines:
            //   no cos map *
            //   no qos map dscp policed
            //   no mls cos map X *
            //
            if ((trimmed.startsWith("no qos map ")
                 || trimmed.startsWith("no qos map dscp policed")
                 || trimmed.startsWith("no mls qos map "))
                && line.equals(nextline)) {
                continue;
            }

            //
            // meta-data "suppress-no-command"
            //
            if (meta.contains(" :: suppress-no-command") && trimmed.startsWith("no ")) {
                // suppress command that can not be removed on the device.
                output = "!suppressed: "+line;
            }

            //
            // enable algorithm-type secret
            //
            else if (line.startsWith("enable secret ") || line.startsWith("no enable secret ")) {
                output = line.replaceFirst("secret (algorithm-type \\S+)", "$1 secret");
            }

            //
            // interface * / cable rf-channels channel-list x-y z bandwidth-percent
            // interface * / cable rf-channels controller ? channel-list x-y z bandwidth-percent
            //
            else if (toptag.startsWith("interface ")
                     && line.contains("cable rf-channels ") && line.contains(" channel-list ")) {
                output = line.replace(",", " ");
            }

            //
            // class-map * / match vlan *
            //
            else if (toptag.startsWith("class-map ") && cmdtrim.startsWith("match vlan ")) {
                output = line.replace(",", " ");
            }

            //
            // vlan * / name
            //
            else if (toptag.startsWith("vlan ") && trimmed.startsWith("name ")
                     && trimmed.substring(5).trim().contains(" ")
                     && (match = getMatch(trimmed, "name\\s+(\\S.+)")) != null) {
                output = line.replace(match, "\""+match+"\"");
            }

            //
            // cable profile service-group * / mac-domain * / downstream sg-channel
            //
            else if (toptag.startsWith("cable ")
                     && line.matches("^\\s*downstream sg-channel .+ profile \\S+(?: upstream .+)?$")) {
                output = line.replace(",", " ");
                Pattern p = Pattern.compile(" upstream[ ]+\\\"(.+)\\\"");
                Matcher m = p.matcher(output);
                if (m.find()) {
                    output = output.replace(m.group(0), " upstream "+m.group(1));
                }
            }

            //
            // no cable service class * name <name>
            //
            else if (trimmed.startsWith("no cable service class ")
                     && (match = getMatch(trimmed, "^no cable service class (\\d+) name \\S+$")) != null) {
                output = "no cable service class "+match;
            }

            //
            // parameter-map type regexp * / pattern *
            //
            else if (toptag.startsWith("parameter-map type regex ")
                     && cmdtrim.startsWith("pattern ")
                     && (match = getMatch(trimmed, "pattern \\\"(.*)\\\"$")) != null) {
                output = " pattern " + match;
            }

            //
            // crypto pki profile enrollment * / authentication command
            //
            else if (toptag.startsWith("crypto pki profile enrollment ")
                     && cmdtrim.startsWith("authentication command ")
                     && (match = getMatch(trimmed, "authentication command\\s+(\\\".*\\\")")) != null) {
                output = " authentication command " + passwordDequote(match);
            }

            //
            // router ospf * / discard-route
            //
            else if (toptag.startsWith("router ospf ") && trimmed.equals("discard-route external disabled")) {
                output = " no discard-route external\n";
            } else if (toptag.startsWith("router ospf ") && trimmed.equals("discard-route internal disabled")) {
                output = " no discard-route internal\n";
            }

            //
            // cts credentials id
            //
            else if (trimmed.startsWith("cts credentials id ")) {
                output = "do "+trimmed;
            } else if (trimmed.startsWith("no cts credentials id ")) {
                output = "!"+trimmed;
            }

            //
            // chat-script * <script>
            //
            else if (toptag.contains("chat-script ")
                     && (match = getMatch(trimmed, "chat-script \\S+ (.*)")) != null) {
                String script = stringDequote(match);
                output = line.replace(match, script);
            }

            //
            // kron policy-list * / cli *
            //
            else if (toptag.startsWith("kron policy-list ")
                     && cmdtrim.startsWith("cli ")
                     && (match = getMatch(trimmed, "cli (.+)")) != null) {
                output = line.replace(match, stringDequote(match));
            }

            //
            // event manager applet * / action * regexp
            //
            else if (toptag.startsWith("event ")
                     && line.matches("^\\s*action \\d+ regexp .*$")) {
                int i = line.indexOf(" regexp \"");
                if (i > 0) {
                    String regexp = stringDequote(line.substring(i+8));
                    output = line.substring(0,i+8) + regexp;
                }
            }

            //
            // crypto pki trustpoint * / subject-name
            //
            else if (toptag.startsWith("crypto pki trustpoint ") && cmdtrim.startsWith("subject-name ")
                     && (match = getMatch(line, "subject-name\\s+(\\\".+\\\")")) != null) {
                output = line.replace(match, stringDequote(match));
            }

            //
            // alias <mode> <name> *
            //
            else if (cmdtrim.startsWith("alias ") &&
                     (group = getMatches(line, "(alias \\S+ \\S+ )\\\"(.*)\\\"")) != null) {
                output = group[1] + passwordDequote(group[2]);
            }

            //
            // snmp-server location|contact *
            //
            else if (cmdtrim.startsWith("snmp-server ")
                     && (group = getMatches(line, "(snmp-server (?:location|contact) )\\\"(.*)\\\"")) != null) {
                output = group[1] + passwordDequote(group[2]);
            }

            //
            // interface * / ip address
            //
            else if (toptag.startsWith("interface ") && trimmed.equals("ip address")) {
                output = " !ip address";
            }

            //
            // disable passive-interface
            //
            else if (line.contains("no disable passive-interface ")) {
                output = line.replace("no disable passive-interface ", "passive-interface ");
            }
            else if (line.contains("disable passive-interface ")) {
                output = line.replace("disable passive-interface ", "no passive-interface ");
            }

            //
            // no-list - generic trick for no-lists
            //
            else if (line.contains("no-list ")) {
                line = line.replace("no-list ", "");
                if (line.matches("^\\s*no .*$")) {
                    output = line.replace("no ", "");
                } else {
                    output = line.replace(line.trim(), "no " + line.trim());
                }
            }

            //
            // ip access-list unordered standard|extended *
            //
            else if (cmdtrim.startsWith("ip access-list unordered ")) {
                output = line.replace(" unordered", "");
            }

            //
            // ip forward-protocol udp
            //
            else if (line.contains("ip forward-protocol udp ") && line.contains(" disabled")) {
                line = line.replace(" disabled", "");
                if (line.contains("no ip")) {
                    output = line.replace("no ip", "ip");
                } else {
                    output = "no " + line;
                }
            }

            //
            // no network-clock-participate wic *
            //
            else if (line.contains("network-clock-participate wic wic-disabled ")) {
                output = line.replace("network-clock-participate wic wic-disabled ",
                                      "no network-clock-participate wic ");
            }

            //
            // policy-map * / class * / police - bpsflat (catalyst style)
            //
            else if (toptag.startsWith("policy-map ")
                     && hasPolice("bpsflat") && cmdtrim.startsWith("police ")) {
                output = line.replaceAll("police (\\d+) bps (\\d+) byte", "police $1 $2");
            }

            //
            // no ip ssh server|client algorithm mac .*
            //
            else if (line.matches("^no ip ssh (server|client) algorithm mac .*$")) {
                output = line.substring(0,line.indexOf("mac")+3);
                output = output.replace("no", "default");
            }

            //
            // no ip ssh server|client algorithm encryption .*
            //
            else if (line.matches("^no ip ssh (server|client) algorithm encryption .*$")) {
                output = line.substring(0,line.indexOf("encryption")+10);
                output = output.replace("no", "default");
            }

            //
            // ip mroute-cache
            //
            else if (line.matches("^\\s*ip mroute-cache$") && this.useIpMrouteCacheDistributed) {
                output = line + " distributed";
            }

            //
            // monitor session * filter vlan *
            // monitor session * source vlan *
            // monitor session * source remote vlan *
            // monitor session * destination remote vlan *
            //
            else if (line.contains("monitor session") && line.contains(" vlan ")) {
                output = line.replace(","," , ").replace("-"," - ");
            }

            //
            // controller SONET * / sts-1 "x - y" mode sts-3c
            //
            else if (toptag.startsWith("controller ") && cmdtrim.startsWith("sts-1 ")) {
                output = line.replace("\"", "");
            }

            //
            // crypto pki certificate chain * / certificate *
            //
            else if (toptag.startsWith("crypto pki certificate ")
                     && line.startsWith(" certificate ")
                     && nextline.trim().startsWith("\"")) {
                // Add certificate line and dequote certificate
                traceVerbose(worker, "transformed => dequoted '"+trimmed+"'");
                sb.append(lines[n++]+"\n");
                lines[n] = stringDequote(lines[n].trim()); // note: prompt shows after each line
            }

            //
            // interface * / no ipv6 nd inspection vlan
            //
            else if (toptag.startsWith("interface ")
                     && trimmed.matches("^no ipv6 nd inspection vlan( add)? \\d+.*$")) {
                // Remove entry
                line = line.replace(" add", "");
                output = line.replace("no ipv6 nd inspection vlan",
                                      "ipv6 nd inspection vlan remove");
            }

            //
            // interface * / bridge-group
            //
            else if (toptag.startsWith("interface ")
                     && (match = getMatch(trimmed, "^no bridge-group (\\d+)$")) != null) {
                // Strip all but the first top-list delete
                sb.append(lines[n++]+"\n");
                for (; n < lines.length; n++) {
                    if (lines[n].contains(" bridge-group " + match)) {
                        traceVerbose(worker, "transformed => stripped '"+lines[n].trim()+"'");
                        continue;
                    }
                    break;
                }
            }

            //
            // voice translation-rule * / rule
            //
            else if (toptag.startsWith("voice translation-rule ") && cmdtrim.startsWith("rule ")
                     && (group = getMatches(trimmed, "rule (\\d+) ((?:[\"])?[/].*?[/](?:[\"])?) ((?:[\"])?[/].*?[/](?:[\"])?)")) != null
                     && Integer.parseInt(group[0]) == 3) {
                String matchingP = passwordDequote(group[2]);
                String replacementP = passwordDequote(group[3]);
                output = " rule "+group[1]+" "+matchingP+" "+replacementP;
            }

            //
            // route-map * / set community *
            //
            else if (toptag.startsWith("route-map ") && trimmed.startsWith("set community ")) {
                String[] token = trimmed.split(" +");
                for (int base = 2; base < token.length; base += 10) {
                    line = " set community";
                    for (int i = base; i < base+10 && i < token.length; i++) {
                        if (!"additive".equals(token[i])) {
                            line += (" " + token[i]);
                        }
                    }
                    if (trimmed.contains(" additive")) {
                        sb.append(line+" additive\n");
                    } else {
                        sb.append(line+"\n");
                    }
                }
                traceVerbose(worker, "transformed => formatted '"+trimmed+"'");
                continue;
            }

            //
            // route-map * / set extcommunity rt *
            //
            else if (toptag.startsWith("route-map ")
                     && trimmed.startsWith("set extcommunity rt ") && trimmed.endsWith(" additive")
                     && trimmed.length() > 100) {
                String[] rts = trimmed.split(" ");
                int base;
                for (base = 3; base < rts.length-1; base += 10) {
                    line = " set extcommunity rt";
                    for (int i = base; i < base+10 && i < rts.length-1; i++) {
                        line += (" " + rts[i]);
                    }
                    sb.append(line+" additive\n");
                }
                if (base > 3) {
                    traceVerbose(worker, "transformed => split '"+trimmed+"'");
                }
                continue;
            }

            //
            //  meta-data "secret" | "support-encrypted-password"
            //
            line = output != null ? output : line;
            if ((meta.contains(":: secret") || meta.contains(":: support-encrypted-password"))
                && (match = getMatch(line, " (\\\".*\\\")")) != null) {
                // Passwords need to be dequoted using passwordDequote before sent to device
                output = line.replace(match, passwordDequote(match));
            }

            //
            // Transform lines[n] -> XXX
            //
            meta = "";
            if (output != null && !output.equals(lines[n])) {
                if (output.isEmpty()) {
                    traceVerbose(worker, "transformed => stripped '"+trimmed+"'");
                    continue;
                }
                traceVerbose(worker, "transformed => '"+trimmed+"' to '"+output.trim()+"'");
                sb.append(output+"\n");
            } else if (lines[n] != null && !lines[n].isEmpty()) {
                sb.append(lines[n]+"\n");
            }
        }
        return "\n" + sb.toString();
    }


    /**
     *
     * @param
     * @return
     * @throws Exception
     */
    private String modifyOutput(NedWorker worker, String data, String function, int toTh, int fromTh)
        throws NedException {

        // Attach to CDB
        maapiAttach(worker, fromTh, toTh);

        // Reset timeout to NED standard
        lastTimeout = setReadTimeout(worker);

        //
        // Scan meta-data and modify data
        //
        data = metaData.modifyData(worker, data, toTh, fromTh, maapi, iosmodel);

        //
        // modifyLocked - unlock locked config
        //
        data = nedData.modifyLocked(worker, data, toTh, fromTh, maapi);

        //
        // Trim output
        //
        data = trimOutput(worker, data, toTh);

        //
        // Reorder data
        //
        //traceVerbose(worker, "\nBEFORE_REORDER:\n"+data);
        traceInfo(worker, function + " reordering config");
        data = reorderData(worker, data);

        //
        // modify access-list
        //
        if (resequenceACL) {
            traceInfo(worker, function + " out-transforming - ip access-lists (resequence)");
            data = nedAcl.modify(worker, data, fromTh, toTh, maapi);
        }

        //
        // Line-by-line transformations
        //
        if (isNetsim()) {
            data = modifyOutputLineNetsim(data);
        } else {
            data = modifyOutputLine(worker, data);
        }

        //
        // write/inject-commit ned-setting - replace/filter config in commit
        //
        if (replaceCommit.size() > 0) {
            traceInfo(worker, function + " out-transforming - inject-commit ned-setting");
            data = replaceCommitData(worker, data);
        }

        //
        // write/inject-command ned-setting - inject command(s) [OLD API]
        //
        if (injectCommand.size() > 0) {
            traceInfo(worker, function + " out-transforming - inject-command ned-setting");
            for (int n = 0; n < injectCommand.size(); n++) {
                String[] entry = injectCommand.get(n);
                data = injectData(worker, data, entry, "=>");
            }
        }

        return data;
    }


    /**
     * Trim output data, e.g. delete of (large) ip prefix-list lists
     * @param
     * @return
     * @throws NedException
     */
    private String trimOutput(NedWorker worker, String data, int toTh) throws NedException {

        String[] lines = data.split("\n");
        StringBuilder sb = new StringBuilder();
        String ipPfxPath = null;
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }

            // no ip prefix-list <name> seq <entry>
            if (line.startsWith("no ip prefix-list ")) {

                // Get ip prefix-list root path
                if (ipPfxPath == null) {
                    String seqNo = maapiGetLeafString(toTh, confRoot+"ip/prefix-list/sequence-number");
                    traceVerbose(worker, "ip prefix-list sequence-number = "+ seqNo);
                    if (seqNo != null && seqNo.equals("false")) {
                        ipPfxPath = confRoot+"ip/prefix-list/prefixes-no-seq";
                    } else {
                        ipPfxPath = confRoot+"ip/prefix-list/prefixes";
                    }
                }

                // Compress prefix-list delete
                String name;
                if ((name = getMatch(line, "no ip prefix-list (\\S+) ")) != null
                    && !maapiExists(worker, toTh, ipPfxPath+"{"+name+"}")) {
                    int num = 1;
                    for (int t = n + 1; t < lines.length; t++) {
                        if (!lines[t].startsWith("no ip prefix-list "+name+" ")) {
                            break;
                        }
                        lines[t] = "";
                        num++;
                    }
                    if (num > 1) {
                        traceVerbose(worker, "transformed -> trimmed "+num+" 'no ip prefix-list "+name+"' lines");
                        sb.append("no ip prefix-list "+name+"\n");
                        continue;
                    }
                }
            }

            // Add line
            sb.append(line+"\n");
        }

        return "\n" + sb.toString();
    }


    /**
     *
     * @param
     * @return
     */
    private String reorderData(NedWorker worker, String data) {
        int n;
        String match;

        num_reordered = 0;

        // Syntax: line to move :: after|before :: line to stay
        String[] interfaceRules = {
            "no switchport \\S.* :: before :: no switchport",
            "no switchport mode private-vlan trunk :: after :: no switchport port-security.*",
            "no switchport port-security maximum vlan :: before :: switchport mode dynamic desirable",

            "no service instance .* :: before :: no switchport.*",
            "no ip dhcp snooping .* :: before :: no switchport.*",
            "(no )?ip (route-cache|redirects|proxy-arp) :: before :: switchport",
            "(no )?ip (route-cache|redirects|proxy-arp) :: after :: no switchport",
            "ip address \\S.* :: after :: no switchport",
            "channel-group \\d+ .+ :: after :: no switchport",

            "no ip address.* :: before :: no encapsulation dot1Q \\d+.*", // RT25447,RT33983
            "ip address \\S.* :: after :: (ip )?vrf \\S.*",
            "no ip address \\S.* :: before :: no (ip )?vrf \\S.*",
            "no ipv6 ospf.* :: before :: no ipv6 address.*", // RT33785

            "(no )?mdix auto :: before :: (media-type\\s+sfp|no media-type\\s+rj45)",
            "no ip address :: before :: media-type\\s+\\S+",
            "duplex\\s+auto :: before :: speed\\s+auto",
            "negotiation auto :: after :: (no )?speed.*",

            "no tunnel mpls.* :: before :: no tunnel mode mpls.*"
        };

        //
        // Pass 1 - reorder sub-mode (block) config
        //
        String toptag = "";
        String[] lines = data.split("\n");
        for (n = 0; n < lines.length - 1; n++) {
            String trimmed = lines[n].trim();
            int start = n;
            int end = -1;
            if (trimmed.isEmpty()) {
                continue;
            }
            if (isTopExit(lines[n])) {
                toptag = "";
            } else if (Character.isLetter(lines[n].charAt(0))) {
                toptag = lines[n].trim();
            }

            //
            // interface
            //
            if (toptag.startsWith("interface ")) {
                // Find interface exit (and forward outer loop)
                for (n = n + 1; n < lines.length; n++) {
                    if (isTopExit(lines[n])) {
                        end = n;
                        break;
                    }
                }
                if (end == -1) {
                    traceInfo(worker, "Internal ERROR: missing interface exit in reorderData()");
                    continue;
                }

                // Reorder interface config
                lines = reorderDataBlock(worker, interfaceRules, toptag, lines, start, end);
            }

            //
            // ip prefix-list
            // ipv6 prefix-list
            //
            String[] deleteListRules = {
                "ip prefix-list ", "ipv6 prefix-list "
            };
            for (int r = 0; r < deleteListRules.length; r++) {
                String name = deleteListRules[r];
                if (toptag.startsWith(name)) {
                    for (n = n + 1; n < lines.length; n++) {
                        if (lines[n].startsWith(name) || lines[n].startsWith("no "+name)) {
                            end = n;
                        } else {
                            break;
                        }
                    }
                    if (end == -1) {
                        continue;
                    }
                    traceVerbose(worker, "reordering '"+name+"' start="+start+" end="+end);
                    String[] rule = new String[1];
                    rule[0] = "no "+name+".* :: before :: "+name+".*";
                    lines = reorderDataBlock(worker, rule, toptag, lines, start, end + 1);
                    break;
                }
            }

            //
            // router bgp * / neighbor *
            //
            if (toptag.startsWith("router bgp ")
                && (match = getMatch(trimmed, "no neighbor (\\S+)")) != null) {
                String neighbor = "no neighbor " + match;
                for (n = n + 1; n < lines.length; n++) {
                    if (!lines[n].trim().startsWith(neighbor)) {
                        end = n;
                        break;
                    }
                }
                if (start + 1 == end) {
                    continue;
                }

                // Reorder neighbor delete lines
                traceInfo(worker, "NCSPATCH: reordering router bgp neighbor "+match+" delete lines "+start+"-"+end);
                String[] remote_asRule = { neighbor + ".* :: before :: " + neighbor + " remote-as \\d+" };
                lines = reorderDataBlock(worker, remote_asRule, toptag, lines, start, end);
                String[] peer_groupRule = { neighbor + ".* :: before :: " + neighbor + " peer-group" };
                lines = reorderDataBlock(worker, peer_groupRule, toptag, lines, start, end);
            }
        }

        //
        // Pass 2 - Make sure delete of access-list rules are before create
        //
        if (newIpACL) {
            for (n = 0; n < lines.length; n++) {
                if (lines[n].startsWith("ip access-list ")
                    || lines[n].startsWith("ipv6 access-list ")) {
                    List<String> delete = new ArrayList<>();
                    List<String> create = new ArrayList<>();
                    for (int m = ++n; m < lines.length; m++) {
                        String trimmed = lines[m].trim();
                        if (isTopExit(trimmed) || lines[m].charAt(0) != ' ') {
                            break;
                        }
                        if (trimmed.startsWith("no ")) {
                            delete.add(lines[m]);
                        } else {
                            create.add(lines[m]);
                        }
                    }
                    for (String line : delete) {
                        lines[n++] = line;
                    }
                    for (String line : create) {
                        lines[n++] = line;
                    }
                }
            }
        }

        //
        // Pass 3 - reorder address change between interfaces
        //
        if (autoIfAddressDeletePatch) {
            lines = reorderIfAddressDelete(worker, lines);
        }

        //
        // Pass 4 - reorder top mode config (e.g. routes, interfaces etc)
        //
        StringBuilder first = new StringBuilder();
        StringBuilder middle = new StringBuilder();
        StringBuilder last = new StringBuilder();
        for (toptag = "", n = 0; n < lines.length; n++) {
            String line = lines[n];
            if (line.isEmpty()) {
                continue;
            }
            String trimmed = line.trim();
            String cmdtrim = trimmed.startsWith("no ") ? trimmed.substring(3) : trimmed;

            if (isTopExit(line)) {
                toptag = "";
            } else if (Character.isLetter(line.charAt(0))) {
                toptag = line; // Note: no trim needed due to output and no trailing \r
            }

            // Routes should always be deleted first and added last [CISCOIOS-1105]
            if (line.startsWith("no ip route ") || line.startsWith("no ipv6 route ")) {
                traceVerbose(worker, "transformed => moved '"+line+"' first");
                first.append(line+"\n");
            } else if (line.startsWith("ip route ") || line.startsWith("ipv6 route ")) {
                traceVerbose(worker, "transformed => moved '"+line+"' last");
                last.append(line+"\n");
            }

            // Always delete LISP interfaces last
            else if (line.startsWith("no interface LISP")) {
                traceVerbose(worker, "transformed => moved '"+line+"' last");
                last.append(line+"\n");
            }

            // Reverse order of line vty deletes [RT24125]
            else if (line.startsWith("no line vty ")) {
                traceVerbose(worker, "transformed => moved '"+line+"' last (reversed)");
                last.insert(0, line+"\n");
            }

            // Restore terminal length
            else if (toptag.startsWith("line ") && cmdtrim.startsWith("length ")) {
                middle.append(line+"\n");
                if (last.indexOf("do terminal length 0\n") < 0) {
                    last.append("do terminal length 0\n");
                }
            }

            // Put delete of ip[v6] prefix-list before create [CISCOIOS-904]
            else if ((line.startsWith("ip prefix-list ") || line.startsWith("ipv6 prefix-list "))
                     && (match = getMatch(line, "(ip(?:v6)? prefix-list \\S+ seq \\d+ )")) != null) {
                for (int p = n + 1; p < lines.length; p++) {
                    if (lines[p].startsWith("no "+match)) {
                        traceVerbose(worker, "transformed -> moved '"+lines[p]+"' up");
                        middle.append(lines[p]+"\n");
                        lines[p] = "";
                        break;
                    }
                }
                middle.append(lines[n]+"\n");
            }

            // AppNav interface and service-insertion ordering
            else if (line.startsWith("no service-insertion ") || line.startsWith("no interface AppNav")) {
                // Move to first
                traceVerbose(worker, "transformed => moved '"+line+"' first");
                first.append(line+"\n");
            } else if (line.startsWith("service-insertion ") || line.startsWith("interface AppNav")) {
                // Move the whole top-mode block
                traceVerbose(worker, "transformed => moved '"+line+"' list last");
                for (; n < lines.length; n++) {
                    last.append(lines[n]+"\n");
                    if (lines[n].equals("!") || lines[n].equals("exit")) {
                        break;
                    }
                }
            }

            // Default case
            else {
                middle.append(line+"\n");

                // Special service-policy policy-map inject patch [CISCOIOS-649]
                if ((match = getMatch(lines[n], "^\\s+service-policy (?:input|output) (\\S+)$")) != null) {
                    boolean found = false;
                    for (int b = n; b >= 0; b--) {
                        if (lines[b].matches("^policy-map(?: type \\S+)? "+match+"$")) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        for (int f = n + 1; f < lines.length; f++) {
                            if (lines[f].matches("^policy-map(?: type \\S+)? "+match+"$")) {
                                traceInfo(worker, "transformed => injected '"+lines[f]+"' before use in service-policy");
                                first.append(lines[f]+"\nexit\n");
                                break;
                            }
                        }
                    }
                }
            }
        }
        data = "\n" + first.toString() + middle.toString() + last.toString();

        //
        // Pass 5 - reorder sub mode config
        //
        StringBuilder sb = new StringBuilder();
        lines = data.split("\n");
        for (n = 0; n < lines.length; n++) {

            // [CISCOIOS-758]
            // Move up router bgp * / neighbor entries before address-family
            if (lines[n].startsWith("router bgp")) {
                sb.append(lines[n]+"\n");
                middle = new StringBuilder();
                first = new StringBuilder();
                // First put everything before first address-family first
                for (n = n + 1; n < lines.length; n++) {
                    if (lines[n].equals("!") || lines[n].equals("exit")) {
                        break;
                    }
                    if (lines[n].startsWith(" address-family ")) {
                        break;
                    }
                    sb.append(lines[n]+"\n");
                }
                // Now move up all new neighbor entries to before address-family
                for (; n < lines.length; n++) {
                    String nextline = (n + 1 < lines.length) ? lines[n+1] : "";
                    if (lines[n].equals("!") || lines[n].equals("exit")) {
                        break;
                    }
                    if (lines[n].startsWith(" neighbor ")
                        || (lines[n].startsWith(" ! meta-data :: ") && lines[n].contains("/neighbor{")
                            && nextline.startsWith(" neighbor "))) {
                        traceVerbose(worker, "transformed => moved up '"+lines[n]+"' in router bgp");
                        first.append(lines[n]+"\n");
                    } else {
                        middle.append(lines[n]+"\n");
                    }
                }
                sb.append(first.toString() + middle.toString());
                // fall through and add final exit "!" | "exit"
            }

            // Add current line
            sb.append(lines[n]+"\n");
        }
        data = "\n" + sb.toString();

        //
        // Pass 6 - Put policy-map bandwidth & priority percent subtractions first
        //
        Pattern p = Pattern.compile("\npolicy-map (\\S+).*?\n!", Pattern.DOTALL);
        Matcher m = p.matcher(data);
        StringBuffer sbf = new StringBuffer();
        // Note: To avoid error: "Sum total of class bandwidths exceeds 100 percent"
        while (m.find()) {
            String polmap = m.group(0);
            if (hasString("\n  no (bandwidth|priority) percent", polmap)
                && hasString("\n  (bandwidth|priority) percent \\d+", polmap)) {
                lines = polmap.split("\n");
                sb = new StringBuilder();
                for (n = 0; n < lines.length; n++) {
                    if (lines[n].trim().startsWith("!")
                        || lines[n].startsWith("policy-map ")
                        || lines[n].startsWith(" class ")
                        || lines[n].startsWith("  no bandwidth percent")
                        || lines[n].startsWith("  no priority percent")) {
                        sb.append(lines[n]+"\n");
                    }
                }
                traceVerbose(worker, "transformed => injected bandwidth|priority percent subtractions in policy-map "+m.group(1)+" classes");
                polmap = sb.toString() + polmap;
            }
            m.appendReplacement(sbf, Matcher.quoteReplacement(polmap));
        }
        m.appendTail(sbf);
        data = sbf.toString();

        //
        // Pass 7 - string buffer swapping
        //
        sb = new StringBuilder();
        lines = data.split("\n");
        toptag = "";
        String value1, value2;
        for (n = 0; n < lines.length; n++) {
            int swap = 0;
            String line = lines[n];
            String trimmed = lines[n].trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String nexttrim = (n + 1 < lines.length) ? lines[n+1].trim() : "";
            String nexttrim2 = (n + 2 < lines.length) ? lines[n+2].trim() : "";
            String nexttrim3 = (n + 3 < lines.length) ? lines[n+3].trim() : "";
            if (isTopExit(line)) {
                toptag = "";
            } else if (Character.isLetter(line.charAt(0))) {
                toptag = trimmed;
            }

            // router ospf * / max-metric router-lsa
            if (toptag.startsWith("router ospf")
                && trimmed.startsWith("max-metric router-lsa ")
                && nexttrim.startsWith("no max-metric router-lsa ")) {
                swap = 1;
            }

            // router * / distribute-list
            else if (toptag.startsWith("router ")
                     && trimmed.startsWith("distribute-list ")
                     && nexttrim.startsWith("no distribute-list ")) {
                swap = 2;
            }

            // redistribute ?
            else if ((match = getMatch(nexttrim, "no redistribute (.*)")) != null
                     && trimmed.startsWith("redistribute "+match+" ")) {
                swap = 3;
            }

            // ip sla * / threshold + timeout
            else if (toptag.startsWith("ip sla ")
                     && trimmed.startsWith("threshold ") && nexttrim.startsWith("timeout ")
                     && (match = getMatch(trimmed, "threshold[ ]+(\\S+)")) != null
                     && Integer.parseInt(match) > 5000) {
                swap = 4;
            }

            // ip sla * / no timeout + no threshold
            else if (toptag.startsWith("ip sla ")
                     && trimmed.startsWith("no timeout ") && nexttrim.startsWith("no threshold ")
                     && (match = getMatch(trimmed, "no timeout[ ]+(\\S+)")) != null
                     && Integer.parseInt(match) > 5000) {
                swap = 5;
            }

            // <= NSO-4.5.3 patch for bad order in remove-before-change with secrets
            else if (trimmed.startsWith("! meta-data :: ") && trimmed.equals(nexttrim2)
                     && !nexttrim.startsWith("no ") && nexttrim3.startsWith("no ")) {
                traceInfo(worker, "transformed => swapped '"+nexttrim+"' and '"+nexttrim3+"'");
                String temp = lines[n+1];
                lines[n+1] = lines[n+3];
                lines[n+3] = temp;
            }

            // Add line, with optional swap before
            if (swap > 0) {
                traceInfo(worker, "transformed => swapped["+swap+"] '"+trimmed+"' and '"+nexttrim+"'");
                line = lines[n+1];
                lines[n+1] = lines[n];
            }
            sb.append(line+"\n");
        }
        data = sb.toString();

        //
        // Reordering complete -> log results
        //
        if (num_reordered > 0) {
            traceInfo(worker, "DIFFPATCH: reordered "+num_reordered+" line(s)");
        }

        return "\n" + data;
    }


    /**
     *
     * @param
     * @return
     */
    private String[] reorderDataBlock(NedWorker worker, String[] rules, String toptag, String[] lines, int start, int end) {
        int j;

        //
        // Syntax of reorder string array - rules
        //
        // rules[rule] = tag[0] :: tag[1] :: tag[2] :: [optional tag[3]]
        // tag[0] = line A to move (regexp)
        // tag[1] = after|before
        // tag[2] = line B to stay (regexp)
        // Note: Rule is whitespace insensitive in endings due to line.trim()

        // Keep looping until we no longer reorder any config
        for (boolean inorder = false; !inorder; ) {
            inorder = true;

            // Loop through the rules
            for (int rule = 0; rule < rules.length; rule++) {
                String[] tag = rules[rule].split(" :: ");
                boolean before = tag[1].startsWith("before");

                // Loop through and reorder all entries in this rule
                for (;;) {

                    // First find stay (note: stay may have moved since last loop)
                    int stay = -1;
                    for (j = start; j < end; j++) {
                        if (lines[j].trim().matches("^"+tag[2].trim()+"$")) {
                            stay = j;
                            if (before) {
                                break; // if moving something before, break at first match
                            }
                        }
                    }
                    if (stay == -1) {
                        break;
                    }

                    // Then find best move (depends on after or before)
                    int move = -1;
                    if (before) {
                        for (j = stay + 1; j < end; j++) {
                            if (lines[j].trim().matches("^"+tag[0].trim()+"$")) {
                                move = j;
                                break;
                            }
                        }
                    } else {
                        for (j = start + 1; j < stay; j++) {
                            if (lines[j].trim().matches("^"+tag[0].trim()+"$")) {
                                move = j;
                                break;
                            }
                        }
                    }
                    if (move == -1) {
                        break;
                    }

                    // Move the 'move' entry by shifting lines
                    traceInfo(worker, "transformed => reorder rule #"+rule+" : "+
                              "moved '"+lines[move]+"' "+tag[1]+" '"+lines[stay]+"' under '"+toptag+"'");
                    String moveLine = lines[move];
                    if (before) {
                        for (j = move; j > stay; j--) {
                            lines[j] = lines[j-1];
                        }
                    } else {
                        for (j = move; j < stay; j++) {
                            lines[j] = lines[j+1];
                        }
                    }
                    lines[stay] = moveLine;
                    inorder = false;
                    num_reordered++;
                }
            }
        }
        return lines;
    }


    /**
     * Reorder interfaces address delete/changes
     * @param
     * @return
     */
    private String[] reorderIfAddressDelete(NedWorker worker, String[] lines) {

        int indexIfAdd = lines.length;
        int indexIfChange = 0;
        int indexIfDelete = 0;
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            if (line.isEmpty()) {
                continue;
            }
            if (line.startsWith("interface ")) {
                for (n = n + 1; n < lines.length; n++) {
                    if (isTopExit(lines[n])) {
                        break;
                    } else if (indexIfAdd == lines.length && isIfInjectLine(lines[n], true)) {
                        indexIfAdd = n;
                    } else if (isIfInjectLine(lines[n], false)) {
                        indexIfChange = n;
                    }
                }
            } else if (line.startsWith("no interface ")) {
                indexIfDelete = n;
            }
        }
        traceVerbose(worker, "reorder: indexIfAdd="+indexIfAdd+" indexIfChange="+indexIfChange
                     +" indexIfDelete="+indexIfDelete);

        if (indexIfAdd > indexIfChange && indexIfAdd > indexIfDelete) {
            return lines;
        }


        //
        // First - pre-inject defaulting of deleted interfaces
        //
        StringBuilder sb = new StringBuilder();
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            if (line.isEmpty()) {
                continue;
            }
            if (!line.startsWith("no interface ")) {
                continue;
            }

            String ifline = getMatch(line, "no (interface \\S+)");
            traceInfo(worker, "transformed => pre-injected 'default "+ifline+"'");

            sb.append("default "+ifline+"\n");

            // Trim all previous changes on this interface
            for (int i = 0; i < n; i++) {
                line = lines[i];
                if (line.isEmpty()) {
                    continue;
                }
                if (!line.equals(ifline)) {
                    continue;
                }
                for (; i < lines.length; i++) {
                    line = lines[i];
                    lines[i] = "";
                    if (isTopExit(line)) {
                        break;
                    }
                }
            }
        }


        //
        // Second - pre-inject delete of interface address and vrf
        //
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            if (line.isEmpty()) {
                continue;
            }
            if (!line.startsWith("interface ")) {
                continue;
            }

            // Find last delete line and interface exit
            int last = -1;
            int exit;
            for (exit = n + 1; exit < lines.length; exit++) {
                if (isTopExit(lines[exit])) {
                    break;
                }
                if (isIfInjectLine(lines[exit], false)) {
                    last = exit;
                }
            }

            // Pre-inject all relevant delete lines
            if (last != -1) {
                traceInfo(worker, "transformed => pre-injected "+(last-n)+" '"+line+"' changes");
                sb.append(line+"\n");
                for (int j = n + 1; j <= last; j++) {
                    if (isIfInjectLine(lines[j], false)) {
                        sb.append(lines[j]+"\n");
                        lines[j] = "";
                    }
                }
                sb.append("exit\n");

                // If interface no longer has any changes, trim it here
                boolean empty = true;
                for (int j = n + 1; j < exit; j++) {
                    if (!lines[j].isEmpty()) {
                        empty = false;
                        break;
                    }
                }
                if (empty) {
                    lines[exit] = "";
                    traceVerbose(worker, "dropped empty '"+line+"' entry");
                    continue; // Drop interface line by continuing
                }
            }
        }

        if (logVerbose) {
            sb.insert(0, "!START auto/if-address-delete-patch\n");
            sb.append("!END auto/if-address-delete-patch\n");
        }

        //
        // Third - rebuild the buffer and split to lines
        //
        for (int n = 0; n < lines.length; n++) {
            String line = lines[n];
            if (line.isEmpty()) {
                continue;
            }
            sb.append(line+"\n");
        }
        return sb.toString().split("\n");
    }


    /**
     * Check if a line has to be pre-injected if deleted with changes
     * @param
     * @return
     */
    private boolean isIfInjectLine(String line, boolean add) {
        String[] lines = {
            " ip address",
            " ipv6 address",
            " vrf forwarding",
            " ip vrf forwarding"
        };
        for (int i = 0; i < lines.length; i++) {
            if (add && line.startsWith(lines[i]+" ")) {
                return true;
            }
            if (!add && line.startsWith(" no"+lines[i])) {
                return true;
            }
        }
        return false;
    }


    /**
     *
     * @param
     * @return
     */
    private String replaceCommitData(NedWorker worker, String data) {
        for (int n = 0; n < replaceCommit.size(); n++) {
            String[] entry = replaceCommit.get(n);
            String regexp = entry[1];
            String replacement = entry[2];
            try {
                Pattern p = Pattern.compile(regexp, Pattern.DOTALL);
                Matcher m = p.matcher(data);
                StringBuffer sb = new StringBuffer();
                while (m.find()) {
                    traceInfo(worker, "transformed => replaced "+stringQuote(m.group(0))+" with " + matcherToString(m, replacement));
                    m.appendReplacement(sb, replacement); // note: not quoted, want regexp replacements
                }
                m.appendTail(sb);
                data = sb.toString();
            } catch (Exception e) {
                logError(worker, "ERROR in replace-commit '"+entry[0]+"' regexp="+stringQuote(regexp)+" replacement="+stringQuote(replacement), e);
            }
        }
        return data;
    }


    /**
     *
     * @param
     * @throws Exception
     */
    protected void enterConfig(NedWorker worker) throws NedException, IOException, SSHSessionException {

        if (inConfig) {
            traceVerbose(worker, "NOTICE: already in config mode");
            return;
        }

        session.print("config t\n");
        NedExpectResult res = session.expect(EC, worker);

        if (res.getHit() > 2) {
            // Aborted | Error | syntax error | error
            throw new NedException("failed to enter config mode");
        }
        else if (res.getHit() == 0) {
            // Do you want to kill that session and continue
            session.print("yes\n");
            res = session.expect(EC2, worker);
            if (res.getHit() > 2) {
                // Aborted | Error | syntax error | error
                throw new NedException("failed to enter config mode");
            }
        }
        inConfig = true;
    }


    /**
     *
     * @param
     * @throws Exception
     */
   protected void exitConfig(NedWorker worker)
        throws IOException, SSHSessionException {
        NedExpectResult res;

        traceVerbose(worker, "exitConfig()");

        while (true) {
            session.print("exit\n");
            res = session.expect(new String[] {
                    "\\A\\S*\\(config\\)#",
                    "\\A\\S*\\(cfg\\)#",
                    "\\A.*\\(.*\\)#",
                    "\\A\\S*\\(cfg.*\\)#",
                    PROMPT}, worker);
            if (res.getHit() == 4) {
                inConfig = false;
                return;
            }
        }
    }


    /**
     *
     * @param
     * @throws Exception
     */
    private void sendConfig(NedWorker worker, int cmd, String[] lines)
        throws NedException, IOException, SSHSessionException, ApplyException {

        warningsBuf = "";

        lastTimeout = setReadTimeout(worker);
        String trimmed = "";
        try {
            // Set reboot timer
            long lastReboot = 0;
            if (applyRebootTimer > 0) {
                setReload(worker, applyRebootTimer, true);
                lastReboot = System.currentTimeMillis();
            }

            // Send commands to device
            String meta = "";
            String toptag = "";
            for (int n = 0 ; n < lines.length ; n++) {
                trimmed = lines[n].trim();
                if (trimmed.isEmpty()) {
                    continue;
                }

                // Modify toptag
                if (isTopExit(lines[n])) {
                    toptag = "";
                } else if (Character.isLetter(lines[n].charAt(0))) {
                    toptag = trimmed;
                }

                // Ignore sending meta-data to device, cache it for checks
                if (trimmed.startsWith("! meta-data :: ")) {
                    meta += (trimmed + "\n");
                    continue;
                }

                // Bulk mode, send chunk of commands before checking replies
                if (chunkSize > 1) {
                    int e;
                    for (e = n; e < lines.length; e++) {
                        int bulk = isBulkConfig(lines[e]);
                        if (bulk == 0) {
                            break;
                        }
                        if (bulk == 1) {
                            continue;
                        }
                        for (e = e + 1; e < lines.length; e++) {
                            if (isTopExit(lines[e])) {
                                break;
                            }
                        }
                    }
                    if (e - n > 1) {
                        sendBulkConfig(worker, lines, n, e);
                        n = e - 1;
                        continue;
                    }
                }

                // Ignore all other comments
                if (trimmed.startsWith("!")) {
                    continue;
                }

                // DIRTY patch for interface / speed & duplex ordering
                if (toptag.startsWith("interface ")) {
                    if (trimmed.startsWith("duplex ")) {
                        int speed = interfaceGetLine(lines, "speed\\s+\\S+", n+1);
                        if (speed > 0) {
                            try {
                                // Send duplex command
                                print_line_wait(worker, cmd, trimmed, 0, meta, n);
                                meta = "";
                                continue;
                            } catch (ApplyException failed) {
                                // duplex command failed, inject the speed command and retry
                                traceInfo(worker, "RUNPATCH: injected speed to solve speed/duplex ordering issue");
                                print_line_wait(worker, cmd, lines[speed].trim(), 0, meta, n);
                                lines[speed] = "";
                            }
                        }
                    }
                    else if (trimmed.startsWith("speed ")) {
                        int duplex = interfaceGetLine(lines, "duplex\\s+\\S+", n+1);
                        if (duplex > 0) {
                            try {
                                // Send speed command
                                print_line_wait(worker, cmd, trimmed, 0, meta, n);
                                meta = "";
                                continue;
                            } catch (ApplyException failed) {
                                // speed command failed, inject the duplex command and retry
                                traceInfo(worker, "RUNPATCH: injected duplex to solve speed/duplex ordering issue");
                                print_line_wait(worker, cmd, lines[duplex].trim(), 0, meta, n);
                                lines[duplex] = "";
                            }
                        }
                    }
                }

                // Text mode
                waitForEcho = Echo.WAIT;
                trimmed = modifyTexts(worker, trimmed);
                if (waitForEcho == Echo.TEXT) {
                    if (trimmed.contains("\t")) {
                        waitForEcho = Echo.DONTWAIT;
                        traceInfo(worker, "Enabling dontwait");
                    } else {
                        String[] textlines = trimmed.split("\\n");
                        traceInfo(worker, "Sending '"+textlines[0]+"' -> enabling text mode");
                    }
                }

                // Reset reboot timer
                if (applyRebootTimer > 0) {
                    final long time = System.currentTimeMillis();
                    final long diff = time - lastReboot; // in milliseconds
                    if (diff > (500 * 60 * applyRebootTimer)) {
                        setReload(worker, applyRebootTimer, true);
                        lastReboot = System.currentTimeMillis();
                    }
                }

                // Update timeout
                lastTimeout = resetReadTimeout(worker, lastTimeout);

                // Send line to device
                print_line_wait(worker, cmd, trimmed, 0, meta, n);
                meta = "";
            } // for(;;)

        } catch (ApplyException e) {
            if (e.inConfigMode) {
                exitConfig(worker);
            }
            if (applyRebootTimer > 0) {
                setReload(worker, 0, false);
            }
            logInfo(worker, "DONE "+nedCmdFullName(cmd)+" - ERROR sending: "
                    +stringQuote(e.getMessage())+" "+tickToString(lastTimeout));
            throw e;
        }

        if (applyRebootTimer > 0) {
            try {
                setReload(worker, 0, true);
            } catch (Exception ignore) {
                // Ignore Exception
            }
        }
    }


    /**
     *
     * @param
     * @return
     */
    private int isBulkConfig(String line) {
        String cmd = line.startsWith("no ") ? line.substring(3) : line;

        // Non-mode lists
        String[] nonModeLists = {
            "access-list ",
            "ip as-path access-list ",
            "ip community-list ",
            "ip prefix-list ",
            "ip route"
        };
        for (int n = 0; n < nonModeLists.length; n++) {
            if (cmd.startsWith(nonModeLists[0])) {
                return 1;
            }
        }

        // Mode lists
        String[] modeLists = {
            "class-map ",
            "ip access-list ",
            "ip explicit-path ",
            "ipv6 access-list ",
            "policy-map ",
            "route-map "
        };
        for (int n = 0; n < modeLists.length; n++) {
            if (line.startsWith(modeLists[0])) {
                return 2;
            }
            if (line.startsWith("no "+modeLists[0])) {
                return 1;
            }
        }

        return 0;
    }


    /**
     *
     * @param
     * @throws Exception
     */
    private void sendBulkConfig(NedWorker worker, String[] lines, int start, int end)
        throws NedException, IOException, SSHSessionException, ApplyException {
        int n;
        int length = end - start;

        traceInfo(worker, "BULK SENDING "+length+" lines [chunk "+chunkSize+"]");

        lastTimeout = setReadTimeout(worker);
        for (int i = start; i < end; i += chunkSize) {

            // Copy in up to chunkSize config commands in chunk
            String chunk = "";
            int num;
            for (num = 0, n = i; n < end && n < (i + chunkSize); n++) {
                String line = lines[n];
                if (line == null || line.isEmpty()) {
                    continue;
                }
                String trimmed = line.trim();
                if (trimmed.startsWith("! meta-data :: ")) {
                    continue;
                }
                if (trimmed.equals("!")) {
                    continue;
                }
                chunk += (line + "\n");
                num++;
            }

            // Send chunk of X lines to device
            traceVerbose(worker, "  BULK SENDING lines "+i+"-"+(i+num-1)+" / "+length);
            session.print(chunk);

            // Check device reply of one line at the time
            for (n = i; n < end && n < (i + chunkSize); n++) {
                String line = lines[n];
                if (line == null || line.isEmpty()) {
                    continue;
                }
                String trimmed = line.trim();
                if (trimmed.startsWith("! meta-data :: ")) {
                    continue;
                }
                if (trimmed.equals("!")) {
                    continue;
                }

                // Reset timeout if needed
                lastTimeout = resetReadTimeout(worker, lastTimeout);

                // Check device echo and possible input error
                noprint_line_wait(worker, trimmed);
            }
        }
    }


    /**
     * Set/cancel reload timer on device
     * @param
     * @throws Exception
     */
    private void setReload(NedWorker worker, int minutes, boolean configMode) throws ApplyException {

        // Prepare the command
        String cmd = "reload ";
        if (minutes > 0) {
            traceInfo(worker, "Setting REBOOT timer to "+minutes+" minutes");
            cmd += "in "+minutes;
        } else {
            traceInfo(worker, "Cancelling REBOOT timer");
            cmd += "cancel";
        }

        // Config mode
        String prompt = PRIVEXEC_PROMPT;
        if (configMode) {
            cmd = "do " + cmd;
            prompt = CONFIG_PROMPT;
        }

        // Run the reload command, wait for prompt and first notice
        try {
            session.println(cmd);
            while (true) {
                traceVerbose(worker, "Waiting for device");
                NedExpectResult res = session.expect(new String[] {
                        "System configuration has been modified",
                        "Proceed with reload",
                        prompt});
                if (res.getHit() == 0) {
                    session.println("no");
                } else if (res.getHit() == 1) {
                    session.println("");
                } else {
                    traceVerbose(worker, "Got prompt");
                    break;
                }
            }
            if (minutes > 0) {
                session.expect(new Pattern[] { Pattern.compile("SHUTDOWN in .*") }, worker);
            } else {
                session.expect(new Pattern[] { Pattern.compile("SHUTDOWN ABORTED .*") }, worker);
            }
            session.expect(prompt, worker);
        } catch (Exception e) {
            throw new ApplyException(cmd, "reload command failed", true, configMode);
        }
    }


    /**
     *
     * @param
     * @return
     */
    private int interfaceGetLine(String[] lines, String line, int i) {
        for (int n = i; n < lines.length; n++) {
            if (isTopExit(lines[n])) {
                break;
            }
            if (lines[n].trim().matches(line)) {
                return n;
            }
        }
        return -1;
    }


    /**
     *
     * @param
     * @throws Exception
     */
    private void print_line_wait(NedWorker worker, int cmd, String line,
                                 int retrying, String meta, int num)
        throws NedException, IOException, SSHSessionException, ApplyException {
        String orgLine = line;
        NedExpectResult res;
        boolean decrypted = false;

        // dirty patch to fix error that happens in timeout
        if (line.equals("config t")) {
            traceVerbose(worker, "ignored malplaced 'config t'");
            return;
        }

        // Modify tailfned police for testing
        if (line.startsWith("tailfned police ")) {
            iospolice = line.substring(16);
            traceInfo(worker, "SET tailfned police to: "+iospolice);
        }

        // Ignore setting/deleting tailfned 'config'
        if (isDevice()
            && (line.startsWith("tailfned ") || line.startsWith("no tailfned "))) {
            traceInfo(worker, "ignored tailfned config: " + line);
            return;
        }

        // Ignore setting/deleting cached-show 'config'
        if (line.trim().contains("cached-show ")) {
            traceInfo(worker, "ignored non-config: " + line);
            return;
        }

        // password - may be maapi encrypted, decrypt to cleartext
        if (meta != null &&
            (meta.contains(" :: secret") || meta.contains(" :: support-encrypted-password"))) {
            String decryptedLine = decryptPassword(worker, line);
            if (!decryptedLine.equals(line)) {
                decrypted = true;
                if (trace) {
                    worker.trace("*" + orgLine + "\n\n", "out", device_id);
                    if (!logVerbose) {
                        session.setTracer(null);
                    }
                }
                line = decryptedLine;
            }
        }

        // Send line (insert CTRL-V before all '?')
        traceVerbose(worker, "SENDING["+nedCmdName(cmd)+num+"]: '"+line+"'");
        session.print(stringInsertCtrlV(line) + "\n");

        // Optional delay, used e.g. to not overload link/device
        if (deviceOutputDelay > 0) {
            sleep(worker, deviceOutputDelay, false);
        }

        // Wait for echo
        if (waitForEcho == Echo.WAIT) {
            try {
                session.expect(new String[] { Pattern.quote(line) }, worker);
            } catch (SSHSessionException e) {
                throw new NedException(e.getMessage()+" sending '"+line+"' [previous sent cmd = '"+lastOKLine+"']");
            }
            //traceVerbose(worker, "got echo: '"+res.getMatch()+"'");
        }

        // Text mode, wait for echo for each line
        else if (waitForEcho == Echo.TEXT) {
            for (String wait: line.split("\n")) {
                try {
                    res = session.expect(new String[] { Pattern.quote(wait), " Invalid input detected at " }, worker);
                    if (res.getHit() == 1) {
                        throw new ApplyException(wait, res.getText(), true, true);
                    }
                } catch (SSHSessionException e) {
                    throw new NedException(e.getMessage()+" sending '"+line+"' [waiting for '"+wait+"']");
                }
            }
        }

        // Enable tracing if disabled due to sending decrypted clear text passwords
        if (decrypted) {
            if (trace) {
                session.setTracer(worker);
                worker.trace("*" + orgLine + "\n", "out", device_id);  // simulated echo
            }
            line = orgLine;
        }

        // Wait for prompt
        try {
            res = session.expect(plw, worker);
            //traceVerbose(worker, "prompt matched("+res.getHit()+"): text='"+res.getText() + "'");
        } catch (IOException e) {
            // Possibly a timeout, try return the input data from the buffer
            res = session.expect(new Pattern[] { Pattern.compile(".*", Pattern.DOTALL) }, true, 0);
            throw new NedException(e.getMessage()+" sending '"+line+"', blocked on '"+res.getMatch()+"'");
        }

        // Check for a blocking confirmation prompt
        if (waitForEcho == Echo.WAIT && res.getHit() >= 4) {
            traceVerbose(worker, "PROMPTED: " + res.getText());

            // Matched write/inject-answer
            if (res.getHit() >= PLW0.length) {
                // First check all entries, matching optional ml-question
                String[] entry = null;
                for (int n = 0; n < injectAnswer.size(); n++) {
                    entry = injectAnswer.get(n);
                    if (entry[3] == null) {
                        continue;
                    }
                    Pattern p = Pattern.compile(entry[3], Pattern.DOTALL);
                    Matcher m = p.matcher(res.getText());
                    if (m.find()) {
                        break;
                    }
                    entry = null;
                }
                if (entry == null) {
                    entry = injectAnswer.get(res.getHit() - PLW0.length);
                }
                traceInfo(worker, "Matched write/inject-answer "+entry[0]+": injecting answer "+stringQuote(entry[2]));
                session.print(entry[2]);
                // Note: do not wait for echo, can be passwords which are not echoed
                res = session.expect(plw, worker);
            }

            // Standard YES and NO questions
            else {
                // First try sending a 'y' only, wait 1 sec for prompt
                session.print("y");
                session.expect(new String[] { "y" }, worker);
                try {
                    res = session.expect(plw, false, 1000, worker);
                } catch (Exception e) {
                    // Timeout -> send 'es\n' for a full 'yes' + enter
                    session.print("es\n");
                    session.expect(new String[] { "es" }, worker);
                    res = session.expect(plw, worker);
                }
            }
        }

        // Get reply text (note: after confirm-questions for new text)
        String reply = res.getText();
        //traceVerbose(worker, "GOT REPLY='"+stringQuote(reply)+"'");

        // Check prompt
        switch (res.getHit()) {
        case 0:
        case 1:
        case 2:
            // config mode
            break;
        case 3:
            // exec mode
            inConfig = false;
            traceInfo(worker, "SENDING ERROR: command '"+line+"' caused exit from config mode");
            throw new ApplyException(line, "exited from config mode", true, false);
        default:
            exitPrompting(worker);
            traceInfo(worker, "SENDING ERROR: command '"+line+"' prompted twice");
            throw new ApplyException(line, "Internal ERROR: prompted twice", true, true);
        }

        // Look for retries
        if (isCliRetry(reply)) {
            // Wait a while and retry
            if (retrying >= configOutputMaxRetries) {
                // Already tried enough, give up
                throw new ApplyException(line, "["+retrying+" retries]: "+reply, true, true);
            }
            else {
                // Sleep a second, reset readTimeout and try same command again
                sleep(worker, 1000, true);
                setReadTimeout(worker);
                traceVerbose(worker, "Retry #" + (retrying+1));
                print_line_wait(worker, cmd, line, retrying+1, meta, num);
                return;
            }
        }

        if (waitForEcho == Echo.WAIT) {
            // Special line treatment
            if (isCliPatch(worker, cmd, reply, line, meta, num)) {
                print_line_wait(worker, cmd, line, retrying, meta, num);
                return;
            }

            // Look for errors
            if (isCliError(worker, cmd, reply, line, meta)) {
                throw new ApplyException(line, reply.trim(), true, true);
            }
        }

        // Retry succeeded, reset timeout
        if (retrying > 0) {
            traceInfo(worker, "Retry success after " + retrying + " retries");
            setReadTimeout(worker);
        }

        // Sleep three seconds for clear command to take effect (RT20042)
        if (line.equals("do clear crypto ikev2 sa fast")
            || line.startsWith("do clear ip nat ")) {
            resetTimeout(worker, this.readTimeout + 3000, 0);
            sleep(worker, 3000, true); // Sleep 3 seconds
        }

        lastOKLine = line;
    }


    /**
     *
     * @param
     * @throws Exception
     */
    private void noprint_line_wait(NedWorker worker, String trimmed)
        throws NedException, IOException, SSHSessionException, ApplyException {

        // Wait for echo
        session.expect(new String[] { Pattern.quote(trimmed) }, worker);

        // Second, wait for the prompt
        NedExpectResult res = session.expect(plw, worker);

        // Third, check if we exited config mode
        switch (res.getHit()) {
        case 0: // (cfg) - top mode
        case 1: // (config) - top mode
        case 2: // (.*) - sub-mode
            break;
        case 3: // exec mode
            inConfig = false;
            traceInfo(worker, "BULK SENDING ERROR: command '"+trimmed+"' caused exit from config mode");
            throw new ApplyException(trimmed, "exited from config mode", true, false);
        default:
            throw new ApplyException(trimmed, "Internal ERROR: device prompted", true, true);
        }

        // Verify no retry
        String reply = res.getText();
        if (isCliRetry(reply)) {
            throw new ApplyException(trimmed, "Internal ERROR: retry-command", true, true);
        }

        // Check for device error
        if (isCliError(worker, NedCmd.PREPARE_CLI, reply, trimmed, null)) {
            throw new ApplyException(trimmed, reply.trim(), true, true);
        }
    }


    /**
     * Check if command must be retried
     * @param
     * @return
     */
    private boolean isCliRetry(String reply) {

        if (reply.trim().isEmpty()) {
            return false;
        }

        // Ignore retry on these patterns:
        final String[] ignoreRetry = {
            "%(\\S+): (informational|error): \\S+ is in use on",
            "please remove .* from .* first",
            "is in use[.] remove from .* before deleting", // no flow monitor *
            "first remove .* from the above", // no crypto ipsec transform-set
            "\\S+ is in use and cannot be modify or delete"
        };
        for (int n = 0; n < ignoreRetry.length; n++) {
            if (findString(ignoreRetry[n], reply.toLowerCase()) >= 0) {
                return false;
            }
        }

        // Retry on these patterns:
        final String[] isRetry = {
            "is in use",
            "is still in use and cannot be removed",
            "wait for it to complete",
            "wait for the current operation to complete",
            "wait for current config download to complete",
            "Config update in progress; please wait and retry",
            "is currently being deconfigured",
            "is currently deactivating",
            "is being deleted, please try later",
            "is being deleted.* Try it later",
            "being configured in another session.* try again later",
            "are down, try again later",
            "Certificate server is busy, initial .* unable to be processed, try again later",
            "In-use PW template cannot be removed", // no template type pseudowire
            " already in use by VRF" // vrf definition * / rd
        };
        for (int n = 0; n < isRetry.length; n++) {
            if (findString(isRetry[n], reply) >= 0) {
                return true;
            }
        }

        // Do not retry
        return false;
    }


    /**
     *
     * @param
     * @return
     * @throws Exception
     */
    private boolean isCliPatch(NedWorker worker, int cmd, String reply, String line, String meta, int num)
        throws NedException, IOException, SSHSessionException, ApplyException {
        String match, res;

        // Changing track type
        if (line.startsWith("track ")
            && (match = getMatch(reply, "Cannot change tracked object (\\d+) - delete old config first")) != null) {
            traceInfo(worker, "RUNPATCH: injected track delete in order to change track type");
            print_line_wait(worker, cmd, "no track "+match, 0, meta, num);
            return true;
        }

        return false;
    }


    /**
     *
     * @param
     * @return
     */
    private boolean isCliError2(NedWorker worker, int cmd, String replyall, String reply, String line, String meta) {

        reply = reply.trim();
        if (reply.isEmpty()) {
            return false;
        }

        traceVerbose(worker, "Checking device reply "+stringQuote(reply));

        if (meta != null
            && line.startsWith("no ")
            && reply.contains("Invalid input detected at")
            && meta.contains("suppress-delete-error-invalid")) {
            traceVerbose(worker, "suppressed delete invalid error on: " + line);
            return false;
        }

        // Special cases ugly patches
        if (line.equals("no shutdown")
            && reply.contains("shutdown can't be applied on standby interface")) {
            // Happens if interface used as "backup interface"
            return false;
        }
        if (line.contains("no ip address ") && reply.contains("Invalid address")) {
            // Happens when IP addresses already deleted on interface
            return false;
        }
        if (line.contains("no ip address ") && reply.contains("Invalid address")) {
            // Happens when IP addresses already deleted on interface
            return false;
        }
        if ((line.equals("no duplex") || line.equals("no speed") || line.equals("speed auto"))
            && !reply.contains("Auto-negotiation is enabled. Speed cannot be set")) {
            // Ignore these errors because harmless and happen:
            // E.g. when 'no media-type' is deleted before duplex or speed
            // E.g. when 'no speed' is sent after negotiation auto
            // E.g. when no speed & speed auto are both sent
            traceInfo(worker, "Ignoring error/warning");
            return false;
        }
        if (line.equals("no mpls control-word")) {
            traceInfo(worker, "Ignoring '"+line+"' (cli-show-no)");
            return false;
        }
        if (line.contains("switchport") && reply.contains("Maximum number of interfaces reached")) {
            return true;
        }
        if (line.equals("no switchport")) {
            // Can't do no switchport on some devices:
            traceInfo(worker, "Ignoring non-required command");
            return false;
        }
        if (line.equals("switchport")) {
            // Some devices (e.g. 891) do not use switchport on single line.
            // Some devices do not support switchport on Port-channel if.
            traceInfo(worker, "Ignoring non-required command");
            return false;
        }
        if (line.startsWith("no interface LISP")
            && reply.contains("Invalid input detected at")) {
            // Delete of router lisp deletes LISP interfaces (which in turn can't be deleted first)
            traceInfo(worker, "Ignoring delete of missing LISP interface");
            return false;
        }
        if (line.contains("reporting smart-licensing-data")
            && reply.contains("Invalid input detected at")) {
            traceInfo(worker, "Ignoring non-required command");
            return false;
        }
        if (line.startsWith("ip redirects")
            && replyall.contains("ip redirect is not applicable for p2p link")) {
            traceInfo(worker, "Ignoring non-required command");
            return false;
        }
        if (line.startsWith("no interface ")
            && replyall.contains("Sub-interfaces are not allowed on switchports")) {
            traceInfo(worker, "Ignoring useless warning");
            return false;
        }

        if (reply.contains("Invalid input detected at")) {
            // Ignore Invalid input error on non-existing injected config
            for (int n = interfaceConfig.size()-1; n >= 0; n--) {
                String[] entry = interfaceConfig.get(n);
                if (findString(line, entry[1]) >= 0) {
                    trace(worker, "Ignoring non-supported injected interface config", "out");
                    return false;
                }
            }
            for (int n = injectConfig.size()-1; n >= 0; n--) {
                String[] entry = injectConfig.get(n);
                if (findString(line, entry[2]) >= 0) {
                    traceInfo(worker, "Ignoring non-supported injected config '"+entry[2]+"'");
                    return false;
                }
            }
        }

        // Error override messages
        String[] staticError = {
            "Error Message",
            "HARDWARE_NOT_SUPPORTED",
            " Incomplete command.",
            "password/key will be truncated to 8 characters",
            "Warning: Current config does not permit HSRP version 1",
            "Cannot modify internally generated "
        };
        for (int n = 0; n < staticError.length; n++) {
            if (findString(staticError[n], reply) >= 0) {
                traceInfo(worker, "ERROR SENDING - matched static error '"+reply+"'");
                return true;
            }
        }

        // Ignore static warnings
        for (int n = 0; n < staticWarning.length; n++) {
            if (findString(staticWarning[n], reply.toLowerCase()) >= 0) {
                traceInfo(worker, "ignoring static warning: "+stringQuote(staticWarning[n]));
                warningsBuf += "> "+line+"\n"+reply+"\n";
                return false;
            }
        }

        // Ignore dynamic warnings
        for (int n = 0; n < dynamicWarning.size(); n++) {
            if (findString(dynamicWarning.get(n), reply) >= 0) {
                traceInfo(worker, "ignoring dynamic warning: '"+reply+"'");
                warningsBuf += "> "+line+"\n"+reply+"\n" ;
                return false;
            }
        }

        // Ignore all errors when rollbacking due to abort (i.e. a previous error)
        if (cmd == NedCmd.ABORT_CLI) {
            traceInfo(worker, "ignoring ABORT error: '"+reply+"'");
            return false;
        }

        // Fail on all else
        traceInfo(worker, "ERROR SENDING - reply '"+reply+"'");
        return true;
    }


    /**
     *
     * @param
     * @return
     */
    private boolean isCliError(NedWorker worker, int cmd, String reply, String line, String meta) {

        // Strip shutdown info message(s)
        reply = reply.replaceAll("\\*\\*\\*\r\n\\*\\*\\* --- SHUTDOWN in \\S+ ---\r\n\\*\\*\\*\r\n", "");
        String replyall = reply;

        // Trim and check if empty reply
        reply = reply.replaceAll("\\r", "").trim();
        if (reply.isEmpty() || reply.length() <= 1) {
            return false;
        }

        // Strip echo of the failing command 'line'
        if (reply.contains("Invalid input")) {
            reply = reply.replace(line, "");
        }

        // Check all warnings, may be multiple
        reply = "\n" + reply;
        String[] warnings = reply.split("\n% ");
        for (int i = 0; i < warnings.length; i++) {
            String warning = warnings[i].trim();
            if (warning.isEmpty() || warning.length() <= 1) {
                continue;
            }
            if (isCliError2(worker, cmd, replyall, warning, line, meta)) {
                return true;
            }
        }
        return false;
    }


    /*
     **************************************************************************
     * persist
     **************************************************************************
     */

    /**
     * Persist (save) config on device
     * @param
     * @throws Exception
     */
    @Override
    public void persist(NedWorker worker) throws Exception {
        final long start = tick(0);
        if (trace) {
            session.setTracer(worker);
        }
        logInfo(worker, "BEGIN PERSIST");

        // Save config
        if (!ignoreNextWrite && this.writeMemoryMode.equals("on-persist")) {
            saveConfig(worker, NedCmd.PERSIST);
        }

        logInfo(worker, "DONE PERSIST "+tickToString(start));
        worker.persistResponse();
    }


    /**
     * Save configuration on device
     * @param
     * @throws Exception
     */
    private void saveConfig(NedWorker worker, int cmd) throws Exception {

        // Save running-config to startup-config
        print_line_wait_oper(worker, cmd, this.writeMemory, 0, writeTimeout);
    }


    /*
     **************************************************************************
     * commit
     **************************************************************************
     */

    /**
     * Commit config
     * @param
     * @throws Exception
     */
    @Override
    public void commit(NedWorker worker, int timeout) throws Exception {
        final long start = tick(0);
        if (trace) {
            session.setTracer(worker);
        }
        logInfo(worker, "BEGIN COMMIT");

        // Reconnect to device if remote end closed connection due to being idle
        if (session.serverSideClosed()) {
            traceInfo(worker, "Server side closed, reconnecting");
            connectorReconnectDevice(worker);
        }

        // Save config
        if (!ignoreNextWrite && this.writeMemoryMode.equals("on-commit")) {
            saveConfig(worker, NedCmd.COMMIT);
        }
        ignoreNextWrite = false;

        // Archive config
        configArchive.archive(worker);

        logInfo(worker, "DONE COMMIT "+tickToString(start));
        worker.commitResponse();
    }


    /*
     **************************************************************************
     * abort
     **************************************************************************
     */

    /**
     * apply failed, rollback config
     * @param
     * @throws Exception
     */
    @Override
    public void abort(NedWorker worker, String data) throws Exception {
        final long start = tick(0);
        if (trace) {
            session.setTracer(worker);
        }
        logInfo(worker, "BEGIN ABORT");

        // Apply the abort
        doApplyConfig(worker, NedCmd.ABORT_CLI , data);

        logInfo(worker, "DONE ABORT "+tickToString(start));
        worker.abortResponse();
    }


    /*
     **************************************************************************
     * revert
     **************************************************************************
     */

    /**
     * Revert config
     * @param
     * @throws Exception
     */
    @Override
    public void revert(NedWorker worker, String data) throws Exception {
        final long start = tick(0);
        if (trace) {
            session.setTracer(worker);
        }
        logInfo(worker, "BEGIN REVERT");

        // Apply the revert
        doApplyConfig(worker, NedCmd.REVERT_CLI, data);

        // Save config
        if ("on-commit".equals(this.writeMemoryMode)) {
            saveConfig(worker, NedCmd.REVERT_CLI);
        }

        // Archive config
        configArchive.archive(worker);

        logInfo(worker, "DONE REVERT "+tickToString(start));
        worker.revertResponse();
    }


    /*
     **************************************************************************
     * command
     **************************************************************************
     */

    /**
     * Run command(s) on device.
     * From ncs_cli: devices device <dev> live-status exec any "command"
     * @param
     * @throws Exception
     */
    @Override
    public void command(NedWorker worker, String cmdName, ConfXMLParam[] p) throws Exception {
        if (trace) {
            session.setTracer(worker);
        }

        // Prepare command
        String cmd = nedCommand.prepare(worker, cmdName, p);

        // internal - show warnings
        String reply;
        if (cmd.equals("show warnings")) {
            reply = "\nWarnings/output since last commit: \n"+ warningsBuf;
        }

        // internal - show ned-settings
        else if (cmd.equals("show ned-settings")) {
            reply = "\n"+nedSettings.dumpAll();
        }

        // internal - show outformat raw
        else if (cmd.equals("show outformat raw")) {
            reply = "\nNext dry-run will show raw (unmodified) format.\n";
            showRaw = true;
        }

        // internal - set iosmodel
        else if (cmd.startsWith("set iosmodel ")) {
            iosmodel = cmd.substring(13);
            reply = "\niosmodel set to '"+iosmodel+"'";
        }

        // internal - secrets resync
        else if (cmd.equals("secrets resync")) {
            secrets.enableReSync();
            String config = getConfig(worker);
            modifyInput(worker, false, -1, config);
            reply = "\nRe-synced all cached secrets.\n";
        }

        // internal - sync-from-file <path/file>
        else if (cmd.startsWith("sync-from-file ")) {
            syncFile = cmd.trim().substring(15).trim();
            reply = "\nNext sync-from will use file = " + syncFile + "\n";
        }

        // Device command
        else {
            nedCommand.execute(worker, cmd);
            return;
        }

        // Internal command reply
        logInfo(worker, "COMMAND - internal: "+stringQuote(cmd));
        traceInfo(worker, reply);
        worker.commandResponse(new ConfXMLParam[] { new ConfXMLParamValue("ios-stats", "result", new ConfBuf(reply))});
    }


    /**
     * Exit prompting
     * @param
     * @throws Exception
     */
    protected void exitPrompting(NedWorker worker) throws IOException, SSHSessionException {

        Pattern[] cmdPrompt = new Pattern[] {
            // Prompt patterns:
            Pattern.compile(PRIVEXEC_PROMPT),
            Pattern.compile("\\A.*\\(.*\\)#"),
            Pattern.compile("\\A\\S*#"),
            // Question patterns:
            Pattern.compile(":\\s*$"),
            Pattern.compile("\\]\\s*$")
        };

        while (true) {
            traceVerbose(worker, "SENDING CTRL-C");
            session.print("\u0003");
            traceVerbose(worker, "Waiting for non-question");
            NedExpectResult res = session.expect(cmdPrompt, true, readTimeout, worker);
            if (res.getHit() <= 2) {
                traceVerbose(worker, "Got prompt ("+res.getHit()+")");
                return;
            }
        }
    }


    /*
     **************************************************************************
     * keepAlive
     **************************************************************************
     */

    /**
     * This method is invoked periodically to keep an connection
     * alive. If false is returned the connection will be closed using the
     * close() method invocation.
     *
     * @param worker
     */
    public boolean keepAlive(NedWorker worker) {
        final long start = tick(0);
        if (trace) {
            session.setTracer(worker);
        }
        logInfo(worker, "BEGIN KEEP-ALIVE");
        boolean alive = true;
        try {
            if (session.serverSideClosed()) {
                traceInfo(worker, "Server side closed, reconnecting");
                connectorReconnectDevice(worker);
            } else {
                traceVerbose(worker, "Sending newline");
                session.println("");
                traceVerbose(worker, "Waiting for prompt");
                session.expect(new String[] { CONFIG_PROMPT, PRIVEXEC_PROMPT}, worker);
            }
        } catch (Exception e) {
            alive = false;
            logError(worker, "KEEP_ALIVE ERROR: "+e.getMessage(), e);
        }
        logInfo(worker, "DONE KEEP-ALIVE = "+alive+" "+tickToString(start));
        return alive;
    }


    /*
     **************************************************************************
     * NedSecrets
     **************************************************************************
     */

    /**
     * Used by NedSecrets to check whether a secret is cleartext or encrypted.
     * Method must be implemented by all NED's which use NedSecrets.
     * @param secret - The secret
     * @return True if secret is cleartext, else false
     */
    @Override
    public boolean isClearText(String secret) {
        String trimmed = secret.trim();

        // encrypted
        if (secret.matches("[0-9a-f]{2}(:([0-9a-f]){2})+")) {
            return false;  // aa:11 .. :22:bb
        }
        if (trimmed.contains(" encrypted")) {
            return false;  // XXX encrypted
        }
        if (trimmed.startsWith("password ")) {
            return false;  // password XXX
        }
        if (trimmed.endsWith(" 7")) {
            return false;  // XXX 7
        }
        if (getMatch(trimmed, "^([1-9] \\S+)") != null) {
            return false;  // [1-9] XXX
        }

        // Default to cleartext
        return true;
    }


    /*
     **************************************************************************
     * Common utility methods
     **************************************************************************
     */

    private void maapiAttach(NedWorker worker, int fromTh, int toTh) throws NedException {
        try {
            maapi.attach(fromTh, 0, worker.getUsid());
            maapi.attach(toTh, 0, worker.getUsid());
        } catch (Exception e) {
            throw new NedException("Internal ERROR: maapiAttach()", e);
        }
    }

    private void maapiDetach(int fromTh, int toTh) throws NedException {
        try {
            maapi.detach(fromTh);
            maapi.detach(toTh);
        } catch (Exception e) {
            throw new NedException("Internal ERROR: maapiDetach(): "+e.getMessage(), e);
        }
    }


    /**
     *
     * @param
     * @throws Exception
     */
    private void print_line_wait_oper(NedWorker worker, int cmd, String line, int retrying)
        throws NedException, IOException, SSHSessionException, ApplyException {
        print_line_wait_oper0(worker, cmd, line, retrying, this.readTimeout);
    }

    private void print_line_wait_oper(NedWorker worker, int cmd, String line, int retrying, int timeout)
        throws NedException, IOException, SSHSessionException, ApplyException {
        print_line_wait_oper0(worker, cmd, line, retrying, timeout);
        setReadTimeout(worker);
    }

    private void print_line_wait_oper0(NedWorker worker, int cmd, String line, int retrying, int timeout)
        throws NedException, IOException, SSHSessionException, ApplyException {

        traceVerbose(worker, "SENDING_OPER: '"+line+"'");

        // Send line and wait for echo
        session.print(line+"\n");
        session.expect(new String[] { Pattern.quote(line) }, worker);

        // Reset timeout after echo in case expect() reset timeout or echo slow
        resetTimeout(worker, timeout, 0);

        // Wait for prompt
        boolean loop = true;
        NedExpectResult res = null;
        while (loop) {
            traceVerbose(worker, "Waiting for oper prompt");
            res = session.expect(new String[] {
                    "Overwrite the previous NVRAM configuration\\?\\[confirm\\]",
                    "Warning: Saving this config to nvram may corrupt any network",
                    "Destination filename \\[\\S+\\][\\?]?\\s*$",
                    PRIVEXEC_PROMPT}, worker);
            String failtxt = res.getText();
            switch (res.getHit()) {
            case 0:
                // Overwrite the previous NVRAM configuration
                traceVerbose(worker, "Sending 'y'");
                session.print("y");
                break;
            case 1:
                // Warning: Saving this config to nvram may corrupt any network
                // management or security files stored at the end of nvram.
                // Continue? [no]: no
                // % Configuration buffer full, can't add command: access-list 99
                // %Aborting Save. Compress the config,
                // Save it to flash or Free up space on device[OK]
                // Confirm question with "n", wait for prompt again then fail
                traceVerbose(worker, "Sending 'n'");
                session.print("n");
                session.expect(new String[] {".*#"}, worker);
                throw new ApplyException(line, failtxt, true, false);
            case 2:
                // Destination filename
                traceInfo(worker, "Sending newline (destination filename)");
                session.print("\r\n");
                break;
            default:
                loop = false;
                break;
            }
        }

        //
        // Check device reply
        //

        // Retries
        String reply = res.getText().trim();
        if (reply.contains("Device or resource busy")) {
            if (retrying >= configOutputMaxRetries) {
                throw new ApplyException(line, reply, true, false); // Give up retrying
            }
            sleep(worker, 1000, true); // sleep a second
            print_line_wait_oper(worker, cmd, line, retrying + 1);
            return;
        }

        // Errors
        if (reply.toLowerCase().contains("error")
            || reply.toLowerCase().contains("failed")) {

            // Ignore dynamic warnings
            for (int n = 0; n < dynamicWarning.size(); n++) {
                if (findString(dynamicWarning.get(n), reply) >= 0) {
                    traceInfo(worker, "ignoring dynamic oper warning on: "+stringQuote(reply));
                    return;
                }
            }

            // Throw exception
            throw new ApplyException(line, reply, true, false);
        }
    }


    /**
     *
     * @param
     * @return
     * @throws Exception
     */
    protected String print_line_exec(NedWorker worker, String line) throws Exception {

        // Send command and wait for echo
        session.print(line + "\n");
        session.expect(new String[] { Pattern.quote(line) }, worker);

        // Return command output
        return session.expect(PRIVEXEC_PROMPT, worker);
    }

    protected String print_line_exec(NedWorker worker, String line, int timeout) throws Exception {

        // Send command and wait for echo
        session.print(line + "\n");
        session.expect(new String[] { Pattern.quote(line) }, worker);

        // Reset timeout after echo in case expect() reset timeout or echo slow
        this.lastTimeout = resetTimeout(worker, timeout, 0);

        // Return command output
        return session.expect(PRIVEXEC_PROMPT, worker);
    }


    /**
     * Send newline to device
     * @param
     * @throws Exception
     */
    private void sendNewLine(NedWorker worker, String logtext) throws Exception {
        traceInfo(worker, logtext);
        session.print("\r\n");
    }


    /**
     *
     * @param
     * @return
     * @throws NedException
     */
    private boolean maapiExists(NedWorker worker, int th, String path) throws NedException {
        try {
            if (maapi.exists(th, path)) {
                traceVerbose(worker, "maapiExists("+path+") = true");
                return true;
            }
        } catch (Exception e) {
            throw new NedException("maapiExists("+path+") ERROR : " + e.getMessage());
        }

        traceVerbose(worker, "maapiExists("+path+") = false");
        return false;
    }


    /**
     *
     * @param
     * @return
     */
    private String maapiGetLeafString(int th, String path) {
        // Trim to absolute path
        int up;
        while ((up = path.indexOf("/../")) > 0) {
            int slash = path.lastIndexOf('/', up-1);
            path = path.substring(0, slash) + path.substring(up + 3);
        }
        // Get leaf
        try {
            if (maapi.exists(th, path)) {
                return ConfValue.getStringByValue(path, maapi.getElem(th, path));
            }
        } catch (Exception e) {
            // Ignore Exception
        }
        return null;
    }


    /**
     *
     * @param
     * @return
     */
    private boolean hasPolice(String police) {
        return iospolice.contains(police);
    }


    /**
     *
     * @return
     */
    private boolean isDevice() {
        return !isNetsim();
    }


    /**
     *
     * @return
     */
    @Override
    public boolean isNetsim() {
        return iosmodel.contains("NETSIM");
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
     *
     * @param
     * @return
     */
    private boolean writeFile(String text, String file) {
        try (
             java.io.BufferedWriter writer = new java.io.BufferedWriter(new java.io.FileWriter(file))
             ) {
            writer.write(text);
        } catch (java.io.IOException e) {
            return false;
        }
        return true;
    }


    /**
     *
     * @param
     * @return
     * @throws NedException
     */
    private String injectData(NedWorker worker, String data, String[] entry, String dir)
        throws NedException {
        String insert;

        if (entry[3] == null) {
            throw new NedException("ned-settings: Missing 'where' leaf config");
        }

        Pattern p = Pattern.compile(entry[1]+"(?:[\r])?[\n]", Pattern.DOTALL);
        Matcher m = p.matcher(data);

        // Special (slow) case for after-last
        if (entry[3].equals("after-last")) {
            int end = -1;
            String[] groups = null;
            while (m.find()) {
                end = m.end(0);
                groups = fillGroups(m);
            }
            if (end != -1) {
                try {
                    insert = fillInjectLine(worker, entry[2] + "\n", entry[3], groups, dir);
                } catch (Exception e) {
                    throw new NedException("malformed inject regexp '"+entry[1]+"' : "+e.getMessage());
                }
                data = data.substring(0, end) + insert + "\n" + data.substring(end);
            }
        }

        else {
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                String replacement = m.group(0);
                try {
                    insert = fillInjectLine(worker, entry[2] + "\n", entry[3], fillGroups(m), dir);
                } catch (Exception e) {
                    throw new NedException("malformed inject regexp '"+entry[1]+"' : "+e.getMessage());
                }
                if (entry[3].equals("before-first")) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(insert + replacement));
                    break;
                } else if (entry[3].equals("before-each")) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(insert + replacement));
                } else if (entry[3].equals("after-each")) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(replacement + insert));
                }
            }
            m.appendTail(sb);
            data = sb.toString();
        }

        return data;
    }


    /**
     *
     * @param
     * @return
     * @throws NedException
     */
    private String fillInjectLine(NedWorker worker, String insert, String where, String[] groups, String dir)
        throws NedException {
        int i, offset = 0;

        // Replace $i with group value from match.
        // Note: hard coded to only support up to $9
        for (i = insert.indexOf('$'); i >= 0; i = insert.indexOf('$', i+offset)) {
            int num = (int)(insert.charAt(i+1) - '0');
            insert = insert.substring(0,i) + groups[num] + insert.substring(i+2);
            offset = offset + groups[num].length() - 2;
        }

        traceInfo(worker, "transformed "+dir+" injected "+stringQuote(insert)+" "+where+" "+stringQuote(groups[0]));

        return insert;
    }


    /**
     *
     * @param
     * @return
     */
    protected String tickToString(long start) {
        long stop = tick(start);
        return String.format("[%d ms]", stop);
    }


    /**
     *
     * @param
     */
    private void sleep(NedWorker worker, long milliseconds, boolean log) {
        if (log) {
            traceVerbose(worker, "Sleeping " + milliseconds + " milliseconds");
        }
        try {
            Thread.sleep(milliseconds);
            if (log) {
                traceVerbose(worker, "Woke up from sleep");
            }
        } catch (InterruptedException e) {
            traceInfo(worker, "sleep interrupted");
            Thread.currentThread().interrupt();
        }
    }


    /**
     *
     * @param
     * @return
     */
    private String decryptPassword(NedWorker worker, String line) {
        Pattern p = Pattern.compile("( \\$[48]\\$[^\\s]*)"); // " $4$<key>" || " $8<key>"
        Matcher m = p.matcher(line);
        while (m.find()) {
            String password = line.substring(m.start() + 1, m.end());
            try {
                traceVerbose(worker, "decryptPassword: "+stringQuote(password));
                String decrypted = mCrypto.decrypt(password);
                traceVerbose(worker, "transformed => decrypted MAAPI password: "+password);
                line = line.substring(0, m.start()+1)
                    + decrypted
                    + line.substring(m.end(), line.length());
            } catch (Exception e) {
                // Ignore exceptions, since can't tell if $8 is NSO or IOS encrypted
                return line;
            }
            m = p.matcher(line);
        }
        return line;
    }


    /**
     *
     * @param
     * @return
     */
    static private String nedCmdName(int cmd) {
        if (cmd == NedCmd.ABORT_CLI) {
            return "abort ";
        }
        if (cmd == NedCmd.REVERT_CLI) {
            return "revert ";
        }
        return "";
    }


    /**
     *
     * @param
     * @return
     */
    static private String nedCmdFullName(int cmd) {
        if (cmd == NedCmd.ABORT_CLI) {
            return "ABORT";
        }
        if (cmd == NedCmd.REVERT_CLI) {
            return "REVERT";
        }
        return "APPLY-CONFIG";
    }


    /**
     * Set user session
     * @throws Exception
     */
    private void setUserSession() throws Exception {
        try {
            maapi.getMyUserSession();
        } catch (Exception ignore) {
            maapi.setUserSession(1);
        }
    }


    /**
     *
     * @param
     * @return
     */
    private String stringInsertCtrlV(String line) {
        if (line.indexOf('?') < 0) {
            return line;
        }
        return line.replace("?", (char)(0x16)+"?");
    }


    /**
     *
     * @param
     * @return
     */
    private static String findLine(String buf, String search) {
        int i = buf.indexOf(search);
        if (i >= 0) {
            int nl = buf.indexOf('\n', i+1);
            if (nl >= 0) {
                return buf.substring(i,nl);
            } else {
                return buf.substring(i);
            }
        }
        return null;
    }


    /**
     *
     * @param
     * @return
     */
    private static String getString(String buf, int offset) {
        int nl = buf.indexOf('\n', offset);
        if (nl < 0) {
            return buf;
        }
        return buf.substring(offset, nl).trim();
    }


    /**
     *
     * @param
     * @return
     */
    private String stripLineAll(NedWorker worker, String res, String search) {
        StringBuilder buffer = new StringBuilder();
        String[] lines = res.split("\n");
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].trim().startsWith(search)) {
                traceVerbose(worker, "transformed <= stripped '"+lines[i]+"'");
                continue;
            }
            buffer.append(lines[i]+"\n");
        }
        return buffer.toString();
    }


    /**
     * Read file from disk
     * @param
     * @return
     * @throws Exception
     */
    private String readFile(String file) throws IOException {
        BufferedReader reader = new BufferedReader(new java.io.FileReader(file));
        String line = null;
        StringBuilder sb = new StringBuilder();
        try {
            while ((line = reader.readLine()) != null) {
                sb.append(line);
                sb.append("\r\n");
            }
            return sb.toString();
        } finally {
            reader.close();
        }
    }


    /**
     * Like NedString.stringDequote except that it preserves single backslash
     * @param
     * @return
     */
    private static String textDequote(String aText) {
        if (aText.indexOf('"') != 0) {
            return aText;
        }
        aText = aText.substring(1,aText.length()-1);
        StringBuilder result = new StringBuilder();
        StringCharacterIterator iterator =
            new StringCharacterIterator(aText);
        char c1 = iterator.current();
        while (c1 != CharacterIterator.DONE) {
            if (c1 == '\\') {
                char c2 = iterator.next();
                if (c2 == CharacterIterator.DONE) {
                    result.append(c1);
                } else if (c2 == 'b') {
                    result.append('\b');
                } else if (c2 == 'n') {
                    result.append('\n');
                } else if (c2 == 'r') {
                    result.append('\r');
                } else if (c2 == 'v') {
                    result.append((char) 11); // \v
                } else if (c2 == 'f') {
                    result.append('\f');
                } else if (c2 == 't') {
                    result.append('\t');
                } else if (c2 == 'e') {
                    result.append((char) 27); // \e
                } else if (c2 == '\\') {
                    result.append('\\');
                } else {
                    result.append(c1);
                    result.append(c2);
                }
            } else {
                result.append(c1);
            }
            c1 = iterator.next();
        }
        return result.toString();
    }

}
