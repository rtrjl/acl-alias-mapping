MAIN_YANG_MODULE = tailf-ned-cisco-ios.yang
PACKAGE_NAME=ios

PYANG_JSON_XARGS = --json-fwhen="^/policy-map/(class-default/)?class/inspect-police$$" \
	--json-fwhen="^/policy-map/(class-default/)?class/police-[^/]+/police$$" \
	--json-fwhen="^/snmp-server/community-list$$" \
	--json-fwhen="^/policy-map/(class-default/)?class/police-[^/]+/police/cir/percent$$" \
	--json-fwhen="^/crypto/map/seq-list/(gdoi-)?set$$" \
	--json-fwhen="^/ip/access-list/(standard|extended|filter-list|resequence)$$" \
	--json-fwhen="^/ip/prefix-list/.*$$" \
	--json-fwhen="^/ipv6/prefix-list/.*$$" \
	--json-fwhen="^/ipv6/access-list/(named-acl|filter-list)$$" \
	--json-frelaxed="^/policy-map/(class-default/)?class/police-policy-map/police$$"

all: all_cli

include nedcom.mk
ncsc-out/modules/fxs/ietf-ip.fxs: ncsc-out/modules/fxs/ietf-interfaces.fxs


#JAVA_SRC := $(JAVA_SRC) java/src/com/tailf/packages/ned/nexus/NexusNedLiveStatsMap.java

#java/src/com/tailf/packages/ned/nexus/NexusNedLiveStatsMap.java: \
#	tmp-yang/tailf-ned-cisco-nx-stats.yang info.awk
#	pyang -f yin $< | gawk -f info.awk > $@
