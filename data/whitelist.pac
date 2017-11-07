var direct = "__DIRECT__";
if (direct == "__DIR" + "ECT__") direct = "DIRECT;";

var wall_proxy = function(){ return "__PROXY__"; };
var wall_v6_proxy = function(){ return "__PROXY__"; };

var nowall_proxy = function(){ return direct; };
var ip_proxy = function(){ return wall_proxy(); };
var ipv6_proxy = function(){ return wall_v6_proxy(); };

/*
 * Copyright (C) 2014 breakwa11
 * https://github.com/breakwa11/gfw_whitelist
 */

var cnIpRange = __IP_LIST__;
var cnIp16Range = __IP16_LIST__;

var whiteIpList = {
	"188.188.188.188":1,
	"100.100.100.100":1
};

var subnetIpRangeList = [
0,1,
167772160,184549376,	//10.0.0.0/8
2886729728,2887778304,	//172.16.0.0/12
3232235520,3232301056,	//192.168.0.0/16
2130706432,2130706688	//127.0.0.0/24
];

var white_domains = __DOMAINS__;

var hasOwnProperty = Object.hasOwnProperty;

function check_ipv4(host) {
	var re_ipv4 = /^\d+\.\d+\.\d+\.\d+$/g;
	if (re_ipv4.test(host)) {
		return true;
	}
}
function check_ipv6(host) {
	var re_ipv6 = /^\[?([a-fA-F0-9]{0,4}\:){1,7}[a-fA-F0-9]{0,4}\]?$/g;
	if (re_ipv6.test(host)) {
		return true;
	}
}
function check_ipv6_dns(dnsstr) {
	var re_ipv6 = /([a-fA-F0-9]{0,4}\:){1,7}[a-fA-F0-9]{0,4}(%[0-9]+)?/g;
	if (re_ipv6.test(dnsstr)) {
		return true;
	}
}
function convertAddress(ipchars) {
	var bytes = ipchars.split('.');
	var result = (bytes[0] << 24) |
	(bytes[1] << 16) |
	(bytes[2] << 8) |
	(bytes[3]);
	return result >>> 0;
}
function isInSingleRange(ipRange, intIp) {
	if ( hasOwnProperty.call(cnIp16Range, intIp >>> 6) ) {
		for ( var range = 1; range < 64; range*=4 ) {
			var master = intIp & ~(range-1);
			if ( hasOwnProperty.call(ipRange, master) )
				return intIp - master < ipRange[master];
		}
	} else {
		for ( var range = 64; range <= 1024; range*=4 ) {
			var master = intIp & ~(range-1);
			if ( hasOwnProperty.call(ipRange, master) )
				return intIp - master < ipRange[master];
		}
	}
}
function isInSubnetRange(ipRange, intIp) {
	for ( var i = 0; i < 10; i += 2 ) {
		if ( ipRange[i] <= intIp && intIp < ipRange[i+1] )
			return true;
	}
}
function getProxyFromIP(strIp) {
	var intIp = convertAddress(strIp);
	if ( isInSubnetRange(subnetIpRangeList, intIp) ) {
		return direct;
	}
	var index = (intIp >>> 24) & 0xff;
	if ( isInSingleRange(cnIpRange[index], intIp >>> 8) ) {
		return nowall_proxy();
	}
	if (hasOwnProperty.call(whiteIpList, strIp)) {
		return nowall_proxy();
	}
	return ip_proxy();
}
function isInDomains(domain_dict, host) {
	var suffix;
	var pos1 = host.lastIndexOf('.');

	suffix = host.substring(pos1 + 1);
	if (suffix == "cn") {
		return true;
	}

	var domains = domain_dict[suffix];
	if ( domains === undefined ) {
		return false;
	}
	host = host.substring(0, pos1);
	var pos = host.lastIndexOf('.');

	while(1) {
		if (pos <= 0) {
			if (hasOwnProperty.call(domains, host)) {
				return true;
			} else {
				return false;
			}
		}
		suffix = host.substring(pos + 1);
		if (hasOwnProperty.call(domains, suffix)) {
			return true;
		}
		pos = host.lastIndexOf('.', pos - 1);
	}
}
function FindProxyForURL(url, host) {
	if ( isPlainHostName(host) === true ) {
		return direct;
	}
	if ( check_ipv4(host) === true ) {
		return getProxyFromIP(host);
	}
	if ( check_ipv6(host) === true ) {
		return ipv6_proxy();
	}
	if ( isInDomains(white_domains, host) === true ) {
		return nowall_proxy();
	}
	return wall_proxy();
}

function FindProxyForURLEx(url, host) {
	if ( isPlainHostName(host) === true ) {
		return direct;
	}
	if ( check_ipv4(host) === true ) {
		return getProxyFromIP(host);
	}
	if ( check_ipv6(host) === true ) {
		return ipv6_proxy();
	}
	if ( isInDomains(white_domains, host) === true ) {
		return nowall_proxy();
	}
	return wall_proxy();
}
