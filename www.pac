function FindProxyForURL(url, host) {

    myip = myIpAddress();
    // alert("myIp: "+myip);
    alert("url: "+url);
    fnalurlpat = /http(s|):\/\/(www-tele)\.fnal\.gov/g;
    // cmsdaqpreseries at LHC Point 5
    if (shExpMatch(host,"*.cmsdaqpreseries")) {
        return "SOCKS5 127.0.0.1:1081";
    }
    // main cms network at LHC Point 5
    else if (shExpMatch(host,"*.cms")) {
        return "SOCKS5 127.0.0.1:1080";
    }
    // cmsdaqpreseries at LHC Point 5
    else if (isInNet(myip, "172.16.0.0",  "255.255.0.0"))    {
        return "SOCKS5 127.0.0.1:1080";
    }
    // main cms network at LHC Point 5
    else if (isInNet(myip, "10.176.0.0",  "255.255.0.0")
	     || shExpMatch(host,"cms-srv-*.cern.ch")
	    ) {
        return "SOCKS5 127.0.0.1:1080";
    }
    // internal-only CERN sites
    else if (shExpMatch(host,"oraweb.cern.ch")
             || shExpMatch(host,"service-dns.web.cern.ch")
             || shExpMatch(host,"cmsdbsfrontier?.cern.ch")
             || shExpMatch(host,"cmsdbssrv?.cern.ch")
             || shExpMatch(host,"cmsdbssrv.cern.ch")
             || shExpMatch(host,"cmslumi.cern.ch")
             || shExpMatch(host,"cmsdbsdev?.cern.ch")
             || shExpMatch(host,"cdbserv*.cern.ch")
             || shExpMatch(host,"vocms*.cern.ch")
             || shExpMatch(host,"voatlas*.cern.ch")
             || shExpMatch(host,"remedy*.cern.ch")
             || shExpMatch(host,"apex.cern.ch")
             || shExpMatch(host,"sir.cern.ch")
             || shExpMatch(host,"cta.cern.ch")
             || shExpMatch(host,"aislogin.cern.ch")
             || shExpMatch(host,"cmswttest.cern.ch")
             || shExpMatch(host,"pccmsdqm*.cern.ch")
             || shExpMatch(host,"cmsdaq*.cern.ch")
             || shExpMatch(host,"cmsrproxy.cern.ch")
             || shExpMatch(host,"phydb*.cern.ch")
             || shExpMatch(host,"cdbtrack*.cern.ch")
             || shExpMatch(host,"popcon*.cern.ch")
             || shExpMatch(host,"devfound.cern.ch")
             || shExpMatch(host,"lxserv*.cern.ch")
             || shExpMatch(host,"guppy.cern.ch")
             || shExpMatch(host,"cmsmonitoring.cern.ch")
             || shExpMatch(host,"swrep*.cern.ch")
             || shExpMatch(host,"cmspnp4nagios.cern.ch")
             || shExpMatch(host,"samdevatp.cern.ch")
             || shExpMatch(host,"gis.cern.ch")
             || shExpMatch(host,"cvmfs-stratum-zero.cern.ch")
             || shExpMatch(host,"cvmfs-monitor.cern.ch")
             || shExpMatch(host,"edh.cern.ch")
             || shExpMatch(host,"frontierluis.cern.ch")
             || shExpMatch(host,"openstack.cern.ch")
             || shExpMatch(host,"metricmgr.cern.ch")
             || shExpMatch(host,"lemon*.cern.ch")
             || shExpMatch(host,"timber.cern.ch")
             || shExpMatch(host,"it-div-assignments.web.cern.ch")
             || shExpMatch(host,"etf-lhcb-dev.cern.ch")
             || shExpMatch(host,"itmon-es-search.cern.ch")
             || shExpMatch(host,"aiermis.cern.ch")
             || shExpMatch(host,"network.cern.ch")
             || shExpMatch(host,"judy.cern.ch")
             || shExpMatch(host,"landb.cern.ch")
             || shExpMatch(host,"lbweb.web.cern.ch")
             || shExpMatch(host,"monit-timber.cern.ch")
             || shExpMatch(host,"keystone.cern.ch")
             || shExpMatch(host,"e-groups.cern.ch")
             || shExpMatch(host,"atlas-kibana-dev.mwt2.org")
             || shExpMatch(host,"*ipmi.cern.ch")
             || shExpMatch(host,"ca.cern.ch")
	     ) {
	// go direct if inside the CERN firewall
	if (isInNet(myip, "137.138.0.0","255.255.0.0")
	    || isInNet(myip, "128.142.0.0","255.255.0.0")
		|| isInNet(myip, "128.141.0.0","255.255.0.0")
	    ) {
	    return "DIRECT";
	}
        return "SOCKS5 127.0.0.1:1079";
    }
    // internal-only FNAL sites
    else if (fnalurlpat.test(url)
    	     || shExpMatch(host,"bss*.fnal.gov")
             || shExpMatch(host,"oidapp*.fnal.gov")
             || shExpMatch(host,"finance.fnal.gov")
             || shExpMatch(host,"fin-hrweb.fnal.gov")
             || shExpMatch(host,"hrweb.fnal.gov")
             || shExpMatch(host,"miscomp.fnal.gov")
             || shExpMatch(host,"appora*.fnal.gov")
             /* || shExpMatch(host,"wdrs.fnal.gov") */
             || shExpMatch(host,"intranet-int.fnal.gov")
             || shExpMatch(host,"cd-docdb.fnal.gov")
             || shExpMatch(host,"cmsganglia.fnal.gov")
             || shExpMatch(host,"tissue.fnal.gov")
             || shExpMatch(host,"fife.fnal.gov")
             || shExpMatch(host,"buildmaster.fnal.gov")
             || shExpMatch(host,"fermipayroll.fnal.gov")
             || shExpMatch(host,"hcmweb.fnal.gov")
             || shExpMatch(host,"computing.fnal.gov")
             || shExpMatch(host,"security.fnal.gov")
             || shExpMatch(host,"landscape*.fnal.gov")
             || shExpMatch(host,"eshq.fnal.gov")
             || shExpMatch(host,"fndca*.fnal.gov")
             || shExpMatch(host,"hr.fnal.gov")
	     // This one depends on network.proxy.autoconfig_url.include_path
	     //  being set to true in about:config
	     || shExpMatch(url,"*/news.fnal.gov/fermilab-at-work*")
	    ) {
	// go direct if inside the FNAL firewall
	// if (isInNet(myip, "131.225.0.0","255.255.0.0")) {
	//    alert("returning DIRECT");
	//    return "DIRECT";
	// }
        return "SOCKS5 127.0.0.1:1078";
    }
    // don't use proxies for https (SOCKS is OK)
    else if (shExpMatch(url, "https://*")) {
	// send through home LAN
	//return "SOCKS5 127.0.0.1:1077";
	return "DIRECT";
    }
    // cmsfrontier server
    else if (shExpMatch(host, "cmsfrontier*.cern.ch") &&
	isInNet(myip, "131.225.0.0","255.255.0.0") ) {
	return "PROXY http://cmsfrontier.fnal.gov:3128; DIRECT";
    }
                                                     
    // send through home LAN
    // return "SOCKS5 127.0.0.1:1077";
    // All other requests go directly to the WWW:
    return "DIRECT";
}
