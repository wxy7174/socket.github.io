package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"
)

func GetSSLInfoFromHost(host string) (dnsNameList, ipList, emailList []string) {
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: time.Second * 3,
	}, "tcp", host, nil)
	if err != nil {
		return
	}
	return GetSSLInfo(conn.ConnectionState().PeerCertificates)
}

func GetSSLInfo(data []*x509.Certificate) (dnsNameList, ipList, emailList []string) {
	for _, cert := range data {
		certDnsNameList := append(cert.DNSNames, cert.PermittedDNSDomains...)
		for _, dnsName := range certDnsNameList {
			dnsName = strings.Replace(dnsName, "*.", "", -1)
			dnsNameList = append(dnsNameList, dnsName)
		}
		for _, ip := range cert.IPAddresses {
			ipList = append(ipList, ip.String())
		}
		for _, ip := range cert.PermittedIPRanges {
			ipList = append(ipList, ip.String())
		}
		certEmailList := append(cert.EmailAddresses, cert.PermittedEmailAddresses...)
		for _, email := range certEmailList {
			emailList = append(emailList, email)
		}
		for _, url := range cert.URIs {
			dnsName := strings.Split(url.Host, ":")[0]
			dnsNameList = append(dnsNameList, dnsName)
		}
		for _, url := range cert.PermittedURIDomains {
			url = strings.Replace(url, "https://", "", -1)
			url = strings.Replace(url, "http://", "", -1)
			url = strings.Split(url, "/")[0]
			dnsName := strings.Split(url, ":")[0]
			dnsNameList = append(dnsNameList, dnsName)
		}
	}
	return
}

func main() {
	var host string
	flag.StringVar(&host, "host", "", "-host")
	flag.Parse()
	if host == "" {
		flag.Usage()
		return
	}
	fmt.Println(GetSSLInfoFromHost(host))
}
