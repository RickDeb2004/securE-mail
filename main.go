package main

import (
	"bufio"
	"fmt"
	whois "github.com/likexian/whois"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("domain, hasMX, hasSPF, spfRecord,hasDMARC,dmarcRecord,owner,registrationStatus \n")
	for scanner.Scan() {
		checkDomain(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal("Error: could not read from the input: %v \n", err)
	}
}
func checkDomain(domain string) {

	var hasMX, hasSPF, hasDMARC bool
	var spfRecord, dmarcRecord string
	var owner, registrationStatus string
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		log.Printf("Error %v\n", err)
	}
	if len(mxRecords) > 0 {
		hasMX = true
	}
	TXTrecords, err := net.LookupTXT(domain)
	if err != nil {
		log.Printf("Error %v \n", err)

	}
	for _, TXTrecord := range TXTrecords {
		if strings.HasPrefix(TXTrecord, "v=spf1") {
			hasSPF = true
			spfRecord = TXTrecord
			break
		}
	}
	dmarcRecords, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		log.Printf("Error %v \n", err)
	}
	for _, record := range dmarcRecords {
		if strings.HasPrefix(record, "v=dmarc1") {
			hasDMARC = true
			dmarcRecord = record
			break
		}
	}
	whoisResult, err := whois.Whois(domain) //for retrieving additional ionfo about the registered owner
	if err != nil {
		log.Printf("No whois record found %v\n", err)
	}
	owner =extract(whoisResult,"Registrant Name")

	registrationStatus = extract(whoisResult,"Domain Status")

	fmt.Printf("%v %v %v %v %v %v %v %v\n", domain, hasMX, hasSPF, spfRecord, hasDMARC, dmarcRecord, owner, registrationStatus)
}
func extract(whoisResult, key string)string{
	lines:=strings.Split(whoisResult,"\n")
	for _,line:=range lines{
		if strings.HasPrefix(line,key){
			return strings.TrimSpace(strings.TrimPrefix(line,key))
		}
	}
	return ""
}