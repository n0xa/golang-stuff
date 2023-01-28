package main
// asn.go - pulls ipv4 and ipv6 prefixes from a
// BGP Autonomous Systen Number.
// ax0n@h-i-r.net | IG: @4x0nn | Twitter: @ax0n
import (
	"os"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {

type IpAsn struct {
	Status        string `json:"status"`
	StatusMessage string `json:"status_message"`
	Data          struct {
		Ipv4Prefixes  []struct {
			Prefix      string `json:"prefix"`
			IP          string `json:"ip"`
			Cidr 	    int    `json:"cidr"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
		} `json:"ipv4_prefixes"`
		Ipv6Prefixes  []struct {
			Prefix      string `json:"prefix"`
			IP          string `json:"ip"`
			Cidr 	    int    `json:"cidr"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
		} `json:"ipv6_prefixes"`
		RirAllocation struct {
			RirName          string      `json:"rir_name"`
			CountryCode      interface{} `json:"country_code"`
			IP               string      `json:"ip"`
			Cidr             int         `json:"cidr"`
			Prefix           string      `json:"prefix"`
			DateAllocated    string      `json:"date_allocated"`
			AllocationStatus string      `json:"allocation_status"`
		} `json:"rir_allocation"`
		IanaAssignment struct {
			AssignmentStatus string      `json:"assignment_status"`
			Description      string      `json:"description"`
			WhoisServer      string      `json:"whois_server"`
			DateAssigned     interface{} `json:"date_assigned"`
		} `json:"iana_assignment"`
		Maxmind struct {
			CountryCode interface{} `json:"country_code"`
			City        interface{} `json:"city"`
		} `json:"maxmind"`
	} `json:"data"`
	Meta struct {
		TimeZone      string `json:"time_zone"`
		APIVersion    int    `json:"api_version"`
		ExecutionTime string `json:"execution_time"`
	} `json:"@meta"`
}

    if len(os.Args) < 2 {
      fmt.Println("ASN Required")
      os.Exit(1)
    }
    asn := os.Args[1]
    
	var ipasn IpAsn
	resp, err := http.Get("https://api.bgpview.io/asn/" + asn + "/prefixes")
	if err != nil {
		log.Panicln(err)
	}

	// Read and display response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Panicln(err)
	}
	if err := json.Unmarshal([]byte(body), &ipasn); err != nil {
		fmt.Println(string(body))
		log.Panicln(err)
	}
	if len(ipasn.Data.Ipv4Prefixes) > 0 {

		fmt.Printf("%6s | %2s | %-10s | %-25s\n", "Prefix", "CC", "Name", "Description")
    	for _, asn := range ipasn.Data.Ipv4Prefixes {
			fmt.Printf("%20s | %2s | %-20s | %-25s\n", asn.Prefix, asn.CountryCode, asn.Name, asn.Description)
   		 }
    	for _, asn := range ipasn.Data.Ipv6Prefixes {
			fmt.Printf("%20s | %2s | %-20s | %-25s\n", asn.Prefix, asn.CountryCode, asn.Name, asn.Description)
   		 }
	}else{
		fmt.Println("BGPView Returned no ASN Prefixes.")
	}
    resp.Body.Close()
}
