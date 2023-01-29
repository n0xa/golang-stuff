package main
// ipasn.go - Fetches the BGP ASN(s) and descriptions 
// for a given ip address
// ax0n@h-i-r.net | IG: @4x0nn | Twitter: @ax0n
import (
	"os"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type IpAsn struct {
	Status        string `json:"status"`
	StatusMessage string `json:"status_message"`
	Data          struct {
		IP        string `json:"ip"`
		PtrRecord string `json:"ptr_record"`
		Prefixes  []struct {
			Prefix string `json:"prefix"`
			IP     string `json:"ip"`
			Cidr   int    `json:"cidr"`
			Asn    struct {
				Asn         int    `json:"asn"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"asn"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
		} `json:"prefixes"`
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

// Check error f | reason: limit the use of if err != nil 
// x = input error
func CE(x error) {
	if x != nil {
		log.Panicln(err)
	}
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("IP Address needed")
		os.Exit(1)
	}

    ip := os.Args[1]

	var ipasn IpAsn
	resp, err := http.Get("https://api.bgpview.io/ip/" + ip)
	CE(err)
	// Read and display response body
	body, err := ioutil.ReadAll(resp.Body)
	CE(err)
	if err := json.Unmarshal([]byte(body), &ipasn); err != nil {
		fmt.Println(string(body))
		log.Panicln(err)
	}
	if len(ipasn.Data.Prefixes) > 0 {

		fmt.Printf("%6s | %2s | %-10s | %-25s\n", "ASNum", "CC", "Name", "Description")
    	for _, asn := range ipasn.Data.Prefixes {
			fmt.Printf("%6d | %2s | %-10s | %-25s\n", asn.Asn.Asn, asn.Asn.CountryCode, asn.Asn.Name, asn.Asn.Description)
   		 }
	}else{
		fmt.Println("BGPView Returned no ASN Prefixes.")
	}
    resp.Body.Close()
}
