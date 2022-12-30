package main
// accepts an IP address as the first command line argument
// queries the bgpview.io API to display the hosting provider
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

    ip := os.Args[1]

	var ipasn IpAsn
	resp, err := http.Get("https://api.bgpview.io/ip/" + ip)
	if err != nil {
		log.Panicln(err)
	}

	// Read and display response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Panicln(err)
	}
	json.Unmarshal([]byte(body), &ipasn)
    for _, asn := range ipasn.Data.Prefixes {
	fmt.Printf("%20s | %25s\n", asn.Asn.Name, asn.Asn.Description)
    }
    resp.Body.Close()
}
