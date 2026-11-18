package honeylog

import (
	"strings"
	"testing"
)

// Lines as written by OpenCanary 0.9.10 on the first droplet (2026-11-18).
const ocSample = `{"dst_host": "10.0.0.5", "dst_port": 445, "local_time": "2026-11-18 08:36:43.973875", "logdata": {"BANNER_ID": "1", "DATA": "b''", "FUNCTION": "CONNECTION_MADE"}, "logtype": 18001, "node_id": "flypaper-hel-1", "src_host": "188.54.224.42", "src_port": 58378, "utc_time": "2026-11-18 08:36:43.973918"}
{"dst_host": "10.0.0.5", "dst_port": 1433, "local_time": "2026-11-18 08:37:07.003977", "logdata": {"AppName": "Microl office", "CltIntName": "ODBC", "Database": "master", "HostName": "SERVER", "Language": "", "ServerName": "10.0.0.5,1433", "UserName": "sa"}, "logtype": 9001, "node_id": "flypaper-hel-1", "src_host": "182.184.230.96", "src_port": 53645, "utc_time": "2026-11-18 08:37:07.004009"}
{"dst_host": "10.0.0.5", "dst_port": 1433, "local_time": "2026-11-18 08:40:07.819486", "logdata": {"AppName": "Nmap NSE", "CltIntName": "mssql.lua", "Database": "tempdb", "HostName": "Nmap", "Language": "", "ServerName": "10.0.0.5", "UserName": "sa"}, "logtype": 9001, "node_id": "flypaper-hel-1", "src_host": "35.210.123.92", "src_port": 31972, "utc_time": "2026-11-18 08:40:07.819525"}
{"dst_host": "10.0.0.5", "dst_port": 1433, "local_time": "2026-11-18 08:40:07.967217", "logdata": {"PASSWORD": "", "USERNAME": ""}, "logtype": 9002, "node_id": "flypaper-hel-1", "src_host": "35.210.123.92", "src_port": 31994, "utc_time": "2026-11-18 08:40:07.967256"}
{"logdata": {"msg": {"logdata": "Canary running!!!"}}, "logtype": 1001, "node_id": "flypaper-hel-1", "src_host": "", "src_port": -1, "utc_time": "2026-11-18 08:30:00.000000"}
`

func TestReadOpenCanary_MSSQLAndBanner(t *testing.T) {
	evs, err := ReadOpenCanary(strings.NewReader(ocSample))
	if err != nil {
		t.Fatal(err)
	}
	// banner connect, (client + login) x2, winauth login; the boot line is skipped
	if len(evs) != 6 {
		t.Fatalf("got %d events: %+v", len(evs), evs)
	}
	if evs[0].Service != "tcp" || evs[0].Kind != "connect" || evs[0].DstPort != 445 {
		t.Errorf("banner event wrong: %+v", evs[0])
	}
	var logins, clients []Event
	for _, e := range evs {
		if e.Service != "mssql" {
			continue
		}
		switch e.Kind {
		case "login_failed":
			logins = append(logins, e)
		case "client":
			clients = append(clients, e)
		}
	}
	if len(logins) != 3 || len(clients) != 2 {
		t.Fatalf("logins=%d clients=%d", len(logins), len(clients))
	}
	if logins[0].Username != "sa" || logins[1].Username != "sa" {
		t.Errorf("UserName not read: %q %q", logins[0].Username, logins[1].Username)
	}
	if clients[0].Input != "Microl office / ODBC / SERVER" || clients[1].Input != "Nmap NSE / mssql.lua / Nmap" {
		t.Errorf("client descriptions: %q %q", clients[0].Input, clients[1].Input)
	}
	if clients[0].SrcIP.String() != "182.184.230.96" || clients[0].Time.IsZero() {
		t.Errorf("client event lost source or time: %+v", clients[0])
	}
}
