package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

// Globals
const LogFile string = "examples/logs.auditd"
const AuditdSep string = "----"

type Record struct {
	Type string
	Msg  string
	Body map[string]string
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	fmt.Println("Name confusion monitoring utility")

	rawLogs := ReadLog(LogFile)
	// fmt.Println(rawLogs)

	ParseLog(rawLogs)
}

func ReadLog(file string) string {
	content, err := ioutil.ReadFile(file)
	check(err)

	logs := string(content)
	return logs
}

func ParseLog(rawLogs string) {
	lines := strings.Split(rawLogs, "\n")
	var recordLines []string

	for _, line := range lines {
		if line == AuditdSep {
			ProcessRecord(recordLines)
			recordLines = nil
		} else {
			recordLines = append(recordLines, line)
		}
	}
}

func parseToMap(str string) map[string]string {
	result := make(map[string]string)
	entries := strings.Split(str, " ")

	// handle msg key w/ spaces
	tryAddingToMsg := func(s string) bool {
		if msg, ok := result["msg"]; ok {
			result["msg"] = msg + " " + s
			return true
		} else {
			return false
		}
	}

	tryAddingToProctitle := func(s string) bool {
		if msg, ok := result["proctitle"]; ok {
			result["proctitle"] = msg + " " + s
			return true
		} else {
			return false
		}
	}

	reportErr := func(e error, entry string) {
		fmt.Println("Result = ", result)
		errorStr := fmt.Sprintf("%v, forstring: %v, at: %v\n",
			e, str, entry)
		log.Fatal(errorStr)
	}

	// actual parsing
	for _, entry := range entries {
		vals := strings.Split(entry, "=")

		switch len(vals) {
		case 2: /* expected */
			k, v := vals[0], vals[1]
			result[k] = v
		case 1:
			ok := tryAddingToMsg(vals[0])
			if ok {
				continue
			}

			ok = tryAddingToProctitle(vals[0])
			if ok {
				continue
			}

			if vals[0] == "" {
				continue
			}
			// fmt.Println(vals, len(vals))

			err := errors.New("Error parsing key=value (len=1)")
			reportErr(err, entry)
		case 0:
			err := errors.New("Error parsing key=value (len=0)")
			reportErr(err, entry)
		default:
			err := errors.New("Error parsing key=value")
			reportErr(err, entry)
		}
	}

	return result
}

func (r *Record) CreateRecord(rawstr string) {
	lines := strings.Split(rawstr, ": ")
	if len(lines) != 2 {
		err := errors.New("Invalid format of auditd line")
		fmt.Println(lines)
		log.Fatal(err)
	}

	headerRaw, bodyRaw := lines[0], lines[1]
	headers := parseToMap(headerRaw)
	body := parseToMap(bodyRaw)

	r.Type = headers["type"]
	r.Msg = headers["msg"]
	r.Body = body
}

func ProcessRecord(recordLines []string) {
	if len(recordLines) == 0 {
		return
	}

	var r Record
	// var timestamp string

	// Parse all records
	for _, record := range recordLines {
		if strings.Contains(record, "time->") {
			// timestamp = record[6:]
			continue
		}
		r.CreateRecord(record)
		fmt.Println(r)
	}
}
