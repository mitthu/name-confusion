package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
)

// Globals
const LogFile string = "examples/logs.auditd"
const AuditdSep string = "----"

var AuSyscalls map[string]string
var Inodes map[string]Inode

/* Holds parsed auditd records */
type Record struct {
	Type      string
	Msg       string
	Timestamp string
	Body      map[string]string
}

/* Represents a path operation */
type Inode struct {
	Timestamp string
	InodeNum  string
	Device    string
	Path      string
	Operation string
	Exe       string
	Syscall   string
	Proctitle string
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func PopulateAuSyscalls() {
	AuSyscalls = make(map[string]string)
	out, err := exec.Command("ausyscall", "--dump").Output()
	check(err)

	output := string(out)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		items := strings.Split(line, "\t")
		if len(items) == 2 {
			num, name := items[0], items[1]
			AuSyscalls[num] = name
		}
	}
	// fmt.Println(AuSyscalls)
}

func main() {
	fmt.Println("Name confusion monitoring utility")
	Inodes = make(map[string]Inode)
	PopulateAuSyscalls()

	logfile := LogFile
	args := os.Args
	if len(args) >= 2 {
		logfile = args[1]
	}

	rawLogs := ReadLog(logfile)
	// fmt.Println(rawLogs)

	ParseLog(rawLogs)
	// fmt.Println(Inodes)
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
			r := ParseRecords(recordLines)
			ProcessRecords(r)
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

func ParseRecords(recordLines []string) *[]Record {
	if len(recordLines) == 0 {
		return nil
	}

	var timestamp string
	var records []Record

	for _, record := range recordLines {
		if strings.Contains(record, "time->") {
			timestamp = record[6:]
			continue
		}
		var r Record
		r.CreateRecord(record)
		r.Timestamp = timestamp
		records = append(records, r)
	}

	return &records
}

func (i *Inode) Initialize(syscall, proctitle, path Record) {
	decodeProctitle := func(hexstr string) string {
		decoded, err := hex.DecodeString(hexstr)
		check(err)
		return string(decoded)
	}

	i.Timestamp = path.Timestamp
	i.InodeNum = path.Body["inode"]
	i.Device = path.Body["dev"]
	i.Path = path.Body["name"]
	i.Operation = path.Body["nametype"]
	i.Exe = syscall.Body["exe"]
	i.Syscall = syscall.Body["syscall"]
	i.Proctitle = proctitle.Body["proctitle"]

	i.Syscall = AuSyscalls[i.Syscall]
	i.Proctitle = decodeProctitle(i.Proctitle)
}

func (i Inode) Name() string {
	name := i.Device + "|" + i.InodeNum
	return name
}

func (i *Inode) Process() {
	name := i.Name()
	verifyUse := func() {
		if i.Path == "(null)" {
			/* syscall operates on inode# */
			return
		}

		if old, ok := Inodes[name]; ok {
			if old.Path != i.Path {
				fmt.Printf("Bad use(%v on %v)=%v create(%v on %v)=%v\n",
					i.Exe, i.Syscall, i.Path,
					old.Exe, old.Syscall, old.Path)
			}
		}
	}

	switch i.Operation {
	case "CREATE":
		Inodes[name] = *i
	case "PARENT":
		fallthrough
	case "NORMAL":
		verifyUse()
	case "DELETE":
		delete(Inodes, name)
	default:
		/* code */
		log.Fatal("Unhandled PATH operation: ", i.Operation)
	}
}

func ProcessRecords(rs *[]Record) {
	if rs == nil {
		return
	}
	// fmt.Println(rs)

	// Extract syscalls & proctitle
	var syscall, proctitle Record
	for _, r := range *rs {
		switch r.Type {
		case "SYSCALL":
			syscall = r
		case "PROCTITLE":
			proctitle = r
		}
	}

	// Extract inodes
	for _, r := range *rs {
		if r.Type == "PATH" {
			var i Inode
			i.Initialize(syscall, proctitle, r)
			i.Process()
			// fmt.Println(i)
		}
	}
	// fmt.Println(syscall, proctitle)
}
