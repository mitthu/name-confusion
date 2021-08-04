/*
Find case consistencies from auditd logs

We extract bad create-use pairs from the auditd logs.

From auditd logs, we create a Record. Related records are bundled into Records.
Next we generate Inodes from Records. Finally, the Inodes are applied against a
Timeline. The Timeline prints out violations as the Inodes are being applied.

To summarize:
	- Create Record
	- Add Record to Records
	- Generate Inodes from Records
	- Apply Inodes against a Timeline

*/
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

// Example file to parse when no input is given
const LogFile string = "examples/logs-1.auditd"

// Event separator in auditd logs
const AuditdSep string = "----"

/* Populated via PopulateAuSyscalls() */
var AuSyscalls map[string]string

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func PopulateAuSyscalls() {
	out, err := exec.Command("ausyscall", "--dump").Output()
	if err != nil {
		return
	}

	AuSyscalls = make(map[string]string)

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
	PopulateAuSyscalls()

	/* parse cmdline args */
	logfile := LogFile
	args := os.Args
	if len(args) >= 2 {
		logfile = args[1]
	}

	/* main logic */
	ParseLog(logfile)
}

// Shim to put it together
func ParseLog(file string) {
	content, err := ioutil.ReadFile(file)
	check(err)

	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")

	tm := NewTimeline() /* records of operations */
	rs := &Records{}

	for _, line := range lines {
		if line != AuditdSep {
			rs.AddLine(line)
		} else {
			inodes := rs.GetInodes()
			tm.ApplyInodes(inodes)
			rs = &Records{}
		}
	}
}

// Parse a string to key-value pairs
func ParseKVPairs(str string) map[string]string {
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

/* Holds parsed auditd records */
type Record struct {
	Type      string
	Msg       string
	Timestamp string
	Body      map[string]string
}

// Create a Record from raw string
func NewRecord(rawstr string) Record {
	lines := strings.Split(rawstr, ": ")
	if len(lines) != 2 {
		err := errors.New("Invalid format of auditd line")
		fmt.Println(lines)
		log.Fatal(err)
	}

	headerRaw, bodyRaw := lines[0], lines[1]
	headers := ParseKVPairs(headerRaw)
	body := ParseKVPairs(bodyRaw)

	return Record{
		Type: headers["type"],
		Msg:  headers["msg"],
		Body: body,
	}
}

// Hold multiple records
type Records struct {
	Records   []Record
	Timestamp string // Also copied to all records
}

// Parse a raw string into Record and add it to itself
func (rs *Records) AddLine(line string) {
	if len(line) == 0 {
		return
	}

	if strings.Contains(line, "time->") {
		rs.Timestamp = line[6:]
	} else {
		r := NewRecord(line)
		r.Timestamp = rs.Timestamp // assumes it's set by the first Record
		rs.Records = append(rs.Records, r)
	}
}

func (rs *Records) AddLines(lines []string) {
	for _, line := range lines {
		rs.AddLine(line)
	}
}

// Generate Inodes from a set of records representing an event.
func (rs Records) GetInodes() *Inodes {
	// fmt.Println(rs)
	inodes := Inodes{}

	// Extract syscalls & proctitle
	var syscall, proctitle Record
	for _, r := range rs.Records {
		switch r.Type {
		case "SYSCALL":
			syscall = r
		case "PROCTITLE":
			proctitle = r
		}
	}

	// Extract inodes
	for _, r := range rs.Records {
		if r.Type == "PATH" {
			inode := NewInode(syscall, proctitle, r)
			inodes.AddInode(inode)
			// fmt.Println(i)
		}
	}

	// fmt.Println(syscall, proctitle)
	return &inodes
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

func NewInode(syscall, proctitle, path Record) Inode {
	decodeProctitle := func(hexstr string) string {
		decoded, err := hex.DecodeString(hexstr)
		check(err)
		return string(decoded)
	}

	i := Inode{
		Timestamp: path.Timestamp,
		InodeNum:  path.Body["inode"],
		Device:    path.Body["dev"],
		Path:      path.Body["name"],
		Operation: path.Body["nametype"],
		Exe:       syscall.Body["exe"],
		Syscall:   syscall.Body["syscall"],
		Proctitle: proctitle.Body["proctitle"],
	}

	i.Proctitle = decodeProctitle(i.Proctitle)
	if AuSyscalls != nil {
		i.Syscall = AuSyscalls[i.Syscall]
	}

	return i
}

// Get unique name for an Inode. It's unique for a given OS.
func (i Inode) Name() string {
	name := i.Device + "|" + i.InodeNum
	return name
}

// Holds collection of Inodes
type Inodes []Inode

func (ins *Inodes) AddInode(i Inode) {
	*ins = append(*ins, i)
}

// Play FS operations against a timeline
type Timeline map[string]Inode

func NewTimeline() Timeline {
	return make(Timeline)
}

func (tm *Timeline) Apply(i *Inode) {
	name := i.Name()
	recordCreate := func() {
		if i.Path == "(null)" {
			/* syscall operates on inode# */
			return
		}
		// Record create
		(*tm)[name] = *i
	}
	verifyUse := func() {
		if i.Path == "(null)" {
			/* syscall operates on inode# */
			return
		}

		if old, ok := (*tm)[name]; ok {
			if old.Path != i.Path {
				fmt.Printf("Bad use(%v on %v)=%v create(%v on %v)=%v\n",
					i.Exe, i.Syscall, i.Path,
					old.Exe, old.Syscall, old.Path)
			}
		}
	}

	switch i.Operation {
	case "CREATE":
		recordCreate()
	case "PARENT":
		fallthrough
	case "NORMAL":
		verifyUse()
	case "DELETE":
		delete(*tm, name)
	default:
		/* code */
		log.Fatal("Unhandled PATH operation: ", i.Operation)
	}
}

func (tm *Timeline) ApplyInodes(inodes *Inodes) {
	for _, i := range *inodes {
		tm.Apply(&i)
	}
}
