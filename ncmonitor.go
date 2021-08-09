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
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Example file to parse when no input is given
const LogFile string = "examples/logs-1.auditd"

// Event separator in auditd logs
const AuditdSep string = "----"

/* Populated via PopulateAuSyscalls() */
var AuSyscalls map[string]string

/* Holds command-line flags */
var (
	flagVerbose     = flag.Bool("verbose", false, "verbose output")
	flagLogfile     = flag.String("file", LogFile, "auditd `logfile` to parse")
	capSyscallNames bool // capability to convert syscall numbers to names
)

func PopulateAuSyscalls() {
	out, err := exec.Command("ausyscall", "--dump").Output()
	if err != nil {
		if *flagVerbose {
			log.Printf("couldn't convert syscall numbers to names: %v\n", err)
		}
		capSyscallNames = false
		return
	}

	capSyscallNames = true
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
	PopulateAuSyscalls()

	/* parse cmdline args */
	flag.Parse()

	/* main logic */
	if *flagVerbose {
		fmt.Println("Name confusion detection utility")
	}
	ParseLog(*flagLogfile)
}

// Shim to put it together
func ParseLog(file string) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

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
	Msg       string // ID of record
	InodeNum  string
	Device    string
	Path      string
	Mode      uint16
	Operation string
	Exe       string
	Syscall   string
	Proctitle string
}

func NewInode(syscall, proctitle, path Record) Inode {
	i := Inode{
		Timestamp: path.Timestamp,
		Msg:       path.Msg,
		InodeNum:  path.Body["inode"],
		Device:    path.Body["dev"],
		Path:      path.Body["name"],
		Mode:      0,
		Operation: path.Body["nametype"],
		Exe:       syscall.Body["exe"],
		Syscall:   syscall.Body["syscall"],
		Proctitle: proctitle.Body["proctitle"],
	}

	// Post-process relevant fields
	mode, _ := strconv.Atoi(path.Body["mode"])
	i.Mode = uint16(mode)

	i.Path = strings.Trim(i.Path, "\"")

	if AuSyscalls != nil {
		i.Syscall = AuSyscalls[i.Syscall]
	}

	decodedBytes, err := hex.DecodeString(i.Proctitle)
	if err != nil {
		log.Printf("%v; cannot decode proctitle for %v\n", err, i)
	} else {
		// replace nulls with space in string
		charNull := make([]byte, 1)
		charSpace := make([]byte, 1)

		utf8.EncodeRune(charNull, '\u0000')
		utf8.EncodeRune(charSpace, ' ')
		withSpaces := bytes.ReplaceAll(decodedBytes, charNull, charSpace)

		// string recovered
		i.Proctitle = string(withSpaces)
	}

	return i
}

// Get unique name for an Inode. It's unique for a given OS.
func (i Inode) Name() string {
	name := i.Device + "|" + i.InodeNum
	return name
}

// Is it directory or file (regular, pipe, etc.)?
func (i Inode) IsDir() bool {
	// See stat.st_mode (in man 7 inode)
	if (i.Mode & 40000) > 1 {
		return true
	}
	return false
}

// Remove trailing "/" only if directory. We don't touch symbolic links.
func (i Inode) NormalizedPath() string {
	if i.IsDir() {
		return strings.TrimSuffix(i.Path, "/")
	}
	return i.Path
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

// Function to report a violation
func (tm Timeline) Report(create, use *Inode) {
	fmt.Printf("use(%v on %v)=%v create(%v on %v)=%v\n",
		use.Exe, use.Syscall, use.NormalizedPath(),
		create.Exe, create.Syscall, create.NormalizedPath())
}

// Apply a single inode against the timeline
func (tm Timeline) Apply(i *Inode) {
	name := i.Name()
	recordCreate := func() {
		if i.Path == "(null)" {
			/* syscall operates on inode# */
			return
		}
		// Record create
		tm[name] = *i
	}
	verifyUse := func() {
		if i.Path == "(null)" {
			/* syscall operates on inode# */
			return
		}

		var create Inode
		var ok bool
		if create, ok = tm[name]; !ok {
			return // no corresponding CREATE
		}

		// Test for inconsistency
		// TODO: handle relative and absolute paths
		cPATH := create.NormalizedPath()
		uPATH := i.NormalizedPath()
		switch {
		case cPATH == uPATH:
			// matching pathname
		case strings.HasSuffix(cPATH, uPATH):
			// USE is substring of CREATE
		case strings.HasSuffix(uPATH, cPATH):
			// CREATE is substring of USE
		default:
			tm.Report(&create, i)
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
		delete(tm, name)
	case "UNKNOWN":
		if *flagVerbose {
			log.Printf("op=UNKNOWN: %v", i)
		}
	default:
		/* code */
		log.Fatal("Unhandled PATH operation: ", i.Operation)
	}
}

// Apply set of inodes against a timeline
func (tm Timeline) ApplyInodes(inodes *Inodes) {
	for _, i := range *inodes {
		tm.Apply(&i)
	}
}
