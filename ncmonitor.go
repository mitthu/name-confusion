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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"path"
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
	flagJson        = flag.Bool("json", false, "output in json")
	flagPretty      = flag.Bool("pretty", false, "pretty-print json output")
	flagAbsPath     = flag.Bool("abspath", false, "convert paths to absolute for non-json output")
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
	defer tm.Close()
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

	// Extract specific records
	var syscall, proctitle, cwd Record
	for _, r := range rs.Records {
		switch r.Type {
		case "SYSCALL":
			syscall = r
		case "PROCTITLE":
			proctitle = r
		case "CWD":
			cwd = r
		case "PATH":
		case "CONFIG_CHANGE":
		default:
			if *flagVerbose {
				log.Println("unknown record type:", r)
			}
		}
	}

	// Extract inodes
	for _, r := range rs.Records {
		if r.Type == "PATH" {
			inode := NewInode(syscall, proctitle, cwd, r)
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
	Cwd       string
}

func NewInode(syscall, proctitle, cwd, path Record) Inode {
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
		Cwd:       cwd.Body["cwd"],
	}

	// Post-process relevant fields
	mode, _ := strconv.Atoi(path.Body["mode"])
	i.Mode = uint16(mode)

	i.Path = strings.Trim(i.Path, "\"")

	i.Exe = strings.Trim(i.Exe, "\"")

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

	// process valid cwd entry
	i.Cwd = strings.Trim(i.Cwd, "\"")

	return i
}

// Get unique name for an Inode. It's unique for a given OS.
func (i Inode) Name() string {
	name := i.Device + "|" + i.InodeNum
	return name
}

// Convert relative paths to absolute paths using "cwd".
func (i Inode) getAbsPath() string {
	// ensure paths aren't empty
	if len(strings.Trim(i.Cwd, " ")) == 0 ||
		len(strings.Trim(i.Path, " ")) == 0 {
		return i.Path
	}

	// is path already absolute or null?
	if i.Path[0] == '/' || i.Path == "(null)" {
		return i.Path
	}

	// make absolute path
	return path.Join(i.Cwd, i.Path)
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
	p := i.getAbsPath()
	if i.IsDir() {
		return strings.TrimSuffix(p, "/")
	}
	return p
}

// Holds collection of Inodes
type Inodes []Inode

func (ins *Inodes) AddInode(i Inode) {
	*ins = append(*ins, i)
}

// Report of create-use pairs
type Report struct{ Create, Use *Inode }

// Play FS operations against a timeline
type Timeline struct {
	history map[string]Inode
	reports []Report
}

func NewTimeline() Timeline {
	tm := Timeline{history: make(map[string]Inode)}
	return tm
}

func (tm *Timeline) Report(create, use *Inode) {
	if *flagJson {
		tm.ReportLater(create, use)
	} else {
		tm.ReportImmediatly(create, use)
	}
}

// Immediately report violations
func (tm Timeline) ReportImmediatly(create, use *Inode) {
	// choose path repr.
	var cPath, uPath string
	if *flagAbsPath {
		cPath = create.NormalizedPath()
		uPath = use.NormalizedPath()
	} else {
		cPath = create.Path
		uPath = use.Path
	}

	fmt.Printf("use['%v'.%v]=%s create['%v'.%v]=%s\n",
		path.Base(use.Exe), use.Syscall, uPath,
		path.Base(create.Exe), create.Syscall, cPath)
	if *flagVerbose {
		fmt.Printf("\tuse: %v, create:%v\n", use.Msg, create.Msg)
	}
}

// Collect all violations for reporting later
func (tm *Timeline) ReportLater(create, use *Inode) {
	r := Report{create, use}
	tm.reports = append(tm.reports, r)
}

// Output all collected violations
func (tm Timeline) processPendingRepots(pretty bool) {
	if len(tm.reports) == 0 {
		return
	}

	var result []byte
	if pretty {
		result, _ = json.MarshalIndent(tm.reports, "", "  ")
	} else {
		result, _ = json.Marshal(tm.reports)
	}

	fmt.Println(string(result))
}

func (tm *Timeline) Close() {
	tm.processPendingRepots(*flagPretty)
}

// Apply a single inode against the timeline
func (tm *Timeline) Apply(i *Inode) {
	name := i.Name()
	recordCreate := func() {
		if i.Path == "(null)" {
			/* syscall operates on inode# */
			return
		}
		// Record create
		tm.history[name] = *i
	}
	verifyUse := func() {
		if i.Path == "(null)" {
			/* syscall operates on inode# */
			return
		}

		var create Inode
		var ok bool
		if create, ok = tm.history[name]; !ok {
			return // no corresponding CREATE
		}

		// Test for inconsistency
		cPATH := create.NormalizedPath()
		uPATH := i.NormalizedPath()
		if cPATH != uPATH {
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
		delete(tm.history, name)
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
func (tm *Timeline) ApplyInodes(inodes *Inodes) {
	for _, i := range *inodes {
		tm.Apply(&i)
	}
}
