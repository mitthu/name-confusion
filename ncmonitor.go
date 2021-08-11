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
		* Generate & embed Syscall
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
	flagVerbose     = flag.Bool("verbose", false, "verbose output; lines starting with 'info:' are writted to stderr")
	flagLogfile     = flag.String("file", LogFile, "auditd `logfile` to parse")
	flagJson        = flag.Bool("json", false, "output in json")
	flagPretty      = flag.Bool("pretty", false, "pretty-print json output")
	flagAbsPath     = flag.Bool("abspath", false, "convert paths to absolute for non-json output")
	flagLogBadOpen  = flag.Bool("logbadopen", false, "log uses of existing files with O_CREAT flag")
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

	/* set logging */
	log.SetPrefix("info: ")
	log.SetFlags(0) // disable data & time

	/* main logic */
	if *flagVerbose {
		log.Println("Name confusion detection utility")
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

/* Represents a syscall operation */
type Syscall struct {
	Msg     string // ID of record
	Name    string
	Number  uint64
	Exe     string
	Cmd     string
	Pid     int64
	Ppid    int64
	A0      uint64
	A1      uint64
	A2      uint64
	A3      uint64
	Exit    int64
	Success bool

	record Record
}

// Create a Syscall from Record
func NewSyscall(r Record) Syscall {
	// ensure syscall record
	if r.Type != "SYSCALL" {
		log.Fatalf("cannot create Syscall from record.type=%s\n", r.Type)
	}

	// construct base syscall
	s := Syscall{
		Msg:    r.Msg,
		Name:   "",
		Exe:    strings.Trim(r.Body["exe"], "\""),
		Cmd:    strings.Trim(r.Body["cmd"], "\""),
		record: r,
	}

	// add number & name
	s.Number, _ = strconv.ParseUint(r.Body["syscall"], 10, 64)
	if AuSyscalls != nil {
		s.Name = AuSyscalls[fmt.Sprint(s.Number)]
	}

	// add other metadata
	s.Pid, _ = strconv.ParseInt(r.Body["pid"], 10, 64)
	s.Ppid, _ = strconv.ParseInt(r.Body["ppid"], 10, 64)

	s.A0, _ = strconv.ParseUint(r.Body["a0"], 16, 64)
	s.A1, _ = strconv.ParseUint(r.Body["a1"], 16, 64)
	s.A2, _ = strconv.ParseUint(r.Body["a2"], 16, 64)
	s.A3, _ = strconv.ParseUint(r.Body["a3"], 16, 64)

	// add exit status
	s.Exit, _ = strconv.ParseInt(r.Body["exit"], 10, 64)
	if r.Body["success"] == "yes" {
		s.Success = true
	} else {
		s.Success = false
	}

	return s
}

// String repr. of syscall
func (s Syscall) String() string {
	// if we don't have its name
	if len(s.Name) == 0 {
		return fmt.Sprint("syscall=", s.Number)
	}

	// for verbose print name & number
	if *flagVerbose {
		return fmt.Sprintf("%s(%v)", s.Name, s.Number)
	}

	return s.Name
}

// For open and openat, is O_CREAT set?
func (s Syscall) FlagCreate() bool {
	O_CREAT := uint64(0100)

	// refer: https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html
	switch {
	case s.Name == "open" || s.Number == 2:
		if (s.A1 & O_CREAT) > 1 {
			return true
		}
	case s.Name == "openat" || s.Number == 257:
		if (s.A2 & O_CREAT) > 1 {
			return true
		}
	case s.Name == "openat2" || s.Number == 437:
		log.Print("openat2 flags are not handled")
	}
	return false
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
	Syscall   Syscall
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
		Syscall:   NewSyscall(syscall),
		Proctitle: proctitle.Body["proctitle"],
		Cwd:       cwd.Body["cwd"],
	}

	// Post-process relevant fields
	mode, _ := strconv.Atoi(path.Body["mode"])
	i.Mode = uint16(mode)

	i.Path = strings.Trim(i.Path, "\"")

	i.Exe = strings.Trim(i.Exe, "\"")

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

// String repr. for printing on console
func (i Inode) String() string {
	// absolute or relative path
	var p string
	if *flagAbsPath {
		p = i.NormalizedPath()
	} else {
		p = i.Path
	}

	// verbose mode
	var msg string
	if *flagVerbose {
		msg = i.Msg
	} else {
		msg = ""

	}

	// example of string repr.:
	// [audit(1628098489.574:15451)'git'.unlink(87)]00:39|2123|a/
	str := fmt.Sprintf("[%v'%v'.%v]%v|%s",
		msg, path.Base(i.Exe), i.Syscall, i.Name(), p)

	return str
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
	fmt.Printf("USE%v CREATE%v\n", use, create)
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
		// ignore failed syscall
		if !i.Syscall.Success {
			return
		}

		if i.Path == "(null)" {
			/* syscall operates on inode# */
			return
		}
		// Record create
		tm.history[name] = *i
	}
	verifyUse := func() {
		// ignore failed syscall
		if !i.Syscall.Success {
			return
		}

		if *flagLogBadOpen && i.Syscall.FlagCreate() {
			log.Printf("use with O_CREAT: %v", i)
		}

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

// Apply set of inodes against a timeline.
//
// We apply in reverse order to preserve order of operations, i.e. apply item=0,
// item=1 and so on.
func (tm *Timeline) ApplyInodes(inodes *Inodes) {
	for i := len(*inodes) - 1; i >= 0; i-- {
		tm.Apply(&(*inodes)[i])
	}
}
