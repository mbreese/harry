package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mbreese/harry/pkg/client"
	"github.com/mbreese/harry/pkg/protocol"
)

const usage = `Usage: harry [flags] <command> [args]

Commands:
  download <file>            Download a file from the server (saves locally)
  upload <local> [remote]    Upload a file to the server
  list                       List available files on the server
  fetch <url>                Fetch a URL via the server (stdout)
  pipe                       Bidirectional stdin/stdout tunnel
  poll                       Poll for data (testing)

Flags:
`

func main() {
	domain := flag.String("domain", "", "base domain")
	password := flag.String("password", "", "shared secret")
	resolver := flag.String("resolver", "", "DNS resolver (host:port, default: system resolver)")
	pollInterval := flag.Duration("poll", 30*time.Second, "idle poll interval")
	noRedirect := flag.Bool("no-redirect", false, "don't follow HTTP redirects (for fetch)")
	output := flag.String("o", "", "output file (for fetch/download, default: stdout)")
	rcFile := flag.String("rc", "", "RC file path (default: ~/.harryrc)")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	// Load RC file defaults
	rc := loadRC(*rcFile)

	// Flags override RC values
	if *domain == "" {
		*domain = rc["domain"]
	}
	if *password == "" {
		*password = rc["password"]
	}
	if *resolver == "" {
		*resolver = rc["resolver"]
	}
	if *resolver == "" {
		*resolver = "8.8.8.8:53"
	}

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	// Validate required config
	if *domain == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "error: domain and password are required (set via flags or ~/.harryrc)")
		os.Exit(1)
	}

	cfg := &client.Config{
		Domain:       *domain,
		Password:     *password,
		Resolver:     *resolver,
		PollInterval: *pollInterval,
	}

	c, err := client.New(cfg)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	if err := c.Connect(); err != nil {
		log.Fatalf("failed to connect: %v", err)
	}

	switch cmd {
	case "download":
		if len(cmdArgs) < 1 {
			log.Fatal("usage: harry download <filename>")
		}
		data, err := c.RequestFile(cmdArgs[0])
		if err != nil {
			log.Fatalf("download failed: %v", err)
		}
		outPath := *output
		if outPath == "" {
			outPath = filepath.Base(cmdArgs[0])
		}
		writeOutput(data, outPath)

	case "upload":
		if len(cmdArgs) < 1 {
			log.Fatal("usage: harry upload <local> [remote]")
		}
		localPath := cmdArgs[0]
		remoteName := filepath.Base(localPath)
		if len(cmdArgs) >= 2 {
			remoteName = cmdArgs[1]
		}
		if err := c.UploadFile(localPath, remoteName); err != nil {
			log.Fatalf("upload failed: %v", err)
		}

	case "fetch":
		if len(cmdArgs) < 1 {
			log.Fatal("usage: harry fetch <url>")
		}
		var fetchFlags byte
		if *noRedirect {
			fetchFlags |= client.FetchNoRedirect
		}
		data, err := c.FetchURL(cmdArgs[0], fetchFlags)
		if err != nil {
			log.Fatalf("fetch failed: %v", err)
		}
		writeOutput(data, *output)

	case "list":
		files, err := c.ListFiles()
		if err != nil {
			log.Fatalf("list failed: %v", err)
		}
		for _, f := range files {
			fmt.Println(f)
		}

	case "pipe":
		runPipe(c, *pollInterval)

	case "poll":
		for {
			resp, err := c.Poll()
			if err != nil {
				log.Printf("poll error: %v", err)
			} else if len(resp.Payload) > 0 {
				fmt.Printf("%s", resp.Payload)
			}
			time.Sleep(*pollInterval)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		flag.Usage()
		os.Exit(1)
	}
}

// writeOutput writes data to a file or stdout.
func writeOutput(data []byte, path string) {
	if path == "" {
		os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
	log.Printf("wrote %d bytes to %s", len(data), path)
}

// loadRC reads key=value pairs from an RC file.
// Looks for ~/.harryrc by default.
func loadRC(path string) map[string]string {
	rc := make(map[string]string)

	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return rc
		}
		path = filepath.Join(home, ".harryrc")
	}

	f, err := os.Open(path)
	if err != nil {
		return rc
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		rc[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	return rc
}

// runPipe runs a bidirectional pipe over the tunnel.
func runPipe(c *client.Client, pollInterval time.Duration) {
	stdinCh := make(chan []byte)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				stdinCh <- data
			}
			if err == io.EOF {
				close(stdinCh)
				return
			}
			if err != nil {
				log.Printf("stdin error: %v", err)
				close(stdinCh)
				return
			}
		}
	}()

	moreData := false
	for {
		select {
		case data, ok := <-stdinCh:
			if !ok {
				return
			}
			resp, err := c.SendData(data)
			if err != nil {
				log.Printf("send error: %v", err)
				continue
			}
			if len(resp.Payload) > 0 {
				os.Stdout.Write(resp.Payload)
			}
			moreData = resp.Flags&protocol.FlagMoreData != 0

		default:
			if moreData {
				resp, err := c.Poll()
				if err != nil {
					log.Printf("poll error: %v", err)
					continue
				}
				if len(resp.Payload) > 0 {
					os.Stdout.Write(resp.Payload)
				}
				moreData = resp.Flags&protocol.FlagMoreData != 0
			} else {
				time.Sleep(pollInterval)
				resp, err := c.Poll()
				if err != nil {
					log.Printf("poll error: %v", err)
					continue
				}
				if len(resp.Payload) > 0 {
					os.Stdout.Write(resp.Payload)
				}
				moreData = resp.Flags&protocol.FlagMoreData != 0
			}
		}
	}
}
