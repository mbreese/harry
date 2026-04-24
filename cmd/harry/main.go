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
  send <local> [remote]      Send a file to the server (local=- for stdin)
  recv <remote> [local]      Receive a file from the server (local=- for stdout)
  list                       List available files on the server
  fetch <url>                Fetch a URL via the server (stdout)
  socks5                     SOCKS5 proxy (tunnel TCP through DNS)
  rshell                     Reverse shell (expose local shell to server)
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
	force := flag.Bool("f", false, "force overwrite existing file")
	verbose := flag.Bool("v", false, "verbose debug logging")
	socksAddr := flag.String("socks-addr", "127.0.0.1:1080", "SOCKS5 listen address")
	rcFile := flag.String("rc", "", "RC file path (default: ~/.harryrc)")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	// Load RC file defaults
	rc := loadRC(*rcFile)

	if *domain == "" {
		*domain = rc["domain"]
	}
	if *password == "" {
		*password = rc["password"]
	}
	if *resolver == "" {
		*resolver = rc["resolver"]
	}

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	if *domain == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "error: domain and password are required (set via flags or ~/.harryrc)")
		os.Exit(1)
	}

	cfg := &client.Config{
		Domain:       *domain,
		Password:     *password,
		Resolver:     *resolver,
		PollInterval: *pollInterval,
		Verbose:      *verbose,
	}

	c, err := client.New(cfg)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	if err := c.Connect(); err != nil {
		log.Fatalf("failed to connect: %v", err)
	}

	switch cmd {
	case "recv", "download":
		if len(cmdArgs) < 1 {
			log.Fatal("usage: harry recv <remote> [local]")
		}
		data, err := c.RequestFile(cmdArgs[0])
		if err != nil {
			log.Fatalf("recv failed: %v", err)
		}
		outPath := filepath.Base(cmdArgs[0])
		if len(cmdArgs) >= 2 {
			outPath = cmdArgs[1]
		}
		if outPath != "-" && !*force {
			if _, err := os.Stat(outPath); err == nil {
				log.Fatalf("file exists: %s (use -f to overwrite)", outPath)
			}
		}
		writeOutput(data, outPath)

	case "send", "upload":
		if len(cmdArgs) < 1 {
			log.Fatal("usage: harry send <local> [remote]")
		}
		localPath := cmdArgs[0]

		var sendFlags byte
		if *force {
			sendFlags |= client.SendForce
		}

		if localPath == "-" {
			// Stdin mode — remote name is required
			remoteName := ""
			if len(cmdArgs) >= 2 {
				remoteName = cmdArgs[1]
			}
			if remoteName == "" {
				log.Fatal("usage: harry send - <remote>  (remote name required for stdin)")
			}
			if err := c.SendStream(os.Stdin, remoteName, sendFlags); err != nil {
				log.Fatalf("send failed: %v", err)
			}
		} else {
			remoteName := filepath.Base(localPath)
			if len(cmdArgs) >= 2 {
				remoteName = cmdArgs[1]
			}
			if err := c.SendFile(localPath, remoteName, sendFlags); err != nil {
				log.Fatalf("send failed: %v", err)
			}
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
		writeOutput(data, "-")

	case "list":
		files, err := c.ListFiles()
		if err != nil {
			log.Fatalf("list failed: %v", err)
		}
		for _, f := range files {
			fmt.Println(f)
		}

	case "socks5", "socks":
		if err := c.StartSocks5(*socksAddr, *pollInterval); err != nil {
			log.Fatalf("socks5 failed: %v", err)
		}

	case "rshell":
		if err := c.StartRShell(*pollInterval); err != nil {
			log.Fatalf("rshell failed: %v", err)
		}

	case "pipe":
		runPipe(c, *pollInterval)

	case "poll":
		for {
			frame, err := c.Poll()
			if err != nil {
				log.Printf("poll error: %v", err)
			} else if len(frame.Payload) > 0 {
				fmt.Printf("%s", frame.Payload)
			}
			time.Sleep(*pollInterval)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		flag.Usage()
		os.Exit(1)
	}
}

// writeOutput writes data to a file, or stdout if path is "-".
func writeOutput(data []byte, path string) {
	if path == "-" {
		os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
	log.Printf("wrote %d bytes to %s", len(data), path)
}

// loadRC reads key=value pairs from an RC file.
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
			frame, err := c.SendData(data)
			if err != nil {
				log.Printf("send error: %v", err)
				continue
			}
			if len(frame.Payload) > 0 {
				os.Stdout.Write(frame.Payload)
			}
			moreData = frame.Flags&protocol.FlagMoreData != 0

		default:
			if moreData {
				frame, err := c.Poll()
				if err != nil {
					log.Printf("poll error: %v", err)
					continue
				}
				if len(frame.Payload) > 0 {
					os.Stdout.Write(frame.Payload)
				}
				moreData = frame.Flags&protocol.FlagMoreData != 0
			} else {
				time.Sleep(pollInterval)
				frame, err := c.Poll()
				if err != nil {
					log.Printf("poll error: %v", err)
					continue
				}
				if len(frame.Payload) > 0 {
					os.Stdout.Write(frame.Payload)
				}
				moreData = frame.Flags&protocol.FlagMoreData != 0
			}
		}
	}
}
