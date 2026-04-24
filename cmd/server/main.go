package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mbreese/harry/pkg/server"
	"github.com/miekg/dns"
)

func main() {
	domain := flag.String("domain", "", "base domain (e.g., tunnel.example.com)")
	password := flag.String("password", "", "shared secret")
	listen := flag.String("listen", ":53", "listen address")
	fileDir := flag.String("files", "./files", "directory for downloadable files")
	uploadDir := flag.String("uploads", "./uploads", "directory for uploaded files")
	cacheDir := flag.String("cache", "", "bootstrap cache directory (default: temp dir)")
	rshellAddr := flag.String("rshell", "", "TCP listen address for reverse shell (e.g., 127.0.0.1:4444)")
	ttl := flag.Uint("ttl", 1, "DNS TTL")
	verbose := flag.Bool("verbose", false, "log all queries including stray traffic")
	flag.Parse()

	if *domain == "" || *password == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Ensure directories exist
	os.MkdirAll(*fileDir, 0755)
	os.MkdirAll(*uploadDir, 0755)

	cfg := &server.Config{
		Domain:     *domain,
		Password:   *password,
		FileDir:    *fileDir,
		UploadDir:  *uploadDir,
		CacheDir:   *cacheDir,
		Listen:     *listen,
		RShellAddr: *rshellAddr,
		TTL:        uint32(*ttl),
		Verbose:    *verbose,
	}

	handler, err := server.New(cfg)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	// Start DNS server on both UDP and TCP
	udpServer := &dns.Server{Addr: cfg.Listen, Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Addr: cfg.Listen, Net: "tcp", Handler: handler}

	go func() {
		log.Printf("starting UDP DNS server on %s for domain %s", cfg.Listen, cfg.Domain)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("UDP server failed: %v", err)
		}
	}()

	go func() {
		log.Printf("starting TCP DNS server on %s for domain %s", cfg.Listen, cfg.Domain)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("TCP server failed: %v", err)
		}
	}()

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("shutting down...")
	udpServer.Shutdown()
	tcpServer.Shutdown()
}
