package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

func main() {
	configPath := flag.String("config", "mintfs.toml", "Path to config file")
	debug := flag.Bool("debug", false, "Enable FUSE debug logging")
	flag.Parse()

	// Load config
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if cfg.MountPoint == "" {
		log.Fatal("mount_point is required in config")
	}

	// Create mount point if it doesn't exist
	if err := os.MkdirAll(cfg.MountPoint, 0o755); err != nil {
		log.Fatalf("Failed to create mount point: %v", err)
	}

	// Mount options
	options := []fuse.MountOption{
		fuse.FSName("mintfs"),
		fuse.Subtype("mintfs"),
		fuse.ReadOnly(),
		fuse.AllowOther(), // requires /etc/fuse.conf user_allow_other
	}

	// Mount the filesystem
	c, err := fuse.Mount(cfg.MountPoint, options...)
	if err != nil {
		log.Fatalf("Failed to mount: %v", err)
	}
	defer c.Close()

	log.Printf("Mounted mintfs at %s", cfg.MountPoint)
	log.Printf("Serving %d credential(s)", len(cfg.Credentials))

	// Handle signals for clean unmount
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Unmounting...")
		fuse.Unmount(cfg.MountPoint)
	}()

	// Serve the filesystem
	srv := fs.New(c, &fs.Config{
		Debug: func(msg interface{}) {
			if *debug {
				log.Printf("FUSE: %v", msg)
			}
		},
	})

	if err := srv.Serve(&MintFS{config: cfg}); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
