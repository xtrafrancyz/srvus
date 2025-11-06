package main

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/likexian/doh"
	"github.com/likexian/doh/dns"

	"golang.org/x/crypto/ssh"
)

var (
	b32encoder = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base64.NoPadding)

	domain           = flag.String("domain", "srv.us", "Domain name under which we run")
	sshAddr          = flag.String("ssh-addr", ":22", "Port for SSH to bind to")
	httpAddr         = flag.String("http-addr", ":80", "Port for HTTP to bind to")
	httpsAddr        = flag.String("https-addr", ":443", "Port for HTTPS to bind to")
	httpsChainPath   = flag.String("https-chain-path", "/etc/letsencrypt/live/srv.us/fullchain.pem", "Path to the certificate chain")
	httpsKeyPath     = flag.String("https-key-path", "/etc/letsencrypt/live/srv.us/privkey.pem", "Path to the private key")
	sshHostKeysPath  = flag.String("ssh-host-keys-path", "/etc/ssh", "Path where ssh_host_ecdsa_key, ssh_host_ed25519_key, ssh_host_rsa_key can be found")
	githubSubdomains = flag.Bool("github-subdomains", false, "Whether to expose $username.gh subdomains")
	gitlabSubdomains = flag.Bool("gitlab-subdomains", false, "Whether to expose $username.gl subdomains")
	docsUrl          = flag.String("docs-url", "https://github.com/xtrafrancyz/srvus", "URL to the documentation")

	httpSupported = false
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
)

type closeWriter interface {
	CloseWrite() error
}

type pipeStats struct {
	sent int64
	recv int64
}

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type target struct {
	KeyID  string
	Remote *ssh.ServerConn
	Host   string
	Port   uint32
}

type tcpTarget struct {
	Listener net.Listener
	Target   *target
}

type tunnelRef struct {
	Endpoint string
	Target   *target
}

type sshConnection struct {
	KeyID      string
	Sessions   []ssh.Channel
	TunnelRefs []*tunnelRef
	lastPort   uint16
}

type server struct {
	sync.Mutex
	conns             map[*ssh.ServerConn]*sshConnection
	endpoints         map[string][]*target
	tcpListeners      []*tcpTarget
	dns               *doh.DoH
	activeClientConns int
}

func newServer() *server {
	return &server{
		conns:     make(map[*ssh.ServerConn]*sshConnection),
		endpoints: make(map[string][]*target),
		dns:       doh.Use(doh.GoogleProvider, doh.CloudflareProvider),
	}
}

func (s *server) newPort(conn *ssh.ServerConn) uint16 {
	s.Lock()
	defer s.Unlock()

	s.conns[conn].lastPort++
	if s.conns[conn].lastPort == 0 {
		s.conns[conn].lastPort = 1
	}
	return s.conns[conn].lastPort
}

// A lock is required
func (s *server) insertEndpointTarget(endpoint string, t *target) {
	log.Printf("%s(%s) on %s", t.Remote.RemoteAddr(), t.KeyID, endpoint)

	sConn, ok := s.conns[t.Remote]
	if !ok {
		return
	}

	s.endpoints[endpoint] = append(s.endpoints[endpoint], t)
	sConn.TunnelRefs = append(sConn.TunnelRefs, &tunnelRef{
		Endpoint: endpoint,
		Target:   t,
	})
}

// A lock is required
func (s *server) removeEndpointTarget(endpoint string, t *target) {
	log.Printf("%s(%s) off %s", t.Remote.RemoteAddr(), t.KeyID, endpoint)

	if s.endpoints[endpoint] == nil {
		return
	}

	s.endpoints[endpoint] = slices.DeleteFunc(s.endpoints[endpoint], func(ref *target) bool {
		return ref.Remote == t.Remote && ref.Host == t.Host && ref.Port == t.Port && ref.KeyID == t.KeyID
	})
	if len(s.endpoints[endpoint]) == 0 {
		delete(s.endpoints, endpoint)
	}

	sConn, ok := s.conns[t.Remote]
	if !ok {
		return
	}
	sConn.TunnelRefs = slices.DeleteFunc(sConn.TunnelRefs, func(ref *tunnelRef) bool {
		return ref.Endpoint == endpoint && ref.Target == t
	})
}

func (s *server) addTcpListener(t *tcpTarget) bool {
	s.Lock()
	defer s.Unlock()

	if _, ok := s.conns[t.Target.Remote]; !ok {
		return false
	}
	s.tcpListeners = append(s.tcpListeners, t)
	return true
}

func (s *server) pickTarget(endpoint string) *target {
	s.Lock()
	ep, found := s.endpoints[endpoint]
	s.Unlock()

	if !found && false {
		resp, err := s.dns.Query(context.Background(), dns.Domain(endpoint), "CNAME")
		if err != nil {
			log.Printf("Could not resolve %s (%v)", endpoint, err)
			return nil
		}

		s.Lock()
		for _, rec := range resp.Answer {
			host := strings.TrimSuffix(rec.Data, ".")
			ep, found = s.endpoints[host]
			if found {
				break
			}
		}
		s.Unlock()
	}

	if !found {
		return nil
	} else {
		var candidates []*target
		for _, c := range ep {
			candidates = append(candidates, c)
		}
		if len(candidates) == 0 {
			return nil
		}
		return candidates[rand.IntN(len(candidates))]
	}
}

func (s *server) startSession(conn *ssh.ServerConn, ch ssh.Channel) bool {
	s.Lock()
	defer s.Unlock()

	if _, ok := s.conns[conn]; ok {
		s.conns[conn].Sessions = append(s.conns[conn].Sessions, ch)
		return true
	}

	return false
}

func (s *server) endSession(conn *ssh.ServerConn, ch ssh.Channel) {
	reportStatus(ch, 0)
	if err := ch.Close(); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("Could not end SSH session (%v)", err)
	}

	s.Lock()
	defer s.Unlock()

	c := s.conns[conn]
	if c == nil {
		return
	}
	c.Sessions = slices.DeleteFunc(c.Sessions, func(c ssh.Channel) bool {
		return c == ch
	})

	if len(c.Sessions) == 0 {
		go func() {
			_ = conn.Close()
		}()
	}
}

func (s *server) startConnection(conn *ssh.ServerConn, keyID string) *sshConnection {
	s.Lock()
	defer s.Unlock()

	c := &sshConnection{
		KeyID:    keyID,
		lastPort: 0,
	}
	s.conns[conn] = c
	return c
}

func (s *server) closeConnection(conn *ssh.ServerConn) {
	s.Lock()
	defer s.Unlock()

	sConn, found := s.conns[conn]
	if !found {
		return
	}
	s.tcpListeners = slices.DeleteFunc(s.tcpListeners, func(ref *tcpTarget) bool {
		match := ref.Target.Remote == conn
		if match {
			go func() {
				err := ref.Listener.Close()
				if err != nil {
					log.Printf("Could not close TCP listener (%v)", err)
				}
			}()
		}
		return match
	})
	for _, er := range sConn.TunnelRefs {
		s.removeEndpointTarget(er.Endpoint, er.Target)
	}
	delete(s.conns, conn)
	go func() {
		_ = conn.Close()
		log.Printf("%s(%s) disconnected", conn.RemoteAddr(), sConn.KeyID)
	}()
}

func (s *server) serveTCP(listener net.Listener, tgt *target, msg func(msg string)) {
	defer func() {
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("Failed to accept TCP connection (%s)", err)
			}
			return
		}

		msg(fmt.Sprintf("New connection from %s", conn.RemoteAddr()))

		go func() {
			defer func() {
				_ = conn.Close()
			}()

			stats, err := s.pipeConns(listener.Addr().String(), tgt, conn)
			if err != nil {
				log.Printf("Could not open channel to %s:%d (%v)", tgt.Host, tgt.Port, err)
			}

			msg(fmt.Sprintf("Connection from %s closed. Sent %d, Recv %d", conn.RemoteAddr(), stats.sent, stats.recv))
		}()
	}
}

func (s *server) serveHTTPS() {
	listener, err := net.Listen("tcp", *httpsAddr)
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("Listening for HTTPS on %s", *httpsAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept HTTPS connection (%s)", err)
			continue
		}

		go s.serveHTTPSConnection(conn)
	}
}

func (s *server) serveHTTP() {
	listener, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("Listening for HTTP on %s", *httpAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept HTTP connection (%s)", err)
			continue
		}

		go s.serveHTTPConnection(conn)
	}
}

func (s *server) serveHTTPSConnection(raw net.Conn) {
	name := ""

	cert, err := tls.LoadX509KeyPair(*httpsChainPath, *httpsKeyPath)
	if err != nil {
		log.Println(err)
		return
	}

	c := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(i *tls.ClientHelloInfo) (*tls.Config, error) {
			name = i.ServerName
			return nil, nil
		},
		NextProtos: []string{
			"http/1.1",
		},
	}

	https := tls.Server(raw, c)

	defer func() {
		_ = https.Close()
	}()

	if err := https.Handshake(); err != nil {
		return
	}

	s.handleHTTP(name, https)
}

func (s *server) serveHTTPConnection(raw net.Conn) {
	defer func() {
		_ = raw.Close()
	}()

	var buf bytes.Buffer
	reader := bufio.NewReader(io.TeeReader(raw, &buf))

	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	s.handleHTTP(req.Host, NewCustomConn(raw, io.MultiReader(&buf, raw)))
}

func (s *server) handleHTTP(name string, conn net.Conn) {
	if name == *domain {
		err := s.serveRoot(conn)
		if err != nil {
			log.Printf("root failed (%v)", err)
		}
		return
	}

	tgt := s.pickTarget(name)
	if tgt == nil {
		_ = httpErrorOut(conn, "503 Service Unavailable", "No tunnel available.")
		return
	}

	_, err := s.pipeConns(name, tgt, conn)
	if err != nil {
		_ = httpErrorOut(conn, "502 Bad Gateway", err.Error())
	}
}

func (s *server) pipeConns(name string, tgt *target, conn net.Conn) (pipeStats, error) {
	sshChannel, reqs, err := tgt.Remote.OpenChannel("forwarded-tcpip", ssh.Marshal(&remoteForwardChannelData{
		DestAddr:   tgt.Host,
		DestPort:   tgt.Port,
		OriginAddr: *domain,
		OriginPort: uint32(s.newPort(tgt.Remote)),
	}))

	if err != nil {
		return pipeStats{}, err
	}

	s.Lock()
	s.activeClientConns++
	s.Unlock()
	defer func() {
		s.Lock()
		s.activeClientConns--
		s.Unlock()

		if err := sshChannel.Close(); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v:%s→%v channel close failed (%d)", tgt.Remote.RemoteAddr(), name, conn.RemoteAddr(), err)
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		for req := range reqs {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()

	var sent int64
	var recv int64

	go func() {
		b, err := io.Copy(conn, sshChannel)
		sent = b
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v %s→%v copy failed (%v)", tgt.Remote.RemoteAddr(), name, conn.RemoteAddr(), err)
		}
		if cw, ok := conn.(closeWriter); ok {
			err = cw.CloseWrite()
		} else {
			err = conn.Close()
		}
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v %s→%v close failed (%v)", tgt.Remote.RemoteAddr(), name, conn.RemoteAddr(), err)
		}
		wg.Done()
	}()

	go func() {
		b, err := io.Copy(sshChannel, conn)
		recv = b
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v %s←%v copy failed (%v)", tgt.Remote.RemoteAddr(), name, conn.RemoteAddr(), err)
		}
		if err := sshChannel.CloseWrite(); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("%v %s←%v close failed (%v)", tgt.Remote.RemoteAddr(), name, conn.RemoteAddr(), err)
		}
		wg.Done()
	}()

	wg.Wait()

	log.Printf("%v: finished %s - %v sent %d recv %d", tgt.Remote.RemoteAddr(), name, conn.RemoteAddr(), sent, recv)

	return pipeStats{sent, recv}, nil
}

func (s *server) serveRoot(https net.Conn) error {
	r := bufio.NewReader(https)
	req, err := http.ReadRequest(r)
	if err != nil {
		return fmt.Errorf("could not read request: %w", err)
	}
	if req.URL.Path == "/" {
		_, _ = https.Write([]byte("HTTP/1.1 307 Temporary Redirect\r\nLocation: " + *docsUrl + "\r\n\r\n"))
	} else {
		_, _ = https.Write([]byte("HTTP/1.1 404 Not Found\n\n"))
	}
	return nil
}

func httpErrorOut(conn net.Conn, status string, message string) error {
	r := bufio.NewReader(conn)
	if _, err := http.ReadRequest(r); err != nil {
		return err
	}
	_, err := conn.Write([]byte(fmt.Sprintf("HTTP/1.1 %s\r\nContent-Length: %d\r\n\r\n%s", status, len(message), message)))
	return err
}

func (s *server) serveSSH() {
	sshConfig := ssh.ServerConfig{
		ServerVersion: "SSH-2.0-" + *domain + "-1.0",
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return `
Docs: ` + *docsUrl + `

`
		},
	}
	addKey(&sshConfig, *sshHostKeysPath+"/ssh_host_ecdsa_key")
	addKey(&sshConfig, *sshHostKeysPath+"/ssh_host_ed25519_key")
	addKey(&sshConfig, *sshHostKeysPath+"/ssh_host_rsa_key")

	listener, err := net.Listen("tcp", *sshAddr)
	if err != nil {
		log.Fatalf("Failed to listen on addr %s (%s)", *sshAddr, err)
	}

	log.Printf("Listening for SSH on %s", *sshAddr)

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept (%s)", err)
		} else {
			go s.serveSSHConnection(&sshConfig, &tcpConn)
		}
	}
}

func (s *server) serveSSHConnection(sshConfig *ssh.ServerConfig, tcpConn *net.Conn) {
	keyID := ""
	noauth := false
	config := sshConfig
	config.PublicKeyCallback = func(conn ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		keyID = base64.RawStdEncoding.EncodeToString(k.Marshal()[:])
		return &ssh.Permissions{}, nil
	}
	config.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		// Request zero input fields (no prompts needed).
		// The challenge function is provided by the server to request info.
		// Request 0 prompts (empty instruction, empty name, nil questions)
		_, err := challenge("", "", nil, nil)
		if err != nil {
			return nil, err
		}
		noauth = true
		b := make([]byte, 32)
		_, _ = cryptorand.Read(b)
		keyID = base64.RawStdEncoding.EncodeToString(b)
		return &ssh.Permissions{}, nil
	}
	config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		noauth = true
		b := make([]byte, 32)
		_, _ = cryptorand.Read(b)
		keyID = base64.RawStdEncoding.EncodeToString(b)
		return &ssh.Permissions{}, nil
	}

	conn, newChans, reqs, err := ssh.NewServerConn(*tcpConn, config)
	if keyID == "" || err != nil {
		return
	}

	githubEnabled := false
	if *githubSubdomains && !noauth && conn.User() != "nomatch" {
		githubEnabled = keyMatchesAccount("github.com", conn.User(), keyID)
	}
	gitlabEnabled := false
	if *gitlabSubdomains && !noauth && conn.User() != "nomatch" {
		gitlabEnabled = keyMatchesAccount("gitlab.com", conn.User(), keyID)
	}

	srvSshConn := s.startConnection(conn, keyID)
	log.Printf("%s (%s) connected (%s, %s, gh:%v, gl:%v)",
		conn.RemoteAddr(), keyID, conn.ClientVersion(), conn.User(), githubEnabled, gitlabEnabled)

	// We want to have at least one session opened so we can send messages to it.
	outputReadyCh := make(chan struct{})
	outputReadyChCloser := NewSafeCloser(outputReadyCh)
	keepalives := make(chan struct{})
	msgs := make(chan string, 10)
	ctx, cancel := context.WithCancel(context.Background())
	requested := int32(0)

	defer func() {
		cancel()
		close(msgs)
		outputReadyChCloser.Close()
		s.closeConnection(conn)
	}()

	sendMsg := func(msg string) {
		colored := ColorCyan + msg + ColorReset
		select {
		case <-ctx.Done():
		case msgs <- colored:
		default: // drop message if buffer full
		}
	}

	go func() {
		t := time.NewTicker(5 * time.Second)
		for range t.C {
			if _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				close(keepalives)
				return
			} else {
				keepalives <- struct{}{}
			}
		}
	}()

	go func() {
		for nc := range newChans {
			newChannel := nc
			go func() {
				if t := newChannel.ChannelType(); t != "session" {
					log.Printf("Rejecting channel type %s", t)
					err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
					if err != nil {
						log.Printf("Failed to reject channel type %s (%s)", t, err)
					}
					return
				}

				channel, sessionReqs, err := newChannel.Accept()
				if err != nil {
					log.Printf("Could not accept channel (%s)", err)
					return
				}

				defer s.endSession(conn, channel)
				if !s.startSession(conn, channel) {
					return
				}

				outputReadyChCloser.Close()

				go func() {
					buf := make([]byte, 256)
					for {
						read, err := channel.Read(buf)
						if err != nil && errors.Is(err, io.EOF) {
							return
						}
						// ctrl-c & ctrl-d
						if bytes.ContainsAny(buf[:read], "\x03\x04") {
							s.endSession(conn, channel)
							break
						}
					}
				}()

				go func() {
					<-time.After(1 * time.Second)
					if atomic.LoadInt32(&requested) == 0 {
						reportStatus(channel, 1)
						_ = channel.Close()
					}
				}()

				for req := range sessionReqs {
					if req.Type == "shell" || req.Type == "pty-req" {
						if err := req.Reply(true, nil); err != nil {
							log.Printf("Could not accept request of type %s (%v)", req.Type, err)
						}
					} else {
						if err := req.Reply(false, nil); err != nil {
							return
						}
					}
				}
			}()
		}
	}()

	go func() {
		<-outputReadyCh

		for msg := range msgs {
			for _, sess := range srvSshConn.Sessions {
				if _, err := sess.Write([]byte(msg + "\r\n")); err != nil {
					log.Printf("Could not send message %s (%v)", msg, err)
				}
			}
		}
	}()

	for {
		select {
		case req := <-reqs:
			if req == nil {
				return
			}
			switch req.Type {
			case "tcpip-forward":
				var payload remoteForwardRequest
				if err = ssh.Unmarshal(req.Payload, &payload); err != nil {
					log.Printf("Invalid new tcpip-forward request (%v)", err)
					if req.WantReply {
						if err := req.Reply(false, nil); err != nil {
							log.Printf("Could not reject new channel request of type %s (%v)", req.Type, err)
						}
					}
					continue
				}
				tgt := &target{
					KeyID:  keyID,
					Remote: conn,
					Host:   payload.BindAddr,
					Port:   payload.BindPort,
				}
				if conn.User() == "tcp" {
					listener, err := net.Listen("tcp", ":"+strconv.Itoa(int(payload.BindPort)))
					if err != nil {
						log.Printf("Could not listen on port %d (%v)", payload.BindPort, err)
						if req.WantReply {
							if err := req.Reply(false, nil); err != nil {
								log.Printf("Could not reject new channel request of type %s (%v)", req.Type, err)
							}
						}
						continue
					}

					atomic.AddInt32(&requested, 1)
					port := listener.Addr().(*net.TCPAddr).Port
					tgt.Port = uint32(port)

					if !s.addTcpListener(&tcpTarget{listener, tgt}) {
						_ = listener.Close()
						continue
					}

					log.Printf("%s listening tcp :%d", conn.RemoteAddr(), port)

					go s.serveTCP(listener, tgt, sendMsg)

					sendMsg(fmt.Sprintf(ColorGreen+"TCP:"+ColorCyan+" %s:%d", *domain, port))

					if req.WantReply {
						if err := req.Reply(true, ssh.Marshal(struct{ uint32 }{tgt.Port})); err != nil {
							log.Printf("Could not accept new channel request of type %s (%v)", req.Type, err)
						}
					}
				} else if httpSupported {
					endpoints := endpointURLs(conn.User(), keyID, payload.BindPort, githubEnabled, gitlabEnabled)
					atomic.AddInt32(&requested, 1)

					var urls []string
					for _, endpoint := range endpoints {
						urls = append(urls, "https://"+endpoint+"/")
					}
					sendMsg(fmt.Sprintf("%d: %s", payload.BindPort, strings.Join(urls, ", ")))

					if payload.BindPort == 0 {
						tgt.Port = 443
					}

					s.Lock()
					for _, endpoint := range endpoints {
						s.insertEndpointTarget(endpoint, tgt)
					}
					s.Unlock()

					if req.WantReply {
						if err := req.Reply(true, ssh.Marshal(struct{ uint32 }{443})); err != nil {
							log.Printf("Could not accept new channel request of type %s (%v)", req.Type, err)
						}
					}
				} else if req.WantReply {
					if err := req.Reply(false, nil); err != nil {
						log.Printf("Could not reject new channel request of type %s (%v)", req.Type, err)
					}
				}
			case "cancel-tcpip-forward":
				var payload remoteForwardCancelRequest
				if err = ssh.Unmarshal(req.Payload, &payload); err != nil {
					log.Printf("Invalid new tcpip-forward request (%v)", err)
					if req.WantReply {
						if err := req.Reply(false, nil); err != nil {
							log.Printf("Could not reject new channel request of type %s (%v)", req.Type, err)
						}
					}
					continue
				}
				if conn.User() == "tcp" {
					atomic.AddInt32(&requested, 1)

					s.Lock()
					var forClose []*tcpTarget
					closedPort := 0
					s.tcpListeners = slices.DeleteFunc(s.tcpListeners, func(ref *tcpTarget) bool {
						if ref.Target.Remote == conn &&
							ref.Target.KeyID == keyID &&
							ref.Target.Host == payload.BindAddr &&
							ref.Target.Port == payload.BindPort || payload.BindPort == 0 {
							forClose = append(forClose, ref)
							closedPort = ref.Listener.Addr().(*net.TCPAddr).Port
							return true
						}
						return false
					})
					s.Unlock()

					for _, ref := range forClose {
						if err := ref.Listener.Close(); err != nil {
							log.Printf("Could not close TCP listener (%v)", err)
						}
					}

					if req.WantReply {
						if err := req.Reply(true, ssh.Marshal(struct{ uint32 }{uint32(closedPort)})); err != nil {
							log.Printf("Could not accept new channel request of type %s (%v)", req.Type, err)
						}
					}
				} else if httpSupported {
					endpoints := endpointURLs(conn.User(), keyID, payload.BindPort, githubEnabled, gitlabEnabled)
					atomic.AddInt32(&requested, 1)

					s.Lock()
					for _, endpoint := range endpoints {
						s.removeEndpointTarget(endpoint, &target{
							KeyID:  keyID,
							Remote: conn,
							Host:   payload.BindAddr,
							Port:   payload.BindPort,
						})
					}
					s.Unlock()

					if req.WantReply {
						if err := req.Reply(true, ssh.Marshal(struct{ uint32 }{443})); err != nil {
							log.Printf("Could not accept new channel request of type %s (%v)", req.Type, err)
						}
					}
				} else if req.WantReply {
					if err := req.Reply(false, nil); err != nil {
						log.Printf("Could not reject new channel request of type %s (%v)", req.Type, err)
					}
				}
			case "keepalive@openssh.com":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					if err := req.Reply(false, nil); err != nil {
						log.Printf("Failed to reply to %v (%v)", req, err)
					} else {
						log.Printf("Rejected request of type %v", req.Type)
					}
				}
			}
		case <-keepalives:
		case <-time.After(10 * time.Second):
			log.Printf("%s(%s) timed out", conn.RemoteAddr(), keyID)
			return
		}
	}
}

func keyMatchesAccount(domain, user, key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/%s.keys", domain, user), nil)
	if err != nil {
		log.Printf("Error creating request to %s for %s (%v)", domain, user, err)
		return false
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error querying %s for %s (%v)", domain, user, err)
		return false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("Error reading response from %s for %s (%v)", domain, user, err)
		return false
	}
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		if strings.TrimRight(parts[1], "=") == key {
			return true
		}
	}
	return false
}

func (s *server) logStats() {
	type stats struct {
		sshConns      int
		tcpEndpoints  int
		httpEndpoints int
		clientConns   int
	}
	collect := func() stats {
		s.Lock()
		defer s.Unlock()
		return stats{
			sshConns:      len(s.conns),
			tcpEndpoints:  len(s.tcpListeners),
			httpEndpoints: len(s.endpoints),
			clientConns:   s.activeClientConns,
		}
	}
	prev := collect()
	t := time.NewTicker(time.Minute)
	for range t.C {
		curr := collect()
		if curr == prev {
			continue
		}
		prev = curr
		log.Printf("Stats: %d ssh conns, endpoints: %d tcp; %d http, %d client conns", curr.sshConns, curr.tcpEndpoints, curr.httpEndpoints, curr.clientConns)
	}
}

func endpointURLs(user string, keyid string, port uint32, githubEnabled bool, gitlabEnabled bool) []string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(keyid))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(strconv.Itoa(int(port))))
	b32 := b32encoder.EncodeToString(hasher.Sum(nil)[:16])
	result := []string{fmt.Sprintf("%s.%s", b32, *domain)}
	lower := strings.ToLower(user)
	if githubEnabled {
		if port == 1 {
			result = append(result, fmt.Sprintf("%s.gh.%s", lower, *domain))
		} else {
			result = append(result, fmt.Sprintf("%s--%d.gh.%s", lower, port, *domain))
		}
	}
	if gitlabEnabled {
		result = append(result, fmt.Sprintf("%s-%d.gl.%s", lower, port, *domain))
	}
	return result
}

func reportStatus(ch ssh.Channel, status byte) {
	_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, status})
}

func addKey(sshConfig *ssh.ServerConfig, path string) {
	privateBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read private key %s (%v)", path, err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key %s (%v)", path, err)
	}

	sshConfig.AddHostKey(private)
}

func main() {
	flag.Parse()

	s := newServer()
	go s.logStats()
	if *httpsAddr != "" {
		go s.serveHTTPS()
		httpSupported = true
	}
	if *httpAddr != "" {
		go s.serveHTTP()
		httpSupported = true
	}
	s.serveSSH()
}
