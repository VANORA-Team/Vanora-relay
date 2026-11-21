package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"vanora-relay/adapter/account"
)

func openBrowser(raw string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", raw)
	case "darwin":
		cmd = exec.Command("open", raw)
	default:
		cmd = exec.Command("xdg-open", raw)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}

type loginOptions struct {
	redirectURI string
	noBrowser   bool
	emitter     *jsonEmitter
}

func isLoopbackHostname(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func login(parent context.Context, a *account.Account, opts loginOptions) error {
	ctx, stop := context.WithTimeout(parent, 5*time.Minute)
	defer stop()

	requestedRedirect := opts.redirectURI
	var preboundLn net.Listener
	if requestedRedirect != "" {
		if parsed, err := url.Parse(requestedRedirect); err == nil &&
			parsed.Scheme == "http" && isLoopbackHostname(parsed.Hostname()) && parsed.Port() == "0" {
			ln, err := net.Listen("tcp", net.JoinHostPort(parsed.Hostname(), "0"))
			if err != nil {
				return err
			}
			defer ln.Close()
			preboundLn = ln
			_, port, err := net.SplitHostPort(ln.Addr().String())
			if err != nil {
				return err
			}
			parsed.Host = net.JoinHostPort(parsed.Hostname(), port)
			requestedRedirect = parsed.String()
		}
	}

	raw, err := a.BeginWithRedirect(ctx, requestedRedirect)
	if err != nil {
		return err
	}
	auth, err := url.Parse(raw)
	if err != nil {
		return err
	}
	q := auth.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirect.Scheme == "" || q.Get("state") == "" {
		return errors.New("identity returned invalid callback configuration")
	}
	type answer struct {
		code  string
		state string
	}
	answers := make(chan answer, 1)
	parse := func(u *url.URL) (answer, bool) {
		if u.Scheme != redirect.Scheme || u.Host != redirect.Host || u.Path != redirect.Path || u.User != nil {
			return answer{}, false
		}
		v := u.Query()
		code, state := v.Get("code"), v.Get("state")
		return answer{code, state}, code != "" && state == q.Get("state")
	}
	host := redirect.Hostname()
	if redirect.Scheme == "http" && isLoopbackHostname(host) && redirect.Port() != "" {
		ln := preboundLn
		if ln == nil {
			var e error
			ln, e = net.Listen("tcp", redirect.Host)
			if e != nil {
				return e
			}
		}
		srv := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := *r.URL
			u.Scheme = "http"
			u.Host = r.Host
			v, ok := parse(&u)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			if !ok || r.Method != "GET" {
				http.Error(w, "Invalid callback", 400)
				return
			}
			select {
			case answers <- v:
			default:
			}
			fmt.Fprintln(w, "Vanora received the login callback. Return to the desktop.")
		})}
		defer srv.Close()
		go srv.Serve(ln)
	} else {
		if opts.emitter == nil {
			fmt.Fprintln(os.Stderr, "After sign-in, paste the complete callback URL into this terminal.")
		}
		go func() {
			reader := bufio.NewReaderSize(os.Stdin, 16384)
			line, e := reader.ReadString('\n')
			if e != nil && line == "" {
				stop()
				return
			}
			u, e := url.Parse(strings.TrimSpace(line))
			if e != nil {
				stop()
				return
			}
			if v, ok := parse(u); ok {
				select {
				case answers <- v:
				case <-ctx.Done():
				}
			} else {
				stop()
			}
		}()
	}
	if opts.emitter != nil {
		opts.emitter.Emit(map[string]any{
			"type":     "login.url",
			"url":      raw,
			"callback": redirect.String(),
		})
	}
	if !opts.noBrowser {
		if err = openBrowser(raw); err != nil && opts.emitter == nil {
			fmt.Fprintln(os.Stderr, "Open this address in the system browser:", raw)
		}
	}
	select {
	case <-ctx.Done():
		return errors.New("login cancelled, callback invalid, or challenge expired")
	case result := <-answers:
		if err = a.Finish(ctx, result.code, result.state); err != nil {
			return err
		}
	}
	if opts.emitter != nil {
		opts.emitter.Emit(map[string]any{
			"type":      "login.ok",
			"user_id":   a.UserID(),
			"device_id": a.DeviceID(),
		})
		return nil
	}
	fmt.Printf("user_id=%s\ndevice_id=%s\n", a.UserID(), a.DeviceID())
	return nil
}
