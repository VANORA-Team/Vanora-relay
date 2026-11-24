package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"vanora-relay/adapter/account"
)

type loginOptions struct {
	channel    string
	token      string
	tokenStdin bool
	in         io.Reader
	emitter    *jsonEmitter
}

func readTokenInput(token string, fromStdin bool, in io.Reader) (string, error) {
	if fromStdin {
		if in == nil {
			return "", errors.New("stdin unavailable")
		}
		reader := bufio.NewReaderSize(in, 32<<10)
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		token = line
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("client auth token required (-token, -token-stdin, or VANORA_CLIENT_TOKEN)")
	}
	return token, nil
}

func login(parent context.Context, a *account.Account, opts loginOptions) error {
	tok, err := readTokenInput(opts.token, opts.tokenStdin, opts.in)
	if err != nil {
		return err
	}
	ctx, stop := context.WithTimeout(parent, 30*time.Second)
	defer stop()

	if err := a.Enroll(ctx, tok); err != nil {
		return err
	}
	if opts.emitter != nil {
		ev := map[string]any{
			"type":      "login.ok",
			"user_id":   a.UserID(),
			"device_id": a.DeviceID(),
		}
		if opts.channel != "" {
			ev["channel"] = opts.channel
		}
		opts.emitter.Emit(ev)
		return nil
	}
	fmt.Printf("user_id=%s\ndevice_id=%s\n", a.UserID(), a.DeviceID())
	return nil
}
