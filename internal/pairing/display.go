package pairing

import (
	"context"
	"encoding/base64"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

type Display struct {
	Link string
	Code string
	QR   string
}

func Present(ctx context.Context, relay, device, ticket, link string, expires time.Time) (Display, func(), error) {
	display, record, err := DisplayLink(link, expires)
	if err != nil {
		return Display{}, nil, err
	}
	if err := Publish(ctx, relay, device, ticket, record); err != nil {
		return Display{}, nil, err
	}
	retire := sync.OnceFunc(func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = Publish(ctx, relay, device, ticket, Record{Locator: record.Locator})
		}()
	})
	return display, retire, nil
}

func DisplayLink(link string, expires time.Time) (Display, Record, error) {
	png, err := qrcode.Encode(link, qrcode.Medium, -6)
	if err != nil {
		return Display{}, Record{}, err
	}
	code, record, err := Seal(link, expires)
	if err != nil {
		return Display{}, Record{}, err
	}
	return Display{link, code, "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)}, record, nil
}
