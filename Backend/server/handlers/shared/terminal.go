package shared

import (
	"crypto/tls"
	"cyberrange/utils"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/labstack/echo/v4"

	"net/http"
	"net/url"
)

type WebsocketProxy struct {
	scheme          string
	remoteAddr      string
	defaultPath     string
	tlsc            *tls.Config
	logger          *log.Logger
	beforeHandshake func(r *http.Request) error
}

const (
	WsScheme  = "ws"
	WssScheme = "wss"
	BufSize   = 1024 * 32
)

var (
	byteSlicePool = sync.Pool{
		New: func() interface{} {
			return []byte{}
		},
	}
	byteSliceChan = make(chan []byte, 10)
	ErrFormatAddr = errors.New("remote websockets addr format error")
)

type Options func(wp *WebsocketProxy)

func Terminal(c echo.Context) error {
	color.Green("Connecting to terminal")
	token := c.QueryParam("token")
	if !utils.ValidateToken(token) {
		return c.JSON(401, map[string]string{"error": "Unauthorized"})
	}

	ip := utils.GetContainerIP(token)

	wsURL := "ws://" + ip + ":8080/ws?"
	disguiseURL := "http://" + ip + ":8080"
	args := c.QueryParams()["arg"]
	for _, arg := range args {
		wsURL += "arg=" + arg + "&"
	}

	wp, err := NewProxy(wsURL, func(r *http.Request) error {

		r.Header.Set("Origin", disguiseURL)
		return nil
	})
	if err != nil {
		fmt.Println(err)

	}

	wp.ServeHTTP(c.Response(), c.Request())

	return nil
}

func NewProxy(addr string, beforeCallback func(r *http.Request) error, options ...Options) (*WebsocketProxy, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, ErrFormatAddr
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, ErrFormatAddr
	}
	if u.Scheme != WsScheme && u.Scheme != WssScheme {
		return nil, ErrFormatAddr
	}
	wp := &WebsocketProxy{
		scheme:          u.Scheme,
		remoteAddr:      fmt.Sprintf("%s:%s", host, port),
		defaultPath:     u.Path,
		beforeHandshake: beforeCallback,
		logger:          log.New(os.Stderr, "", log.LstdFlags),
	}
	if u.Scheme == WssScheme {
		wp.tlsc = &tls.Config{InsecureSkipVerify: true}
	}
	for op := range options {
		options[op](wp)
	}
	return wp, nil
}

func (wp *WebsocketProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	wp.Proxy(writer, request)
}

func (wp *WebsocketProxy) Proxy(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Connection") != "Upgrade" && request.Header.Get("Connection") != "keep-alive, Upgrade" {
		_, _ = writer.Write([]byte(`Must be a websocket request`))
		return
	}

	if strings.ToLower(request.Header.Get("Upgrade")) != "websocket" {
		_, _ = writer.Write([]byte(`Must be a websocket request`))
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		fmt.Println("http.Hijacker not supported")
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Println("hijack err:", err)
		return
	}
	defer conn.Close()
	req := request.Clone(request.Context())
	req.URL.Path, req.URL.RawPath, req.RequestURI = wp.defaultPath, wp.defaultPath, wp.defaultPath
	req.Host = wp.remoteAddr
	if wp.beforeHandshake != nil {
		err = wp.beforeHandshake(req)
		if err != nil {
			fmt.Println("beforeHandshake err:", err)
			_, _ = writer.Write([]byte(err.Error()))
			return
		}
	}
	var remoteConn net.Conn
	for {
		switch wp.scheme {
		case WsScheme:
			remoteConn, err = net.Dial("tcp", wp.remoteAddr)
		case WssScheme:
			remoteConn, err = tls.Dial("tcp", wp.remoteAddr, wp.tlsc)
		}
		if err != nil {
			continue
		}
		break
	}
	defer remoteConn.Close()
	err = req.Write(remoteConn)
	if err != nil {
		wp.logger.Println("remote write err:", err)
		return
	}
	errChan := make(chan error, 2)
	copyConn := func(a, b net.Conn) {
		buf := ByteSliceGet(BufSize)
		defer ByteSlicePut(buf)
		_, err := io.CopyBuffer(a, b, buf)
		errChan <- err
	}
	go copyConn(conn, remoteConn)
	go copyConn(remoteConn, conn)
	err = <-errChan
	if err != nil {
		log.Println(err)
	}
}

func SetTLSConfig(tlsc *tls.Config) Options {
	return func(wp *WebsocketProxy) {
		wp.tlsc = tlsc
	}
}

func SetLogger(l *log.Logger) Options {
	return func(wp *WebsocketProxy) {
		if l != nil {
			wp.logger = l
		}
	}
}

func ByteSliceGet(length int) (data []byte) {
	select {
	case data = <-byteSliceChan:
	default:
		data = byteSlicePool.Get().([]byte)[:0]
	}

	if cap(data) < length {
		data = make([]byte, length)
	} else {
		data = data[:length]
	}

	return data
}

func ByteSlicePut(data []byte) {
	select {
	case byteSliceChan <- data:
	default:
		byteSlicePool.Put(&data)
	}
}
