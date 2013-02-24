// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// RTSP server.  See RFC 2326.

// TODO(rsc):
//	logging

package rtsp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Errors introduced by the RTSP server.
var (
	ErrWriteAfterFlush = errors.New("Conn.Write called after Flush")
	ErrBodyNotAllowed  = errors.New("rtsp: request method or response status code does not allow body")
	ErrHijacked        = errors.New("Conn has been hijacked")
	ErrContentLength   = errors.New("Conn.Write wrote more than the declared Content-Length")
)

// Objects implementing the Handler interface can be
// registered to serve a particular path or subtree
// in the RTSP server.
//
// ServeRTSP should write reply headers and data to the ResponseWriter
// and then return.  Returning signals that the request is finished
// and that the RTSP server can move on to the next request on
// the connection.
type Handler interface {
	ServeRTSP(ResponseWriter, *Request)
}

// A ResponseWriter interface is used by an RTSP handler to
// construct an RTSP response.
type ResponseWriter interface {
	// Header returns the header map that will be sent by WriteHeader.
	// Changing the header after a call to WriteHeader (or Write) has
	// no effect.
	Header() Header

	// Write writes the data to the connection as part of an RTSP reply.
	// If WriteHeader has not yet been called, Write calls WriteHeader(rtsp.StatusOK)
	// before writing the data.  
	Write([]byte) (int, error)

	// WriteHeader sends an RTSP response header with status code.
	// If WriteHeader is not called explicitly, the first call to Write
	// will trigger an implicit WriteHeader(rtsp.StatusOK).
	// Thus explicit calls to WriteHeader are mainly used to
	// send error codes.
	WriteHeader(int)
}

// The Flusher interface is implemented by ResponseWriters that allow
// an RTSP handler to flush buffered data to the client.
//
// Note that even for ResponseWriters that support Flush,
// if the client is connected through an RTSP proxy,
// the buffered data may not reach the client until the response
// completes.
type Flusher interface {
	// Flush sends any buffered data to the client.
	Flush()
}

// The Hijacker interface is implemented by ResponseWriters that allow
// an RTSP handler to take over the connection.
type Hijacker interface {
	// Hijack lets the caller take over the connection.
	// After a call to Hijack(), the RTSP server library
	// will not do anything else with the connection.
	// It becomes the caller's responsibility to manage
	// and close the connection.
	Hijack() (net.Conn, *bufio.ReadWriter, error)
}

// A conn represents the server side of an RTSP connection.
type conn struct {
	remoteAddr string               // network address of remote side
	server     *Server              // the Server on which the connection arrived
	rwc        net.Conn             // i/o connection
	lr         *io.LimitedReader    // io.LimitReader(rwc)
	buf        *bufio.ReadWriter    // buffered(lr,rwc), reading from bufio->limitReader->rwc
	hijacked   bool                 // connection has been hijacked by handler
	body       []byte
}

// A response represents the server side of an RTSP response.
type response struct {
	conn          *conn
	req           *Request // request for this response
	chunking      bool     // using chunked transfer encoding for reply body
	wroteHeader   bool     // reply header has been written
	wroteContinue bool     // 100 Continue response was written
	header        Header   // reply header parameters
	written       int64    // number of bytes written in body
	contentLength int64    // explicitly-declared Content-Length; or -1
	status        int      // status code passed to WriteHeader
	needSniff     bool     // need to sniff to find Content-Type

	// close connection after this reply.  set on request and
	// updated after response from handler if there's a
	// "Connection: keep-alive" response header and a
	// Content-Length.
	closeAfterReply bool //will not close after reply

	// requestBodyLimitHit is set by requestTooLarge when
	// maxBytesReader hits its max size. It is checked in
	// WriteHeader, to make sure we don't consume the the
	// remaining request body to try to advance to the next RTSP 
	// request. Instead, when this is set, we stop doing
	// subsequent requests on this connection and stop reading
	// input from it.
	requestBodyLimitHit bool
}

// requestTooLarge is called by maxBytesReader when too much input has
// been read from the client.
func (w *response) requestTooLarge() {
	w.closeAfterReply = true
	w.requestBodyLimitHit = true
	if !w.wroteHeader {
		w.Header().Set("Connection", "close")
	}
}

type writerOnly struct {
	io.Writer
}

func (w *response) ReadFrom(src io.Reader) (n int64, err error) {
	// Call WriteHeader before checking w.chunking if it hasn't
	// been called yet, since WriteHeader is what sets w.chunking.
	if !w.wroteHeader {
		w.WriteHeader(StatusOK)
	}
	if !w.chunking && w.bodyAllowed() && !w.needSniff {
		w.Flush()
		if rf, ok := w.conn.rwc.(io.ReaderFrom); ok {
			n, err = rf.ReadFrom(src)
			w.written += n
			return
		}
	}
	// Fall back to default io.Copy implementation.
	// Use wrapper to hide w.ReadFrom from io.Copy.
	return io.Copy(writerOnly{w}, src)
}

// noLimit is an effective infinite upper bound for io.LimitedReader
const noLimit int64 = (1 << 63) - 1

// Create new connection from rwc.
func (srv *Server) newConn(rwc net.Conn) (c *conn, err error) {
	c = new(conn)
	c.remoteAddr = rwc.RemoteAddr().String()
	c.server = srv
	c.rwc = rwc
	c.body = make([]byte, sniffLen)
	c.lr = io.LimitReader(rwc, noLimit).(*io.LimitedReader)
	br := bufio.NewReader(c.lr)
	bw := bufio.NewWriter(rwc)
	c.buf = bufio.NewReadWriter(br, bw)
	return c, nil
}

// DefaultMaxHeaderBytes is the maximum permitted size of the headers
// in an HTTP request.
// This can be overridden by setting Server.MaxHeaderBytes.
const DefaultMaxHeaderBytes = 1 << 20 // 1 MB

func (srv *Server) maxHeaderBytes() int {
	if srv.MaxHeaderBytes > 0 {
		return srv.MaxHeaderBytes
	}
	return DefaultMaxHeaderBytes
}

// wrapper around io.ReaderCloser which on first read, sends an
// HTTP/1.0 100 RTSP header
type expectContinueReader struct {
	resp       *response
	readCloser io.ReadCloser
	closed     bool
}

func (ecr *expectContinueReader) Read(p []byte) (n int, err error) {
	if ecr.closed {
		return 0, errors.New("rtsp: Read after Close on request Body")
	}
	if !ecr.resp.wroteContinue && !ecr.resp.conn.hijacked {
		ecr.resp.wroteContinue = true
		io.WriteString(ecr.resp.conn.buf, "RTSP/1.0 100 Continue\r\n\r\n")
		ecr.resp.conn.buf.Flush()
	}
	return ecr.readCloser.Read(p)
}

func (ecr *expectContinueReader) Close() error {
	ecr.closed = true
	return ecr.readCloser.Close()
}

// TimeFormat is the time format to use with
// time.Parse and time.Time.Format when parsing
// or generating times in HTTP headers.
// It is like time.RFC1123 but hard codes GMT as the time zone.
const TimeFormat = "Mon, 02 Jan 2006 15:04:05 GMT"

var errTooLarge = errors.New("rtsp: request too large")

// Read next request from connection.
func (c *conn) readRequest() (w *response, err error) {
	if c.hijacked {
		return nil, ErrHijacked
	}
	c.lr.N = int64(c.server.maxHeaderBytes()) + 4096 /* bufio slop */
	var req *Request
	if req, err = ReadRequest(c.buf.Reader); err != nil {
		if c.lr.N == 0 {
			return nil, errTooLarge
		}
		return nil, err
	}
	c.lr.N = noLimit

	req.RemoteAddr = c.remoteAddr
	req.TLS = c.tlsState

	w = new(response)
	w.conn = c
	w.req = req
	w.header = make(Header)
	w.contentLength = -1
	c.body = c.body[:0]
	return w, nil
}

func (w *response) Header() Header {
	return w.header
}

// maxPostHandlerReadBytes is the max number of Request.Body bytes not
// consumed by a handler that the server will read from the client
// in order to keep a connection alive.  If there are more bytes than
// this then the server to be paranoid instead sends a "Connection:
// close" response.
//
// This number is approximately what a typical machine's TCP buffer
// size is anyway.  (if we have the bytes on the machine, we might as
// well read them)
const maxPostHandlerReadBytes = 256 << 10

func (w *response) WriteHeader(code int) {
	if w.conn.hijacked {
		log.Print("rtsp: response.WriteHeader on hijacked connection")
		return
	}
	if w.wroteHeader {
		log.Print("rtsp: multiple response.WriteHeader calls")
		return
	}
	w.wroteHeader = true
	w.status = code

	// Check for a explicit (and valid) Content-Length header.
	var hasCL bool
	var contentLength int64
	if clenStr := w.header.Get("Content-Length"); clenStr != "" {
		var err error
		contentLength, err = strconv.ParseInt(clenStr, 10, 64)
		if err == nil {
			hasCL = true
		} else {
			log.Printf("rtsp: invalid Content-Length of %q sent", clenStr)
			w.header.Del("Content-Length")
		}
	}

	//TODO how to close connection???
	/*
	if w.req.wantsHttp10KeepAlive() && (w.req.Method == "HEAD" || hasCL) {
		_, connectionHeaderSet := w.header["Connection"]
		if !connectionHeaderSet {
			w.header.Set("Connection", "keep-alive")
		}
	} else if !w.req.ProtoAtLeast(1, 1) {
		// Client did not ask to keep connection alive.
		w.closeAfterReply = true
	}

	if w.header.Get("Connection") == "close" {
		w.closeAfterReply = true
	}
	*/

	proto := "RTSP/1.0"
	if w.req.ProtoAtLeast(1, 1) {
		proto = "RTSP/1.1"
	}
	codestring := strconv.Itoa(code)
	text, ok := statusText[code]
	if !ok {
		text = "status code " + codestring
	}
	io.WriteString(w.conn.buf, proto+" "+codestring+" "+text+"\r\n")
	w.header.Write(w.conn.buf)

	// If we need to sniff the body, leave the header open.
	// Otherwise, end it here.
	if !w.needSniff {
		io.WriteString(w.conn.buf, "\r\n")
	}
}

// sniff uses the first block of written data,
// stored in w.conn.body, to decide the Content-Type
// for the RTSP body.
func (w *response) sniff() {
	if !w.needSniff {
		return
	}
	w.needSniff = false

	data := w.conn.body
	fmt.Fprintf(w.conn.buf, "Content-Type: %s\r\n\r\n", DetectContentType(data))

	if len(data) == 0 {
		return
	}
	if w.chunking {
		fmt.Fprintf(w.conn.buf, "%x\r\n", len(data))
	}
	_, err := w.conn.buf.Write(data)
	if w.chunking && err == nil {
		io.WriteString(w.conn.buf, "\r\n")
	}
}

// bodyAllowed returns true if a Write is allowed for this response type.
// It's illegal to call this before the header has been flushed.
func (w *response) bodyAllowed() bool {
	if !w.wroteHeader {
		panic("")
	}
	return w.status != StatusNotModified && w.req.Method != "HEAD"
}

func (w *response) Write(data []byte) (n int, err error) {
	if w.conn.hijacked {
		log.Print("http: response.Write on hijacked connection")
		return 0, ErrHijacked
	}
	if !w.wroteHeader {
		w.WriteHeader(StatusOK)
	}
	if len(data) == 0 {
		return 0, nil
	}
	if !w.bodyAllowed() {
		return 0, ErrBodyNotAllowed
	}

	w.written += int64(len(data)) // ignoring errors, for errorKludge
	if w.contentLength != -1 && w.written > w.contentLength {
		return 0, ErrContentLength
	}

	var m int
	if w.needSniff {
		// We need to sniff the beginning of the output to
		// determine the content type.  Accumulate the
		// initial writes in w.conn.body.
		// Cap m so that append won't allocate.
		m = cap(w.conn.body) - len(w.conn.body)
		if m > len(data) {
			m = len(data)
		}
		w.conn.body = append(w.conn.body, data[:m]...)
		data = data[m:]
		if len(data) == 0 {
			// Copied everything into the buffer.
			// Wait for next write.
			return m, nil
		}

		// Filled the buffer; more data remains.
		// Sniff the content (flushes the buffer)
		// and then proceed with the remainder
		// of the data as a normal Write.
		// Calling sniff clears needSniff.
		w.sniff()
	}

	// TODO(rsc): if chunking happened after the buffering,
	// then there would be fewer chunk headers.
	// On the other hand, it would make hijacking more difficult.
	if w.chunking {
		fmt.Fprintf(w.conn.buf, "%x\r\n", len(data)) // TODO(rsc): use strconv not fmt
	}
	n, err = w.conn.buf.Write(data)
	if err == nil && w.chunking {
		if n != len(data) {
			err = io.ErrShortWrite
		}
		if err == nil {
			io.WriteString(w.conn.buf, "\r\n")
		}
	}

	return m + n, err
}

func (w *response) finishRequest() {
	// If the handler never wrote any bytes and never sent a Content-Length
	// response header, set the length explicitly to zero. This helps
	// HTTP/1.0 clients keep their "keep-alive" connections alive, and for
	// HTTP/1.1 clients is just as good as the alternative: sending a
	// chunked response and immediately sending the zero-length EOF chunk.
	if w.written == 0 && w.header.Get("Content-Length") == "" {
		w.header.Set("Content-Length", "0")
	}
	// If this was an HTTP/1.0 request with keep-alive and we sent a
	// Content-Length back, we can make this a keep-alive response ...
	if w.req.wantsHttp10KeepAlive() {
		sentLength := w.header.Get("Content-Length") != ""
		if sentLength && w.header.Get("Connection") == "keep-alive" {
			w.closeAfterReply = false
		}
	}
	if !w.wroteHeader {
		w.WriteHeader(StatusOK)
	}
	if w.needSniff {
		w.sniff()
	}
	if w.chunking {
		io.WriteString(w.conn.buf, "0\r\n")
		// trailer key/value pairs, followed by blank line
		io.WriteString(w.conn.buf, "\r\n")
	}
	w.conn.buf.Flush()
	// Close the body, unless we're about to close the whole TCP connection
	// anyway.
	if !w.closeAfterReply {
		w.req.Body.Close()
	}
	if w.req.MultipartForm != nil {
		w.req.MultipartForm.RemoveAll()
	}

	if w.contentLength != -1 && w.contentLength != w.written {
		// Did not write enough. Avoid getting out of sync.
		w.closeAfterReply = true
	}
}

func (w *response) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(StatusOK)
	}
	w.sniff()
	w.conn.buf.Flush()
}

// Close the connection.
func (c *conn) close() {
	if c.buf != nil {
		c.buf.Flush()
		c.buf = nil
	}
	if c.rwc != nil {
		c.rwc.Close()
		c.rwc = nil
	}
}

// Serve a new connection.
func (c *conn) serve() {
	defer func() {
		err := recover()
		if err == nil {
			return
		}

		var buf bytes.Buffer
		fmt.Fprintf(&buf, "rtsp: panic serving %v: %v\n", c.remoteAddr, err)
		buf.Write(debug.Stack())
		log.Print(buf.String())

		if c.rwc != nil { // may be nil if connection hijacked
			c.rwc.Close()
		}
	}()

	for {
		w, err := c.readRequest()
		if err != nil {
			msg := "400 Bad Request"
			if err == errTooLarge {
				// Their RTSP client may or may not be
				// able to read this if we're
				// responding to them and hanging up
				// while they're still writing their
				// request.  Undefined behavior.
				msg = "413 Request Entity Too Large"
			} else if err == io.EOF {
				break // Don't reply
			} else if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				break // Don't reply
			}
			fmt.Fprintf(c.rwc, "RTSP/1.1 %s\r\n\r\n", msg)
			break
		}

		handler := c.server.Handler
		if handler == nil {
			handler = DefaultServeMux
		}

		// RTSP cannot have multiple simultaneous active requests.[*]
		// Until the server replies to this request, it can't read another,
		// so we might as well run the handler in this goroutine.
		// [*] Not strictly true: RTSP pipelining.  We could let them all process
		// in parallel even if their responses need to be serialized.
		handler.ServeRTSP(w, w.req)
		if c.hijacked {
			return
		}
		w.finishRequest()
		// TODO when close???
		if w.closeAfterReply {
			break
		}
	}
	c.close()
}

// Hijack implements the Hijacker.Hijack method. Our response is both a ResponseWriter
// and a Hijacker.
func (w *response) Hijack() (rwc net.Conn, buf *bufio.ReadWriter, err error) {
	if w.conn.hijacked {
		return nil, nil, ErrHijacked
	}
	w.conn.hijacked = true
	rwc = w.conn.rwc
	buf = w.conn.buf
	w.conn.rwc = nil
	w.conn.buf = nil
	return
}

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as HTTP handlers.  If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler object that calls f.
type HandlerFunc func(ResponseWriter, *Request)

// ServeRTSP calls f(w, r).
func (f HandlerFunc) ServeRTSP(w ResponseWriter, r *Request) {
	f(w, r)
}

// Helper handlers

// Error replies to the request with the specified error message and HTTP code.
func Error(w ResponseWriter, error string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintln(w, error)
}

// NotFound replies to the request with an RTSP 404 not found error.
func NotFound(w ResponseWriter, r *Request) { Error(w, "404 page not found", StatusNotFound) }

// NotFoundHandler returns a simple request handler
// that replies to each request with a ``404 page not found'' reply.
func NotFoundHandler() Handler { return HandlerFunc(NotFound) }

var htmlReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	// "&#34;" is shorter than "&quot;".
	`"`, "&#34;",
	// "&#39;" is shorter than "&apos;" and apos was not in HTML until HTML5.
	"'", "&#39;",
)

func htmlEscape(s string) string {
	return htmlReplacer.Replace(s)
}

// ServeMux is an RTSP request multiplexer.
// It matches the method of each incoming request against a list of registered
// method and calls the handler for the method that
// matches the method.
type ServeMux struct {
	mu sync.RWMutex
	m  map[string]muxEntry
}

type muxEntry struct {
	explicit bool
	h        Handler
}

// NewServeMux allocates and returns a new ServeMux.
func NewServeMux() *ServeMux { return &ServeMux{m: make(map[string]muxEntry)} }

// DefaultServeMux is the default ServeMux used by Serve.
var DefaultServeMux = NewServeMux()

func methodMatch(method) bool {
}

// Does path match pattern?
func pathMatch(pattern, path string) bool {
	if len(pattern) == 0 {
		// should not happen
		return false
	}
	n := len(pattern)
	if pattern[n-1] != '/' {
		return pattern == path
	}
	return len(path) >= n && path[0:n] == pattern
}

// Return the canonical path for p, eliminating . and .. elements.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}
	return np
}

// Find a handler on a handler map given a method string
func (mux *ServeMux) match(method string) Handler {
	var h Handler
	if v, ok := mux.m[method], ok {
		h = v.h	
	}
	return h
}

// handler returns the handler to use for the request r.
func (mux *ServeMux) handler(r *Request) Handler {
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	// Host-specific method takes precedence over generic ones
	h := mux.match(r.Method)
	if h == nil {
		h = NotFoundHandler()
	}
	return h
}

// ServeRTSP dispatches the request to the handler whose
// method same as the request method.
func (mux *ServeMux) ServeRTSP(w ResponseWriter, r *Request) {
	mux.handler(r).ServeRTSP(w, r)
}

// Handle registers the handler for the given method.
// If a handler already exists for method, Handle panics.
func (mux *ServeMux) Handle(method string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	if pattern == "" {
		panic("rtsp: invalid method " + method)
	}
	if handler == nil {
		panic("method: nil handler")
	}
	if mux.m[method].explicit {
		panic("rtsp: multiple registrations for " + method)
	}

	mux.m[method] = muxEntry{explicit: true, h: handler}
}

// HandleFunc registers the handler function for the given method.
func (mux *ServeMux) HandleFunc(method string, handler func(ResponseWriter, *Request)) {
	mux.Handle(method, HandlerFunc(handler))
}

// Handle registers the handler for the given method 
// in the DefaultServeMux.
func Handle(method string, handler Handler) { DefaultServeMux.Handle(method, handler) }

// HandleFunc registers the handler function for the given method 
// in the DefaultServeMux.
func HandleFunc(method string, handler func(ResponseWriter, *Request)) {
	DefaultServeMux.HandleFunc(method, handler)
}

// Serve accepts incoming RTSP connections on the listener l,
// creating a new service thread for each.  The service threads
// read requests and then call handler to reply to them.
// Handler is typically nil, in which case the DefaultServeMux is used.
func Serve(l net.Listener, handler Handler) error {
	srv := &Server{Handler: handler}
	return srv.Serve(l)
}

// A Server defines parameters for running an RTSP server.
type Server struct {
	Addr           string        // TCP address to listen on, ":http" if empty
	Handler        Handler       // handler to invoke, http.DefaultServeMux if nil
	ReadTimeout    time.Duration // maximum duration before timing out read of the request
	WriteTimeout   time.Duration // maximum duration before timing out write of the response
	MaxHeaderBytes int           // maximum size of request headers, DefaultMaxHeaderBytes if 0
}

// ListenAndServe listens on the TCP network address srv.Addr and then
// calls Serve to handle requests on incoming connections.  If
// srv.Addr is blank, ":http" is used.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":http"
	}
	l, e := net.Listen("tcp", addr)
	if e != nil {
		return e
	}
	return srv.Serve(l)
}

// Serve accepts incoming connections on the Listener l, creating a
// new service thread for each.  The service threads read requests and
// then call srv.Handler to reply to them.
func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		rw, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("rtsp: Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0
		if srv.ReadTimeout != 0 {
			rw.SetReadDeadline(time.Now().Add(srv.ReadTimeout))
		}
		if srv.WriteTimeout != 0 {
			rw.SetWriteDeadline(time.Now().Add(srv.WriteTimeout))
		}
		c, err := srv.newConn(rw)
		if err != nil {
			continue
		}
		go c.serve()
	}
	panic("not reached")
}

// ListenAndServe listens on the TCP network address addr
// and then calls Serve with handler to handle requests
// on incoming connections.  Handler is typically nil,
// in which case the DefaultServeMux is used.
//
// A trivial example server is:
//
//	package main
//
//	import (
//		"io"
//		"rtsp"
//		"log"
//	)
//
//	func OptionsHandler(w rtsp.ResponseWriter, req *rtsp.Request) {
//		...
//	}
//
//	func main() {
//		http.HandleFunc("OPTIONS", OptionsHandler)
//		err := rtsp.ListenAndServe(":12345", nil)
//		if err != nil {
//			log.Fatal("ListenAndServe: ", err)
//		}
//	}
func ListenAndServe(addr string, handler Handler) error {
	server := &Server{Addr: addr, Handler: handler}
	return server.ListenAndServe()
}

// TimeoutHandler returns a Handler that runs h with the given time limit.
//
// The new Handler calls h.ServeRTSP to handle each request, but if a
// call runs for more than ns nanoseconds, the handler responds with
// a 503 Service Unavailable error and the given message in its body.
// (If msg is empty, a suitable default message will be sent.)
// After such a timeout, writes by h to its ResponseWriter will return
// ErrHandlerTimeout.
func TimeoutHandler(h Handler, dt time.Duration, msg string) Handler {
	f := func() <-chan time.Time {
		return time.After(dt)
	}
	return &timeoutHandler{h, f, msg}
}

// ErrHandlerTimeout is returned on ResponseWriter Write calls
// in handlers which have timed out.
var ErrHandlerTimeout = errors.New("rtsp: Handler timeout")

type timeoutHandler struct {
	handler Handler
	timeout func() <-chan time.Time // returns channel producing a timeout
	body    string
}

func (h *timeoutHandler) ServeRTSP(w ResponseWriter, r *Request) {
	done := make(chan bool)
	tw := &timeoutWriter{w: w}
	go func() {
		h.handler.ServeHTTP(tw, r)
		done <- true
	}()
	select {
	case <-done:
		return
	case <-h.timeout():
		tw.mu.Lock()
		defer tw.mu.Unlock()
		if !tw.wroteHeader {
			tw.w.WriteHeader(StatusServiceUnavailable)
		}
		tw.timedOut = true
	}
}

type timeoutWriter struct {
	w ResponseWriter

	mu          sync.Mutex
	timedOut    bool
	wroteHeader bool
}

func (tw *timeoutWriter) Header() Header {
	return tw.w.Header()
}

func (tw *timeoutWriter) Write(p []byte) (int, error) {
	tw.mu.Lock()
	timedOut := tw.timedOut
	tw.mu.Unlock()
	if timedOut {
		return 0, ErrHandlerTimeout
	}
	return tw.w.Write(p)
}

func (tw *timeoutWriter) WriteHeader(code int) {
	tw.mu.Lock()
	if tw.timedOut || tw.wroteHeader {
		tw.mu.Unlock()
		return
	}
	tw.wroteHeader = true
	tw.mu.Unlock()
	tw.w.WriteHeader(code)
}
