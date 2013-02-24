// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// RTSP Request reading and parsing.

package rtsp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strings"
)

const (
	maxValueLength   = 4096
	maxHeaderLines   = 1024
	chunkSize        = 4 << 10  // 4 KB chunks
	defaultMaxMemory = 32 << 20 // 32 MB
)

// ErrMissingFile is returned by FormFile when the provided file field name
// is either not present in the request or not a file field.
var ErrMissingFile = errors.New("http: no such file")

// RTSP request parsing errors.
type ProtocolError struct {
	ErrorString string
}

func (err *ProtocolError) Error() string { return err.ErrorString }

var (
	ErrHeaderTooLong        = &ProtocolError{"header too long"}
	ErrShortBody            = &ProtocolError{"entity body too short"}
	ErrNotSupported         = &ProtocolError{"feature not supported"}
	ErrUnexpectedTrailer    = &ProtocolError{"trailer header without chunked transfer encoding"}
	ErrMissingContentLength = &ProtocolError{"missing ContentLength in HEAD response"}
	ErrNotMultipart         = &ProtocolError{"request Content-Type isn't multipart/form-data"}
	ErrMissingBoundary      = &ProtocolError{"no multipart boundary param Content-Type"}
)

type badStringError struct {
	what string
	str  string
}

func (e *badStringError) Error() string { return fmt.Sprintf("%s %q", e.what, e.str) }

// Headers that Request.Write handles itself and should be skipped.
var reqWriteExcludeHeader = map[string]bool{
	"Host":              true, // not in Header map anyway
	"User-Agent":        true,
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"Trailer":           true,
}

// A Request represents an RTSP request received by a server
// or to be sent by a client.
type Request struct {
	Method string // DESCRIBE, SETUP, PLAY, etc.
	URL    *url.URL

	// The protocol version for incoming requests.
	// Outgoing requests always use RTSP/1.0.
	Proto      string // "RTSP/1.0"
	ProtoMajor int    // 1
	ProtoMinor int    // 0

	// A header maps request lines to their values.
	// If the header says
	//
	//	accept-encoding: gzip, deflate
	//	Accept-Language: en-us
	//	Connection: keep-alive
	//
	// then
	//
	//	Header = map[string][]string{
	//		"Accept-Encoding": {"gzip, deflate"},
	//		"Accept-Language": {"en-us"},
	//		"Connection": {"keep-alive"},
	//	}
	//
	// RTSP defines that header names are case-insensitive.
	// The request parser implements this by canonicalizing the
	// name, making the first character and any characters
	// following a hyphen uppercase and the rest lowercase.
	Header Header

	// The message body.
	Body io.ReadCloser

	// ContentLength records the length of the associated content.
	// The value -1 indicates that the length is unknown.
	// Values >= 0 indicate that the given number of bytes may
	// be read from Body.
	// For outgoing requests, a value of 0 means unknown if Body is not nil.
	ContentLength int64

	// TransferEncoding lists the transfer encodings from outermost to
	// innermost. An empty list denotes the "identity" encoding.
	// TransferEncoding can usually be ignored; chunked encoding is
	// automatically added and removed as necessary when sending and
	// receiving requests.
	TransferEncoding []string

	// Close indicates whether to close the connection after
	// replying to this request.
	Close bool

	// The host on which the URL is sought.
	// Per RFC 2616, this is either the value of the Host: header
	// or the host name given in the URL itself.
	Host string

	// Form contains the parsed form data, including the URL
	// field's query parameters 
	Form url.Values

	// RemoteAddr allows RTSP servers and other software to record
	// the network address that sent the request, usually for
	// logging. This field is not filled in by ReadRequest and
	// has no defined format. The HTTP server in this package
	// sets RemoteAddr to an "IP:port" address before invoking a
	// handler.
	RemoteAddr string

	// RequestURI is the unmodified Request-URI of the
	// Request-Line (RFC 2616, Section 5.1) as sent by the client
	// to a server. Usually the URL field should be used instead.
	// It is an error to set this field in an RTSP client request.
	RequestURI string
}

// ProtoAtLeast returns whether the RTSP protocol used
// in the request is at least major.minor.
func (r *Request) ProtoAtLeast(major, minor int) bool {
	return r.ProtoMajor > major ||
		r.ProtoMajor == major && r.ProtoMinor >= minor
}

// UserAgent returns the client's User-Agent, if sent in the request.
func (r *Request) UserAgent() string {
	return r.Header.Get("User-Agent")
}

// Referer returns the referring URL, if sent in the request.
//
// Referer is misspelled as in the request itself, a mistake from the
// earliest days of HTTP.  This value can also be fetched from the
// Header map as Header["Referer"]; the benefit of making it available
// as a method is that the compiler can diagnose programs that use the
// alternate (correct English) spelling req.Referrer() but cannot
// diagnose programs that use Header["Referrer"].
func (r *Request) Referer() string {
	return r.Header.Get("Referer")
}

// Return value if nonempty, def otherwise.
func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

const defaultUserAgent = "Go rtsp package"

// Write writes an RTSP/1.0 request -- header -- in wire format.
// This method consults the following fields of the request:
//	URL
//	Method (defaults to "SETUP")
//	Header
func (r *Request) Write(w io.Writer) error {
	return r.write(w, false, nil)
}

// extraHeaders may be nil
func (req *Request) write(w io.Writer, usingProxy bool, extraHeaders Header) error {
	host := req.Host
	if host == "" {
		if req.URL == nil {
			return errors.New("http: Request.Write on Request with no Host or URL set")
		}
		host = req.URL.Host
	}

	ruri := req.URL.RequestURI()
	if usingProxy && req.URL.Scheme != "" && req.URL.Opaque == "" {
		ruri = req.URL.Scheme + "://" + host + ruri
	} else if req.Method == "CONNECT" && req.URL.Path == "" {
		// CONNECT requests normally give just the host and port, not a full URL.
		ruri = host
	}
	// TODO(bradfitz): escape at least newlines in ruri?

	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "%s %s HTTP/1.1\r\n", valueOrDefault(req.Method, "GET"), ruri)

	// Header lines
	fmt.Fprintf(bw, "Host: %s\r\n", host)

	// Use the defaultUserAgent unless the Header contains one, which
	// may be blank to not send the header.
	userAgent := defaultUserAgent
	if req.Header != nil {
		if ua := req.Header["User-Agent"]; len(ua) > 0 {
			userAgent = ua[0]
		}
	}
	if userAgent != "" {
		fmt.Fprintf(bw, "User-Agent: %s\r\n", userAgent)
	}

	// Process Body,ContentLength,Close,Trailer
	tw, err := newTransferWriter(req)
	if err != nil {
		return err
	}
	err = tw.WriteHeader(bw)
	if err != nil {
		return err
	}

	// TODO: split long values?  (If so, should share code with Conn.Write)
	err = req.Header.WriteSubset(bw, reqWriteExcludeHeader)
	if err != nil {
		return err
	}

	if extraHeaders != nil {
		err = extraHeaders.Write(bw)
		if err != nil {
			return err
		}
	}

	io.WriteString(bw, "\r\n")

	// Write body and trailer
	err = tw.WriteBody(bw)
	if err != nil {
		return err
	}

	return bw.Flush()
}

// Convert decimal at s[i:len(s)] to integer,
// returning value, string position where the digits stopped,
// and whether there was a valid number (digits, not too big).
func atoi(s string, i int) (n, i1 int, ok bool) {
	const Big = 1000000
	if i >= len(s) || s[i] < '0' || s[i] > '9' {
		return 0, 0, false
	}
	n = 0
	for ; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n > Big {
			return 0, 0, false
		}
	}
	return n, i, true
}

// ParseRTSPVersion parses a RTSP version string.
// "RTSP/1.0" returns (1, 0, true).
func ParseHTTPVersion(vers string) (major, minor int, ok bool) {
	if len(vers) < 5 || vers[0:5] != "RTSP/" {
		return 0, 0, false
	}
	major, i, ok := atoi(vers, 5)
	if !ok || i >= len(vers) || vers[i] != '.' {
		return 0, 0, false
	}
	minor, i, ok = atoi(vers, i+1)
	if !ok || i != len(vers) {
		return 0, 0, false
	}
	return major, minor, true
}

// ReadRequest reads and parses a request from b.
func ReadRequest(b *bufio.Reader) (req *Request, err error) {

	tp := textproto.NewReader(b)
	req = new(Request)

	// First line: SETUP /index.html RTSP/1.0
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return nil, err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	var f []string
	if f = strings.SplitN(s, " ", 3); len(f) < 3 {
		return nil, &badStringError{"malformed HTTP request", s}
	}
	req.Method, req.RequestURI, req.Proto = f[0], f[1], f[2]
	rawurl := req.RequestURI
	var ok bool
	if req.ProtoMajor, req.ProtoMinor, ok = ParseRTSPVersion(req.Proto); !ok {
		return nil, &badStringError{"malformed RTSP version", req.Proto}
	}

	if req.URL, err = url.ParseRequestURI(rawurl); err != nil {
		return nil, err
	}

	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	req.Header = Header(mimeHeader)

	// RFC2326: Must treat
	//	SETUP rtsp://www.google.com/audio RTSP/1.0
	req.Host = req.URL.Host

	fixPragmaCacheControl(req.Header)

	// TODO: Parse specific header values:
	//	Accept
	//	Accept-Encoding
	//	Accept-Language
	//	Authorization
	//	Cache-Control
	//	Connection
	//	Date
	//	Expect
	//	From
	//	If-Match
	//	If-Modified-Since
	//	If-None-Match
	//	If-Range
	//	If-Unmodified-Since
	//	Max-Forwards
	//	Proxy-Authorization
	//	Referer [sic]
	//	TE (transfer-codings)
	//	Trailer
	//	Transfer-Encoding
	//	Upgrade
	//	User-Agent
	//	Via
	//	Warning

	err = readTransfer(req, b)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// MaxBytesReader is similar to io.LimitReader but is intended for
// limiting the size of incoming request bodies. In contrast to
// io.LimitReader, MaxBytesReader's result is a ReadCloser, returns a
// non-EOF error for a Read beyond the limit, and Closes the
// underlying reader when its Close method is called.
//
// MaxBytesReader prevents clients from accidentally or maliciously
// sending a large request and wasting server resources.
func MaxBytesReader(w ResponseWriter, r io.ReadCloser, n int64) io.ReadCloser {
	return &maxBytesReader{w: w, r: r, n: n}
}

type maxBytesReader struct {
	w       ResponseWriter
	r       io.ReadCloser // underlying reader
	n       int64         // max bytes remaining
	stopped bool
}

func (l *maxBytesReader) Read(p []byte) (n int, err error) {
	if l.n <= 0 {
		if !l.stopped {
			l.stopped = true
			if res, ok := l.w.(*response); ok {
				res.requestTooLarge()
			}
		}
		return 0, errors.New("http: request body too large")
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err = l.r.Read(p)
	l.n -= int64(n)
	return
}

func (l *maxBytesReader) Close() error {
	return l.r.Close()
}

// ParseForm parses the raw query from the URL.
//
// For POST or PUT requests, it also parses the request body as a form.
// If the request Body's size has not already been limited by MaxBytesReader,
// the size is capped at 10MB.
//
// ParseMultipartForm calls ParseForm automatically.
// It is idempotent.
func (r *Request) ParseForm() (err error) {
	if r.Form != nil {
		return
	}
	if r.URL != nil {
		r.Form, err = url.ParseQuery(r.URL.RawQuery)
	}
	if r.Method == "POST" || r.Method == "PUT" {
		if r.Body == nil {
			return errors.New("missing form body")
		}
		ct := r.Header.Get("Content-Type")
		ct, _, err = mime.ParseMediaType(ct)
		switch {
		case ct == "application/x-www-form-urlencoded":
			var reader io.Reader = r.Body
			maxFormSize := int64(1<<63 - 1)
			if _, ok := r.Body.(*maxBytesReader); !ok {
				maxFormSize = int64(10 << 20) // 10 MB is a lot of text.
				reader = io.LimitReader(r.Body, maxFormSize+1)
			}
			b, e := ioutil.ReadAll(reader)
			if e != nil {
				if err == nil {
					err = e
				}
				break
			}
			if int64(len(b)) > maxFormSize {
				return errors.New("http: POST too large")
			}
			var newValues url.Values
			newValues, e = url.ParseQuery(string(b))
			if err == nil {
				err = e
			}
			if r.Form == nil {
				r.Form = make(url.Values)
			}
			// Copy values into r.Form. TODO: make this smoother.
			for k, vs := range newValues {
				for _, value := range vs {
					r.Form.Add(k, value)
				}
			}
		case ct == "multipart/form-data":
			// handled by ParseMultipartForm (which is calling us, or should be)
			// TODO(bradfitz): there are too many possible
			// orders to call too many functions here.
			// Clean this up and write more tests.
			// request_test.go contains the start of this,
			// in TestRequestMultipartCallOrder.
		}
	}
	return err
}

// ParseMultipartForm parses a request body as multipart/form-data.
// The whole request body is parsed and up to a total of maxMemory bytes of
// its file parts are stored in memory, with the remainder stored on
// disk in temporary files.
// ParseMultipartForm calls ParseForm if necessary.
// After one call to ParseMultipartForm, subsequent calls have no effect.
func (r *Request) ParseMultipartForm(maxMemory int64) error {
	if r.MultipartForm == multipartByReader {
		return errors.New("http: multipart handled by MultipartReader")
	}
	if r.Form == nil {
		err := r.ParseForm()
		if err != nil {
			return err
		}
	}
	if r.MultipartForm != nil {
		return nil
	}

	mr, err := r.multipartReader()
	if err == ErrNotMultipart {
		return nil
	} else if err != nil {
		return err
	}

	f, err := mr.ReadForm(maxMemory)
	if err != nil {
		return err
	}
	for k, v := range f.Value {
		r.Form[k] = append(r.Form[k], v...)
	}
	r.MultipartForm = f

	return nil
}

// FormValue returns the first value for the named component of the query.
// FormValue calls ParseMultipartForm and ParseForm if necessary.
func (r *Request) FormValue(key string) string {
	if r.Form == nil {
		r.ParseMultipartForm(defaultMaxMemory)
	}
	if vs := r.Form[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// FormFile returns the first file for the provided form key.
// FormFile calls ParseMultipartForm and ParseForm if necessary.
func (r *Request) FormFile(key string) (multipart.File, *multipart.FileHeader, error) {
	if r.MultipartForm == multipartByReader {
		return nil, nil, errors.New("http: multipart handled by MultipartReader")
	}
	if r.MultipartForm == nil {
		err := r.ParseMultipartForm(defaultMaxMemory)
		if err != nil {
			return nil, nil, err
		}
	}
	if r.MultipartForm != nil && r.MultipartForm.File != nil {
		if fhs := r.MultipartForm.File[key]; len(fhs) > 0 {
			f, err := fhs[0].Open()
			return f, fhs[0], err
		}
	}
	return nil, nil, ErrMissingFile
}

func (r *Request) expectsContinue() bool {
	return strings.ToLower(r.Header.Get("Expect")) == "100-continue"
}

func (r *Request) wantsHttp10KeepAlive() bool {
	if r.ProtoMajor != 1 || r.ProtoMinor != 0 {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "keep-alive")
}
