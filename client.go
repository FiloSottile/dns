package dns

// A concurrent client implementation. 

import (
	"io"
	"net"
	"time"
)

type QueryHandler interface {
	QueryDNS(w RequestWriter, q *Msg)
}

// The RequestWriter interface is used by a DNS query handler to
// construct a DNS request.
type RequestWriter interface {
	// RemoteAddr returns the net.Addr of the server
	RemoteAddr() net.Addr
	// TsigStatus returns the TSIG validation status.
	TsigStatus() error
	// Write returns the request message and the reply back to the client (i.e. your Go code).
	Write(*Msg) error
	// Send sends the message to the server.
	Send(*Msg) error
	// Receive waits for the reply of the servers. 
	Receive() (*Msg, error)
	// Close closes the connection with the server.
	Close() error
	// Dials calls the server.
	Dial() error
}

// hijacked connections...?
type reply struct {
	client         *Client
	addr           string
	req            *Msg
	conn           net.Conn
	tsigRequestMAC string
	tsigTimersOnly bool
	tsigStatus     error
	rtt            time.Duration
	t              time.Time
}

// A Request is a incoming message from a Client.
type Request struct {
	Request *Msg
	Addr    string
	Client  *Client
}

// QueryMux is an DNS request multiplexer. It matches the
// zone name of each incoming request against a list of 
// registered patterns add calls the handler for the pattern
// that most closely matches the zone name.
type QueryMux struct {
	m map[string]QueryHandler
}

// NewQueryMux allocates and returns a new QueryMux.
func NewQueryMux() *QueryMux { return &QueryMux{make(map[string]QueryHandler)} }

// DefaultQueryMux is the default QueryMux used by Query.
var DefaultQueryMux = NewQueryMux()

func newQueryChanSlice() chan *Exchange { return make(chan *Exchange) }
func newQueryChan() chan *Request       { return make(chan *Request) }

// Default channels to use for the resolver
var (
	// QueryReply is the channel on which the replies are
	// coming back. Is it a channel of *Exchange. The original 
	// question is included with the answer.
	QueryReply = newQueryChanSlice()
	// QueryRequest is the channel were you can send the questions to.
	// It is a channel of *Request
	QueryRequest = newQueryChan()
)

// The HandlerQueryFunc type is an adapter to allow the use of
// ordinary functions as DNS query handlers.  If f is a function
// with the appropriate signature, HandlerQueryFunc(f) is a
// QueryHandler object that calls f.
type HandlerQueryFunc func(RequestWriter, *Msg)

// QueryDNS calls f(w, reg).
func (f HandlerQueryFunc) QueryDNS(w RequestWriter, r *Msg) {
	go f(w, r)
}

// HandleQueryFunc registers the handler with the given pattern in the
// DefaultQueryMux. See HandleQuery for an example.
func HandleQueryFunc(pattern string, handler func(RequestWriter, *Msg)) {
	DefaultQueryMux.HandleFunc(pattern, handler)
}

// HandleQuery registers the handler in the DefaultQueryMux. The pattern is
// the name of a zone, or "." which can be used as a catch-all. Basic use pattern
// (sans error checking) for setting up a query handler:
//
//	func myhandler(w dns.RequestWriter, m *dns.Msg) {
//		w.Send(m)		// send the message m to server specified in the Do() call
//		r, _ := w.Receive()	// wait for a response
//		w.Close()		// close connection with the server
//		w.Write(r)		// write the received answer back to the client
//	}
// 
//	func main() {
//		dns.HandleQuery(".", myhandler)
//		dns.ListenAndQuery(nil)
//		m := new(dns.Msg)
//		c := new(dns.Client)
//		m.SetQuestion("miek.nl.", TypeMX)
//		c.Do(m, "127.0.0.1:53")
//		// ...
//		r := <- c.Reply  // or <- dns.QueryReply, when using the defaults
//	}
func HandleQuery(pattern string, handler HandlerQueryFunc) {
	DefaultQueryMux.Handle(pattern, handler)
}

// HandleQueryRemove deregisters the handle with the given pattern                                                                          
// in the DefaultQueryMux.                                   
func HandleQueryRemove(pattern string) {
	DefaultQueryMux.HandleRemove(pattern)
}

// reusing zoneMatch from server.go
func (mux *QueryMux) match(zone string) QueryHandler {
	var h QueryHandler
	var n = 0
	for k, v := range mux.m {
		if !zoneMatch(k, zone) {
			continue
		}
		if h == nil || len(k) > n {
			n = len(k)
			h = v
		}
	}
	return h
}

func (mux *QueryMux) Handle(pattern string, handler QueryHandler) {
	if pattern == "" {
		panic("dns: invalid pattern " + pattern)
	}
	// check is domainname TODO(mg)
	mux.m[pattern] = handler
}

// HandleRemove deregisters the handler with given pattern.
func (mux *QueryMux) HandleRemove(pattern string) {
	delete(mux.m, pattern)
}

// HandleFunc ...
func (mux *QueryMux) HandleFunc(pattern string, handler func(RequestWriter, *Msg)) {
	mux.Handle(pattern, HandlerQueryFunc(handler))
}

func (mux *QueryMux) QueryDNS(w RequestWriter, r *Msg) {
	h := mux.match(r.Question[0].Name)
	if h == nil {
		panic("dns: no handler found for " + r.Question[0].Name)
	}
	h.QueryDNS(w, r)
}

// A nil Client is usable.
type Client struct {
	Net          string            // if "tcp" a TCP query will be initiated, otherwise an UDP one (default is "", is UDP)
	Attempts     int               // number of attempts, if not set defaults to 1
	Retry        bool              // retry with TCP
	Request      chan *Request     // read DNS request from this channel
	Reply        chan *Exchange    // write replies to this channel
	ReadTimeout  time.Duration     // the net.Conn.SetReadTimeout value for new connections (ns), defauls to 2 * 1e9
	WriteTimeout time.Duration     // the net.Conn.SetWriteTimeout value for new connections (ns), defauls to 2 * 1e9
	TsigSecret   map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>
	Hijacked     net.Conn          // if set the calling code takes care of the connection
	// LocalAddr string            // Local address to use
}

type Query struct {
	Request chan *Request // read DNS request from this channel
	Handler QueryHandler  // handler to invoke, dns.DefaultQueryMux if nil
}

func (q *Query) Query() error {
	handler := q.Handler
	if handler == nil {
		handler = DefaultQueryMux
	}
	for {
		select {
		case in := <-q.Request:
			w := new(reply)
			w.req = in.Request
			w.addr = in.Addr
			w.client = in.Client
			handler.QueryDNS(w, in.Request)
		}
	}
	return nil
}

func (q *Query) ListenAndQuery() error {
	if q.Request == nil {
		q.Request = QueryRequest
	}
	return q.Query()
}

// ListenAndQuery starts the listener for firing off the queries.
// If handler is nil DefaultQueryMux is used. The default request
// channel (QueryRequest) is used for requesting queries.
func ListenAndQuery(handler QueryHandler) {
	q := &Query{Request: nil, Handler: handler}
	go q.ListenAndQuery()
}

// ListenAndQueryRequest starts the listener for firing off queries. If
// request is nil QueryRequest is used. If handler is nil DefaultQueryMux is used.
func ListenAndQueryRequest(request chan *Request, handler QueryHandler) {
	q := &Query{Request: request, Handler: handler}
	go q.ListenAndQuery()
}

// Write returns the original question and the answer on the 
// reply channel of the client.
func (w *reply) Write(m *Msg) error {
	// What to do if the channels here are nil?
	// Do() sets them if empty - but not everything goes through Do()
	if w.conn == nil {
		w.Client().Reply <- &Exchange{Request: w.req, Reply: m, Rtt: w.rtt}
	} else {
		w.Client().Reply <- &Exchange{Request: w.req, Reply: m, Rtt: w.rtt, RemoteAddr: w.conn.RemoteAddr()}
	}
	return nil
}

func (w *reply) RemoteAddr() net.Addr {
	if w.conn == nil {
		return nil
	} else {
		return w.conn.RemoteAddr()
	}
	return nil
}

// Do performs an asynchronous query. The result is returned on the
// channel c.Reply. Basic use pattern for
// sending message m to the server listening on port 53 on localhost
//
//	   c.Do(m, "127.0.0.1:53")
//	   r := <- c.Reply
// 
// r is of type *Exchange.
func (c *Client) Do(m *Msg, a string) {
	if c.Request == nil {
		c.Request = QueryRequest
	}
	if c.Reply == nil {
		c.Reply = QueryReply
	}
	c.Request <- &Request{Client: c, Addr: a, Request: m}
}

// exchangeBuffer performs a synchronous query. It sends the buffer m to the
// address contained in a.
func (c *Client) exchangeBuffer(inbuf []byte, a string, outbuf []byte) (n int, w *reply, err error) {
	w = new(reply)
	w.client = c
	w.addr = a
	if c.Hijacked == nil {
		if err = w.Dial(); err != nil {
			return 0, w, err
		}
		defer w.Close()
	}
	if c.Hijacked != nil {
		w.conn = c.Hijacked
	}
	w.t = time.Now()
	if n, err = w.writeClient(inbuf); err != nil {
		return 0, w, err
	}
	if n, err = w.readClient(outbuf); err != nil {
		return n, w, err
	}
	w.rtt = time.Since(w.t)
	return n, w, nil
}

// Exchange performs an synchronous query. It sends the message m to the address
// contained in a and waits for an reply. Basic use pattern with a *Client:
//
//	c := new(dns.Client)
//	in, err := c.Exchange(message, "127.0.0.1:53")
//
// See Client.ExchangeRtt(...) to get the round trip time.
func (c *Client) Exchange(m *Msg, a string) (r *Msg, err error) {
	r, _, _, err = c.ExchangeRtt(m, a)
	return
}

// ExchangeRtt performs an synchronous query. It sends the message m to the address
// contained in a and waits for an reply. Basic use pattern with a *Client:
//
//	c := new(dns.Client)
//	in, rtt, addr, err := c.ExchangeRtt(message, "127.0.0.1:53")
// 
// The 'addr' return value is superfluous in this case, but it is here to retain symmetry
// with the asynchronous call, see Client.Do().
func (c *Client) ExchangeRtt(m *Msg, a string) (r *Msg, rtt time.Duration, addr net.Addr, err error) {
	var n int
	var w *reply
	out, ok := m.Pack(nil)
	if !ok {
		return nil, 0, nil, ErrPack
	}
	var in []byte
	switch c.Net {
	case "tcp", "tcp4", "tcp6":
		in = make([]byte, MaxMsgSize)
	case "", "udp", "udp4", "udp6":
		size := UDPMsgSize
		for _, r := range m.Extra {
			if r.Header().Rrtype == TypeOPT {
				size = int(r.(*RR_OPT).UDPSize())
			}
		}
		in = make([]byte, size)
	}
	if n, w, err = c.exchangeBuffer(out, a, in); err != nil {
		if w.conn != nil {
			return nil, 0, w.conn.RemoteAddr(), err
		}
		return nil, 0, nil, err
	}
	r = new(Msg)
	r.Size = n
	if ok := r.Unpack(in[:n]); !ok {
		return nil, w.rtt, w.conn.RemoteAddr(), ErrUnpack
	}
	return r, w.rtt, w.conn.RemoteAddr(), nil
}

// Dial connects to the address addr for the network set in c.Net
func (w *reply) Dial() (err error) {
	var conn net.Conn
	if w.Client().Net == "" {
		conn, err = net.Dial("udp", w.addr)
	} else {
		conn, err = net.Dial(w.Client().Net, w.addr)
	}
	if err != nil {
		return
	}
	w.conn = conn
	return nil
}

func (w *reply) Receive() (*Msg, error) {
	var p []byte
	m := new(Msg)
	switch w.Client().Net {
	case "tcp", "tcp4", "tcp6":
		p = make([]byte, MaxMsgSize)
	case "", "udp", "udp4", "udp6":
		p = make([]byte, DefaultMsgSize)
	}
	n, err := w.readClient(p)
	if err != nil || n == 0 {
		return nil, err
	}
	p = p[:n]
	if ok := m.Unpack(p); !ok {
		return nil, ErrUnpack
	}
	w.rtt = time.Since(w.t)
	m.Size = n
	if m.IsTsig() {
		secret := m.Extra[len(m.Extra)-1].(*RR_TSIG).Hdr.Name
		if _, ok := w.Client().TsigSecret[secret]; !ok {
			w.tsigStatus = ErrSecret
			return m, nil
		}
		// Need to work on the original message p, as that was used to calculate the tsig.
		w.tsigStatus = TsigVerify(p, w.Client().TsigSecret[secret], w.tsigRequestMAC, w.tsigTimersOnly)
	}
	return m, nil
}

func (w *reply) readClient(p []byte) (n int, err error) {
	if w.conn == nil {
		return 0, ErrConnEmpty
	}
	if len(p) < 1 {
		return 0, io.ErrShortBuffer
	}
	attempts := w.Client().Attempts
	if attempts == 0 {
		attempts = 1
	}
	switch w.Client().Net {
	case "tcp", "tcp4", "tcp6":
		setTimeouts(w)
		for a := 0; a < attempts; a++ {
			n, err = w.conn.(*net.TCPConn).Read(p[0:2])
			if err != nil || n != 2 {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			l, _ := unpackUint16(p[0:2], 0)
			if l == 0 {
				return 0, ErrShortRead
			}
			if int(l) > len(p) {
				return int(l), io.ErrShortBuffer
			}
			n, err = w.conn.(*net.TCPConn).Read(p[:l])
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			i := n
			for i < int(l) {
				j, err := w.conn.(*net.TCPConn).Read(p[i:int(l)])
				if err != nil {
					if e, ok := err.(net.Error); ok && e.Timeout() {
						// We are half way in our read...
						continue
					}
					return i, err
				}
				i += j
			}
			n = i
		}
	case "", "udp", "udp4", "udp6":
		for a := 0; a < attempts; a++ {
			setTimeouts(w)
			n, _, err = w.conn.(*net.UDPConn).ReadFromUDP(p)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
		}
	}
	return
}

// Send sends a dns msg to the address specified in w.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (w *reply) Send(m *Msg) (err error) {
	var out []byte
	if m.IsTsig() {
		mac := ""
		name := m.Extra[len(m.Extra)-1].(*RR_TSIG).Hdr.Name
		if _, ok := w.Client().TsigSecret[name]; !ok {
			return ErrSecret
		}
		out, mac, err = TsigGenerate(m, w.Client().TsigSecret[name], w.tsigRequestMAC, w.tsigTimersOnly)
		if err != nil {
			return err
		}
		w.tsigRequestMAC = mac
	} else {
		ok := false
		out, ok = m.Pack(nil)
		if !ok {
			return ErrPack
		}
	}
	w.t = time.Now()
	if _, err = w.writeClient(out); err != nil {
		return err
	}
	return nil
}

func (w *reply) writeClient(p []byte) (n int, err error) {
	attempts := w.Client().Attempts
	if attempts == 0 {
		attempts = 1
	}
	if w.Client().Hijacked == nil {
		if err = w.Dial(); err != nil {
			return 0, err
		}
	}
	switch w.Client().Net {
	case "tcp", "tcp4", "tcp6":
		if len(p) < 2 {
			return 0, io.ErrShortBuffer
		}
		for a := 0; a < attempts; a++ {
			setTimeouts(w)
			a, b := packUint16(uint16(len(p)))
			n, err = w.conn.Write([]byte{a, b})
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			if n != 2 {
				return n, io.ErrShortWrite
			}
			n, err = w.conn.Write(p)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
			i := n
			if i < len(p) {
				j, err := w.conn.Write(p[i:len(p)])
				if err != nil {
					if e, ok := err.(net.Error); ok && e.Timeout() {
						// We are half way in our write...
						continue
					}
					return i, err
				}
				i += j
			}
			n = i
		}
	case "", "udp", "udp4", "udp6":
		for a := 0; a < attempts; a++ {
			setTimeouts(w)
			n, err = w.conn.(*net.UDPConn).Write(p)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				return n, err
			}
		}
	}
	return
}

func setTimeouts(w *reply) {
	if w.Client().ReadTimeout == 0 {
		w.conn.SetReadDeadline(time.Now().Add(2 * 1e9))
	} else {
		w.conn.SetReadDeadline(time.Now().Add(w.Client().ReadTimeout))
	}

	if w.Client().WriteTimeout == 0 {
		w.conn.SetWriteDeadline(time.Now().Add(2 * 1e9))
	} else {
		w.conn.SetWriteDeadline(time.Now().Add(w.Client().WriteTimeout))
	}
}

// Close implents the RequestWriter.Close method
func (w *reply) Close() (err error) { return w.conn.Close() }

// Client returns a pointer to the client
func (w *reply) Client() *Client { return w.client }

// Request returns the request contained in reply
func (w *reply) Request() *Msg { return w.req }

// TsigStatus implements the RequestWriter.TsigStatus method
func (w *reply) TsigStatus() error { return w.tsigStatus }
