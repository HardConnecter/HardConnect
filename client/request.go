package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/log"
	utls "github.com/refraction-networking/utls"
)

var errSMSRequired = errors.New("SMS code required")

func (c *EasyConnectClient) requestTwfID() error {
	err := c.loginAuthAndPsw()
	if err != nil {
		if errors.Is(err, errSMSRequired) {
			err = c.loginSMS()
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

func (c *EasyConnectClient) loginAuthAndPsw() error {
	// First we request the TwfID from server
	addr := "https://" + c.server + "/por/login_auth.csp?apiversion=1"
	log.Printf("Request: %s", addr)

	resp, err := c.httpClient.Get(addr)
	if err != nil {
		debug.PrintStack()
		return err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return err
	}

	c.twfID = string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf.Bytes())[1])
	log.Printf("TWFID: %s", c.twfID)

	// Now we need to do authentication
	rndImg := string(regexp.MustCompile(`<RndImg>(.*)</RndImg>`).FindSubmatch(buf.Bytes())[1])
	if rndImg == "1" {
		log.Print("Due to too many login failures, the server has activated risk control for this IP")
		log.Print("Continuing to log in may cause this IP to be banned. The program has stopped the login process")
		log.Print("You can wait a minute and try again")

		return errors.New("too many login failures")
	}

	rsaKey := string(regexp.MustCompile(`<RSA_ENCRYPT_KEY>(.*)</RSA_ENCRYPT_KEY>`).FindSubmatch(buf.Bytes())[1])
	log.Printf("RSA key: %s", rsaKey)

	rsaExpMatch := regexp.MustCompile(`<RSA_ENCRYPT_EXP>(.*)</RSA_ENCRYPT_EXP>`).FindSubmatch(buf.Bytes())
	rsaExp := ""
	if rsaExpMatch != nil {
		rsaExp = string(rsaExpMatch[1])
	} else {
		log.Printf("Warning: No RSA_ENCRYPT_EXP, using default")
		rsaExp = "65537"
	}
	log.Printf("RSA exp: %s", rsaExp)

	csrfMatch := regexp.MustCompile(`<CSRF_RAND_CODE>(.*)</CSRF_RAND_CODE>`).FindSubmatch(buf.Bytes())
	csrfCode := ""
	password := c.password
	if csrfMatch != nil {
		csrfCode = string(csrfMatch[1])
		log.Printf("CSRF Code: %s", csrfCode)
		password += "_" + csrfCode
	} else {
		log.Printf("Warning: No CSRF rand code")
	}

	pubKey := rsa.PublicKey{}
	pubKey.E, _ = strconv.Atoi(rsaExp)
	modulus := big.Int{}
	modulus.SetString(rsaKey, 16)
	pubKey.N = &modulus

	encryptedPassword, err := rsa.EncryptPKCS1v15(rand.Reader, &pubKey, []byte(password))
	if err != nil {
		return err
	}
	encryptedPasswordHex := hex.EncodeToString(encryptedPassword)

	addr = "https://" + c.server + "/por/login_psw.csp?anti_replay=1&encrypt=1&apiversion=1"
	log.Printf("Request: %s", addr)

	form := url.Values{
		"svpn_rand_code":    {""},
		"mitm_result":       {""},
		"svpn_req_randcode": {csrfCode},
		"svpn_name":         {c.username},
		"svpn_password":     {encryptedPasswordHex},
	}

	req, err := http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+c.twfID)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0")
	req.Header.Set("Origin", "https://stuvpn.fudan.edu.cn")
	req.Header.Set("Referer", "https://stuvpn.fudan.edu.cn/portal/")

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return err
	}

	buf.Reset()
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if strings.Contains(buf.String(), "<NextService>auth/sms</NextService>") || strings.Contains(buf.String(), "<NextAuth>2</NextAuth>") {
		log.Print("SMS code required")

		return errSMSRequired
	}

	if strings.Contains(buf.String(), "<NextAuth>-1</NextAuth>") || !strings.Contains(buf.String(), "<NextAuth>") {
		log.Print("No NextAuth found")
	} else {
		return errors.New("Not implemented auth: " + buf.String())
	}

	if !strings.Contains(buf.String(), "<Result>1</Result>") {
		return errors.New("Login failed: " + buf.String())
	}

	twfIDMatch := regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf.Bytes())
	if twfIDMatch != nil {
		c.twfID = string(twfIDMatch[1])
		log.Printf("Update TWFID: %s", c.twfID)
	}

	log.Printf("TWFID has been authorized")

	return nil
}

func (c *EasyConnectClient) loginSMS() error {
	addr := "https://" + c.server + "/por/login_sms.csp?apiversion=1"
	log.Printf("SMS request: " + addr)
	req, err := http.NewRequest("POST", addr, nil)
	req.Header.Set("Cookie", "TWFID="+c.twfID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.Reset()
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if !strings.Contains(buf.String(), "验证码已发送到您的手机") && !strings.Contains(buf.String(), "<USER_PHONE>") {
		return errors.New("unexpected SMS response: " + buf.String())
	}

	log.Printf("SMS code is sent or still valid")

	fmt.Print("Please enter your SMS code:")
	smsCode := ""
	_, err = fmt.Scan(&smsCode)
	if err != nil {
		return err
	}

	addr = "https://" + c.server + "/por/login_sms1.csp?apiversion=1"
	log.Printf("SMS Request: " + addr)
	form := url.Values{
		"svpn_inputsms": {smsCode},
	}

	req, err = http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+c.twfID)

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return err
	}

	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if !strings.Contains(buf.String(), "Auth sms suc") {
		debug.PrintStack()
		return errors.New("SMS code verification failed: " + buf.String())
	}

	c.twfID = string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf.Bytes())[1])
	log.Print("SMS code verification success")

	return nil
}

func (c *EasyConnectClient) requestConfig() (string, error) {
	addr := "https://" + c.server + "/por/conf.csp"
	log.Printf("Request: %s", addr)

	req, err := http.NewRequest("GET", addr, nil)
	req.Header.Set("Cookie", "TWFID="+c.twfID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	return buf.String(), nil
}

func (c *EasyConnectClient) requestResources() (string, error) {
	addr := "https://" + c.server + "/por/rclist.csp"
	log.Printf("Request: %s", addr)

	req, err := http.NewRequest("GET", addr, nil)
	req.Header.Set("Cookie", "TWFID="+c.twfID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	return buf.String(), nil
}

func (c *EasyConnectClient) requestToken() error {
	dialConn, err := net.Dial("tcp", c.server)
	defer func(dialConn net.Conn) {
		_ = dialConn.Close()
	}(dialConn)
	conn := utls.UClient(dialConn, &utls.Config{InsecureSkipVerify: true}, utls.HelloGolang)
	defer func(conn *utls.UConn) {
		_ = conn.Close()
	}(conn)

	// When establish an HTTPS connection to server and send a valid request with TWFID to it
	// The **TLS ServerHello SessionId** is the first part of token
	log.Printf("ECAgent request: /por/conf.csp & /por/rclist.csp")
	_, err = io.WriteString(
		conn,
		"GET /por/conf.csp HTTP/1.1\r\nHost: "+c.server+
			"\r\nCookie: TWFID="+c.twfID+
			"\r\n\r\nGET /por/rclist.csp HTTP/1.1\r\nHost: "+c.server+
			"\r\nCookie: TWFID="+c.twfID+"\r\n\r\n",
	)
	if err != nil {
		return err
	}

	sessionID := hex.EncodeToString(conn.HandshakeState.ServerHello.SessionId)
	log.Printf("Server session ID: %s", sessionID)

	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if n == 0 || err != nil {
		return errors.New("ECAgent request invalid: error " + err.Error() + "\n" + string(buf[:]))
	}

	c.token = (*[48]byte)([]byte(sessionID[:31] + "\x00" + c.twfID))

	log.Printf("Token: %s", hex.EncodeToString(c.token[:]))

	return nil
}

func (c *EasyConnectClient) requestIP() error {
	conn, err := c.tlsConn()
	if err != nil {
		return err
	}

	// Request IP Packet
	message := []byte{0x00, 0x00, 0x00, 0x00}
	message = append(message, c.token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}...)

	n, err := conn.Write(message)
	if err != nil {
		return err
	}

	log.DebugPrintf("Request IP: wrote %d bytes", n)
	log.DebugDumpHex(message[:n])

	reply := make([]byte, 0x80)
	n, err = conn.Read(reply)
	if err != nil {
		return err
	}

	log.DebugPrintf("Request IP: read %d bytes", n)
	log.DebugDumpHex(reply[:n])

	if reply[0] != 0x00 {
		return errors.New("unexpected request IP reply")
	}

	c.ip = reply[4:8]
	c.ipReverse = []byte{c.ip[3], c.ip[2], c.ip[1], c.ip[0]}

	log.Printf("Client IP: %s", c.ip.String())

	// Request IP conn CAN NOT be closed, otherwise tx/rx handshake will fail
	go func() {
		for {
			time.Sleep(time.Second * 10)
			runtime.KeepAlive(conn)
		}
	}()

	return nil
}
