package logrus_mail

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	format = "20060102 15:04:05"
)

// MailHook to sends logs by email without authentication.
type MailHook struct {
	AppName string
	c       *smtp.Client
}

// MailAuthHook to sends logs by email with authentication.
type MailAuthHook struct {
	AppName  string
	Host     string
	Port     int
	From     *mail.Address
	To       *mail.Address
	Username string
	Password string
}

// MailAuthLoginHook to sends logs by email with authentication using AUTH LOGIN.
type MailAuthLoginHook struct {
	AppName  string
	Host     string
	Port     int
	From     *mail.Address
	To       *mail.Address
	Username string
	Password string
}

// NewMailHook creates a hook to be added to an instance of logger.
func NewMailHook(appname string, host string, port int, from string, to string) (*MailHook, error) {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(host + ":" + strconv.Itoa(port))
	if err != nil {
		return nil, err
	}

	// Validate sender and recipient
	sender, err := mail.ParseAddress(from)
	if err != nil {
		return nil, err
	}
	recipient, err := mail.ParseAddress(to)
	if err != nil {
		return nil, err
	}

	// Set the sender and recipient.
	if err := c.Mail(sender.Address); err != nil {
		return nil, err
	}
	if err := c.Rcpt(recipient.Address); err != nil {
		return nil, err
	}

	return &MailHook{
		AppName: appname,
		c:       c,
	}, nil

}

// NewMailAuthHook creates a hook to be added to an instance of logger.
func NewMailAuthHook(appname string, host string, port int, from string, to string, username string, password string) (*MailAuthHook, error) {
	// Check if server listens on that port.
	conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(port), 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Validate sender and recipient
	sender, err := mail.ParseAddress(from)
	if err != nil {
		return nil, err
	}
	receiver, err := mail.ParseAddress(to)
	if err != nil {
		return nil, err
	}

	return &MailAuthHook{
		AppName:  appname,
		Host:     host,
		Port:     port,
		From:     sender,
		To:       receiver,
		Username: username,
		Password: password}, nil
}

// NewMailAuthLoginHook creates a hook to be added to an instance of logger.
func NewMailAuthLoginHook(appname string, host string, port int, from string, to string, username string, password string) (*MailAuthLoginHook, error) {
	// Check if server listens on that port.
	conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(port), 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Validate sender and recipient
	sender, err := mail.ParseAddress(from)
	if err != nil {
		return nil, err
	}
	receiver, err := mail.ParseAddress(to)
	if err != nil {
		return nil, err
	}

	return &MailAuthLoginHook{
		AppName:  appname,
		Host:     host,
		Port:     port,
		From:     sender,
		To:       receiver,
		Username: username,
		Password: password}, nil
}

// Fire is called when a log event is fired.
func (hook *MailAuthLoginHook) Fire(entry *logrus.Entry) error {

	message := createMessage(entry, hook.AppName)

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	err := smtp.SendMail(
		hook.Host+":"+strconv.Itoa(hook.Port),
		LoginAuth(hook.Username, hook.Password),
		hook.From.Address,
		[]string{hook.To.Address},
		message.Bytes(),
	)
	if err != nil {
		return err
	}
	return nil
}

// Fire is called when a log event is fired.
func (hook *MailHook) Fire(entry *logrus.Entry) error {
	wc, err := hook.c.Data()
	if err != nil {
		return err
	}
	defer wc.Close()
	message := createMessage(entry, hook.AppName)
	if _, err = message.WriteTo(wc); err != nil {
		return err
	}
	return nil
}

// Fire is called when a log event is fired.
func (hook *MailAuthHook) Fire(entry *logrus.Entry) error {
	auth := smtp.PlainAuth("", hook.Username, hook.Password, hook.Host)

	message := createMessage(entry, hook.AppName)

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	err := smtp.SendMail(
		hook.Host+":"+strconv.Itoa(hook.Port),
		auth,
		hook.From.Address,
		[]string{hook.To.Address},
		message.Bytes(),
	)
	if err != nil {
		return err
	}
	return nil
}

// loginAuth contains a username and password for implementing authentication using AUTH LOGIN.
type loginAuth struct {
	username, password string
}

// LoginAuth returns an Auth that implements authentication using AUTH LOGIN.
func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

// Start implements the LOGIN step in AUTH LOGIN.
func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

// Next implements the NEXT step in AUTH LOGIN.
func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, errors.New("Unkown fromServer")
		}
	}
	return nil, nil
}

// Levels returns the available logging levels.
func (hook *MailAuthHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
	}
}

// Levels returns the available logging levels.
func (hook *MailHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
	}
}

func createMessage(entry *logrus.Entry, appname string) *bytes.Buffer {
	body := entry.Time.Format(format) + " - " + entry.Message
	subject := appname + " - " + entry.Level.String()
	fields, _ := json.MarshalIndent(entry.Data, "", "\t")
	contents := fmt.Sprintf("Subject: %s\r\n\r\n%s\r\n\r\n%s", subject, body, fields)
	message := bytes.NewBufferString(contents)
	return message
}
