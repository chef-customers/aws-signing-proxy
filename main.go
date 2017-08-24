package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client/metadata"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var targetFlag = flag.String("target", os.Getenv("AWS_ES_TARGET"), "target url to proxy to")
var portFlag = flag.Int("port", 8080, "listening port for proxy")
var listenAddress = flag.String("listen-address", "", "Local address to listen on")
var regionFlag = flag.String("region", os.Getenv("AWS_REGION"), "AWS region for credentials")
var flushInterval = flag.Int("flush-interval", 0, "Flush interval to flush to the client while copying the response body.")
var idleConnTimeout = flag.Int("idle-conn-timeout", 90, "the maximum amount of time an idle (keep-alive) connection will remain idle before closing itself. Zero means no limit.")
var dialTimeout = flag.Int("dial-timeout", 30, "The maximum amount of time a dial will wait for a connect to complete.")
var dialKeepAlive = flag.Int("dial-keep-alive", 30, "The amount of time a dial will keep a connection alive for.")
var fileLog = flag.Bool("no-file-log", false, "Do not send log output to file.  Can be used in place of or in addition to logging to stdout.")
var logLevel = flag.String("log-level", "info", "Log level.  Default is info.  May also be set to 'debug'.")
var logLocation = flag.String("log-location", "/var/log/aws-signing-proxy", "The location to write the log file to.")
var configLocation = flag.String("config-location", "/etc", "The location of the aws-signing-proxy.")
var stdOutLog = flag.Bool("stdout-log", false, "Send log output to stdout.  Can be used in place of or in addition to the log file.")

type configuration struct {
	Target          string `mapstructure:"target"`
	Port            int    `mapstructure:"port"`
	ListenAddress   string `mapstructure:"listen-address"`
	Region          string `mapstructure:"region"`
	FlushInterval   int    `mapstructure:"flush-interval"`
	IdleConnTimeout int    `mapstructure:"idle-conn-timeout"`
	DialTimeout     int    `mapstructure:"dial-timeout"`
	DialKeepAlive   int    `mapstructure:"dial-keep-alive"`
	LogLevel        string `mapstructure:"log-level"`
	LogLocation     string `mapstructure:"log-location"`
	StdOutLog       bool   `mapstructure:"stdout-log"`
	NoFileLog       bool   `mapstructure:"no-file-log"`
}

var config configuration
var logger *zap.Logger
var sugar *zap.SugaredLogger
var requestCount int

// NewSigningProxy proxies requests to AWS services which require URL signing using the provided credentials
func NewSigningProxy(target *url.URL, creds *credentials.Credentials, region string) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		// Bump the request count
		requestCount++
		// Rewrite request to desired server host
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host

		// To perform the signing, we leverage aws-sdk-go
		// aws.request performs more functions than we need here
		// we only populate enough of the fields to successfully
		// sign the request
		config := aws.NewConfig().WithCredentials(creds).WithRegion(region)

		clientInfo := metadata.ClientInfo{
			ServiceName: "es",
		}

		operation := &request.Operation{
			Name:       "",
			HTTPMethod: req.Method,
			HTTPPath:   req.URL.Path,
		}

		handlers := request.Handlers{}
		handlers.Sign.PushBack(v4.SignSDKRequest)

		// Do we need to use request.New ? Or can we create a raw Request struct and
		//  jus swap out the HTTPRequest with our own existing one?
		awsReq := request.New(*config, clientInfo, handlers, nil, operation, nil, nil)
		// Referenced during the execution of awsReq.Sign():
		//  req.Config.Credentials
		//  req.Config.LogLevel.Value()
		//  req.Config.Logger
		//  req.ClientInfo.SigningRegion (will default to Config.Region)
		//  req.ClientInfo.SigningName (will default to ServiceName)
		//  req.ClientInfo.ServiceName
		//  req.HTTPRequest
		//  req.Time
		//  req.ExpireTime
		//  req.Body

		// Set the body in the awsReq for calculation of body Digest
		// iotuil.ReadAll reads the Body from the stream so it can be copied into awsReq
		// This drains the body from the original (proxied) request.
		// To fix, we replace req.Body with a copy (NopCloser provides io.ReadCloser interface)
		if req.Body != nil {
			buf, err := ioutil.ReadAll(req.Body)
			if err != nil {
				sugar.Infof("error reading request body: %v", err)
			}
			req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))

			awsReq.SetBufferBody(buf)
		}

		// Use the updated req.URL for creating the signed request
		// We pass the full URL object to include Host, Scheme, and any params
		awsReq.HTTPRequest.URL = req.URL
		sugar.Debugf("Issuing request to: %s", req.URL)
		// These are now set above via req, but it's imperative that this remains
		//  correctly set before calling .Sign()
		//awsReq.HTTPRequest.URL.Scheme = target.Scheme
		//awsReq.HTTPRequest.URL.Host = target.Host

		// Perform the signing, updating awsReq in place
		if err := awsReq.Sign(); err != nil {
			sugar.Infof("error signing: %v", err)
		}

		// Write the Signed Headers into the Original Request
		for k, v := range awsReq.HTTPRequest.Header {
			req.Header[k] = v
		}
		sugar.Debugf("Headers: %v", req.Header)
		sugar.Debugf("Body: %v", req.Body)
	}

	// Convert config ints to duration
	dialerTimeout := time.Duration(config.DialTimeout) * time.Second
	dialerKeepAlive := time.Duration(config.DialKeepAlive) * time.Second
	idleTimeout := time.Duration(config.IdleConnTimeout) * time.Second
	flushInter := time.Duration(config.FlushInterval) * time.Second

	// transport is http.DefaultTransport but with the ability to override some
	// timeouts
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   dialerTimeout,
			KeepAlive: dialerKeepAlive,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     idleTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &httputil.ReverseProxy{
		Director:      director,
		FlushInterval: flushInter,
		Transport:     transport,
	}
}

func main() {
	// Translate stdlib flags into pflags
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	// Viper defaults
	viper.SetDefault("region", "us-west-2")

	// Bind ENV vars
	viper.BindEnv("region", "AWS_REGION")

	// Viper setup
	viper.SetConfigName("aws-signing-proxy")
	viper.AddConfigPath(*configLocation)
	viper.AddConfigPath(".")
	viper.ReadInConfig()

	// Unpack config values into config struct
	err := viper.Unmarshal(&config)
	if err != nil {
		fmt.Println("Could not decode config!")
		return
	}

	// Setup logger
	rawJSON := []byte(`{
	  "level": "info",
	  "encoding": "json",
	  "encoderConfig": {
	    "messageKey": "message",
	    "timeKey": "time",
	    "levelKey": "level",
	    "levelEncoder": "lowercase",
	    "timeEncoder": "iso8601"
	  }
	}`)
	var loggerConfig zap.Config
	var level zap.AtomicLevel

	if err := json.Unmarshal(rawJSON, &loggerConfig); err != nil {
		panic(err)
	}
	if config.LogLevel == "debug" {
		level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	} else {
		level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	// Set log outputs
	var outputs []zapcore.Core
	if config.StdOutLog {
		core := zapcore.NewCore(
			zapcore.NewJSONEncoder(loggerConfig.EncoderConfig),
			zapcore.Lock(os.Stdout),
			level,
		)
		outputs = append(outputs, core)
	}

	if !config.NoFileLog {
		// Setup lumberjack for rotation
		w := zapcore.AddSync(&lumberjack.Logger{
			Filename:   config.LogLocation + "/proxy.log",
			MaxSize:    100,
			MaxBackups: 3,
		})
		core := zapcore.NewCore(
			zapcore.NewJSONEncoder(loggerConfig.EncoderConfig),
			w,
			level,
		)
		outputs = append(outputs, core)
	}
	core := zapcore.NewTee(outputs...)
	logger := zap.New(core)
	if err != nil {
		panic(err)
	}
	defer logger.Sync()
	sugar = logger.Sugar()

	sugar.Infow("Service starting...")

	if config.Target == "" {
		fmt.Println("No proxy target set. Please set this either in the config file or using the --target flag")
		return
	}

	// Validate URL
	targetURL, err := url.Parse(config.Target)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Set listen-address and port
	listenAddress := config.ListenAddress
	port := config.Port

	// Get credentials:
	// Environment variables > local aws config file > remote role provider
	// https://github.com/aws/aws-sdk-go/blob/master/aws/defaults/defaults.go#L88
	creds := defaults.CredChain(defaults.Config(), defaults.Handlers())
	if _, err = creds.Get(); err != nil {
		// We couldn't get any credentials
		fmt.Println(err)
		return
	}

	// Region order of precident:
	// regionFlag > os.Getenv("AWS_REGION") > "us-west-2"
	region := config.Region

	// Start the proxy server
	proxy := NewSigningProxy(targetURL, creds, region)
	listenString := fmt.Sprintf("%s:%v", listenAddress, port)
	sugar.Infof("Listening on %v", listenString)
	go statusLogging(sugar)
	http.ListenAndServe(listenString, proxy)
}

func statusLogging(logger *zap.SugaredLogger) {
	for {
		logger.Infof("Requests made in last 60 seconds: %v", requestCount)
		requestCount = 0
		time.Sleep(60 * time.Second)
	}
}
