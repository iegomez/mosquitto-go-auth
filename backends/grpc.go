package backends

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	gs "github.com/iegomez/mosquitto-go-auth/grpc"
)

// GRPC holds a client for the service and implements the Backend interface.
type GRPC struct {
	client           gs.AuthServiceClient
	conn             *grpc.ClientConn
	disableSuperuser bool
}

// NewGRPC tries to connect to the gRPC service at the given host.
func NewGRPC(authOpts map[string]string, logLevel log.Level) (GRPC, error) {
	var g GRPC

	if authOpts["grpc_host"] == "" || authOpts["grpc_port"] == "" {
		return g, errors.New("grpc must have a host and port")
	}

	if authOpts["grpc_disable_superuser"] == "true" {
		g.disableSuperuser = true
	}

	caCert := []byte(authOpts["grpc_ca_cert"])
	tlsCert := []byte(authOpts["grpc_tls_cert"])
	tlsKey := []byte(authOpts["grpc_tls_key"])
	addr := fmt.Sprintf("%s:%s", authOpts["grpc_host"], authOpts["grpc_port"])

	conn, gsClient, err := createClient(addr, caCert, tlsCert, tlsKey)
	if err != nil {
		return g, err
	}

	g.client = gsClient
	g.conn = conn

	return g, nil
}

// GetUser checks that the username exists and the given password hashes to the same password.
func (o GRPC) GetUser(username, password, clientid string) bool {

	req := gs.GetUserRequest{
		Username: username,
		Password: password,
		Clientid: clientid,
	}

	resp, err := o.client.GetUser(context.Background(), &req)

	if err != nil {
		log.Errorf("grpc get user error: %s", err)
		return false
	}

	return resp.Ok

}

// GetSuperuser checks that the user is a superuser.
func (o GRPC) GetSuperuser(username string) bool {

	if o.disableSuperuser {
		return false
	}

	req := gs.GetSuperuserRequest{
		Username: username,
	}

	resp, err := o.client.GetSuperuser(context.Background(), &req)

	if err != nil {
		log.Errorf("grpc get superuser error: %s", err)
		return false
	}

	return resp.Ok

}

// CheckAcl checks if the user has access to the given topic.
func (o GRPC) CheckAcl(username, topic, clientid string, acc int32) bool {

	req := gs.CheckAclRequest{
		Username: username,
		Topic:    topic,
		Clientid: clientid,
		Acc:      acc,
	}

	resp, err := o.client.CheckAcl(context.Background(), &req)

	if err != nil {
		log.Errorf("grpc check acl error: %s", err)
		return false
	}

	return resp.Ok

}

// GetName gets the gRPC backend's name.
func (o GRPC) GetName() string {
	resp, err := o.client.GetName(context.Background(), &empty.Empty{})
	if err != nil {
		return "gRPC name error"
	}
	return resp.Name
}

// Halt signals the gRPC backend that mosquitto is halting.
func (o GRPC) Halt() {
	_, err := o.client.Halt(context.Background(), &empty.Empty{})
	if err != nil {
		log.Errorf("grpc halt: %s", err)
	}
}

func createClient(hostname string, caCert, tlsCert, tlsKey []byte) (*grpc.ClientConn, gs.AuthServiceClient, error) {
	logrusEntry := log.NewEntry(log.StandardLogger())
	logrusOpts := []grpc_logrus.Option{
		grpc_logrus.WithLevels(grpc_logrus.DefaultCodeToLevel),
	}

	nsOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithUnaryInterceptor(
			grpc_logrus.UnaryClientInterceptor(logrusEntry, logrusOpts...),
		),
	}

	if len(caCert) == 0 && len(tlsCert) == 0 && len(tlsKey) == 0 {
		nsOpts = append(nsOpts, grpc.WithInsecure())
		log.WithField("server", hostname).Warning("creating insecure grpc client")
	} else {
		log.WithField("server", hostname).Info("creating grpc client")
		cert, err := tls.X509KeyPair(tlsCert, tlsKey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "load x509 keypair error")
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, nil, errors.Wrap(err, "append ca cert to pool error")
		}

		nsOpts = append(nsOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		})))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	gsClient, err := grpc.DialContext(ctx, hostname, nsOpts...)
	if err != nil {
		return nil, nil, errors.Wrap(err, "dial grpc api error")
	}

	return gsClient, gs.NewAuthServiceClient(gsClient), nil
}
