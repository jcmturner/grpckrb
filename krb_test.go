package grpc_krb

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/grpckrb/test"
	"google.golang.org/grpc"

	"github.com/jcmturner/gokrb5/v8/service"

	"github.com/jcmturner/gokrb5/v8/client"
)

const (
	krb5conf = `[libdefaults]
  default_realm = TEST.GOKRB5
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96

[realms]
 TEST.GOKRB5 = {
  kdc = 127.0.0.1:88
  admin_server = 127.0.0.1:749
  default_domain = test.gokrb5
 }

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
 `
	testuser1Keytab              = "05020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100110010698c4df8e9f60e7eea5a21bf4526ad25000000010000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200110010698c4df8e9f60e7eea5a21bf4526ad25000000020000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9000000020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001300102eb8501967a7886e1f0c63ac9be8c4a0000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001300102eb8501967a7886e1f0c63ac9be8c4a0000000020000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001400208ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee000000010000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001400208ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee00000002000000430001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001000184580fb91760dabe6f808c22c26494f644cb35d61d32c79e300000001000000430001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001000184580fb91760dabe6f808c22c26494f644cb35d61d32c79e3000000020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200170010084768c373663b3bef1f6385883cf7ff00000002"
	testuser2Keytab              = "05020000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb240010011001086824c55ff5de30386dd83dc62b44bb7000000010000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400100120020d8ed27f96be76fd5b281ee9f8029db93cc5fb06c7eb3be9ee753106d3488fa92000000010000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb240020011001086824c55ff5de30386dd83dc62b44bb7000000020000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400200120020d8ed27f96be76fd5b281ee9f8029db93cc5fb06c7eb3be9ee753106d3488fa92000000020000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb24001001300106ccff358aaa8a4a41c444e173b1463c2000000010000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb24002001300106ccff358aaa8a4a41c444e173b1463c2000000020000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb24001001400205cf3773dd920be800229ac1c6f9bf59c6706c583f82c2dea66c9a29152118cd7000000010000004b0001000b544553542e474f4b52423500097465737475736572320000000159beb24002001400205cf3773dd920be800229ac1c6f9bf59c6706c583f82c2dea66c9a29152118cd700000002000000430001000b544553542e474f4b52423500097465737475736572320000000159beb2400100100018bc025746e9e66bd6b62a918f6413d529803192a28aabf79200000001000000430001000b544553542e474f4b52423500097465737475736572320000000159beb2400200100018bc025746e9e66bd6b62a918f6413d529803192a28aabf792000000020000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b544553542e474f4b52423500097465737475736572320000000159beb2400200170010084768c373663b3bef1f6385883cf7ff00000002"
	testuser1KeytabWrongPassword = "0502000000370001000b544553542e474f4b52423500097465737475736572310000000158ef4bc5010011001039a9a382153105f8708e80f93382654e000000470001000b544553542e474f4b52423500097465737475736572310000000158ef4bc60100120020fc5bb940d6075214e0c6fc0456ce68c33306094198a927b4187d7cf3f4aea50d"
	serviceKeytab                = "0502000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590dc4dc010011001057a7754c70c4d85c155c718c2f1292b0000000540002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590dc4dc01001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590dc4dc020011001057a7754c70c4d85c155c718c2f1292b0000000540002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590dc4dc02001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51"
)

func TestUnary_ValidAuthn_ValidAuthz(t *testing.T) {
	srv, addr, errChan := newTestServer(0)
	if srv == nil {
		t.Fatal("could not create grpc server")
	}

	_, err := sendUnaryMessage(addr.String(), "", "testuser1", testuser1Keytab)
	if err != nil {
		t.Fatalf("error in sending message: %v", err)
	}
	go srv.GracefulStop()
	for err := range errChan {
		if err != nil {
			t.Errorf("error from grpc server: %v", err)
		}
	}
}

func TestStream_ValidAuthn_ValidAuthz(t *testing.T) {
	srv, addr, errChan := newTestServer(0)
	if srv == nil {
		t.Fatal("could not create grpc server")
	}
	conn, err := connect(addr.String(), "", "testuser1", testuser1Keytab)
	if err != nil {
		t.Fatalf("could not create client connection: %v", err)
	}
	defer conn.Close()
	client := test.NewServiceClient(conn)
	stream, err := client.Mirror(context.Background())
	if err != nil {
		t.Fatalf("could not create client stream: %v", err)
	}

	var msgs []*test.Request
	for i := 1; i <= 3; i++ {
		msgs = append(msgs, &test.Request{
			RequestInt: int32(i),
			RequestStr: "test message",
		})
	}
	//send the messages
	for _, msg := range msgs {
		err := stream.Send(msg)
		if err != nil {
			t.Errorf("error sending message %d: %v", msg.RequestInt, err)
		}
	}
	stream.CloseSend()

	//receive the replies
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("error receiving reply: %v", err)
			break
		}
	}

	go srv.GracefulStop()
	for err := range errChan {
		if err != nil {
			t.Errorf("error from grpc server: %v", err)
		}
	}
}

func TestUnary_InValidAuthn(t *testing.T) {
	srv, addr, errChan := newTestServer(0)
	if srv == nil {
		t.Fatal("could not create grpc server")
	}

	// Passing the username as the SPN so that a ticket is requested from the KDC for the user being the service to access and not the target service.
	// Sending this ticket to the service is not valid to authenticate the user and therefore auth should fail.
	// We could request any other SPN other than the correct one to simulate this.
	// We are just using the username as it is a principal we can definitely get a ticket for from the KDC.
	_, err := sendUnaryMessage(addr.String(), "testuser1", "testuser1", testuser1Keytab)
	if err == nil {
		t.Fatal("call to service should have failed with an authentication error")
	}
	go srv.GracefulStop()
	for err := range errChan {
		if err != nil {
			t.Errorf("error from grpc server: %v", err)
		}
	}
}

func TestUnary_ValidAuthn_InvalidAuthz(t *testing.T) {
	srv, addr, errChan := newTestServer(0)
	if srv == nil {
		t.Fatal("could not create grpc server")
	}

	_, err := sendUnaryMessage(addr.String(), "", "testuser2", testuser2Keytab)
	if err == nil {
		t.Fatal("call to service should have failed with an authorization error")
	}
	go srv.GracefulStop()
	for err := range errChan {
		if err != nil {
			t.Errorf("error from grpc server: %v", err)
		}
	}
}

func TestStream_InValidAuthn(t *testing.T) {
	srv, addr, errChan := newTestServer(0)
	if srv == nil {
		t.Fatal("could not create grpc server")
	}
	defer srv.GracefulStop()

	// Passing the username as the SPN so that a ticket is requested from the KDC for the user being the service to access and not the target service.
	// Sending this ticket to the service is not valid to authenticate the user and therefore auth should fail.
	// We could request any other SPN other than the correct one to simulate this.
	// We are just using the username as it is a principal we can definitely get a ticket for from the KDC.
	conn, err := connect(addr.String(), "testuser1", "testuser1", testuser1Keytab)
	if err != nil {
		t.Fatalf("could not create client connection: %v", err)
	}
	defer conn.Close()
	client := test.NewServiceClient(conn)
	stream, err := client.Mirror(context.Background())
	if err != nil {
		t.Fatalf("could not create client stream: %v", err)
	}

	var msgs []*test.Request
	for i := 1; i <= 3; i++ {
		msgs = append(msgs, &test.Request{
			RequestInt: int32(i),
			RequestStr: "test message",
		})
	}
	//send the messages
	for _, msg := range msgs {
		err := stream.Send(msg)
		if err != nil {
			t.Errorf("error sending message %d: %v", msg.RequestInt, err)
		}
	}
	stream.CloseSend()

	//receive the replies
	var authFailed bool
	for {
		_, err := stream.Recv()
		if err != nil && err != io.EOF {
			authFailed = true
		}
		break
	}

	go srv.GracefulStop()
	for err := range errChan {
		if err != nil {
			t.Errorf("error from grpc server: %v", err)
		}
	}
	if !authFailed {
		t.Error("call to service should have failed with an authorization error")
	}
}

func TestStream_ValidAuthn_InvalidAuthz(t *testing.T) {
	srv, addr, errChan := newTestServer(0)
	if srv == nil {
		t.Fatal("could not create grpc server")
	}
	defer srv.GracefulStop()
	conn, err := connect(addr.String(), "", "testuser2", testuser2Keytab)
	if err != nil {
		t.Fatalf("could not create client connection: %v", err)
	}
	defer conn.Close()
	client := test.NewServiceClient(conn)
	stream, err := client.Mirror(context.Background())
	if err != nil {
		t.Fatalf("could not create client stream: %v", err)
	}

	var msgs []*test.Request
	for i := 1; i <= 3; i++ {
		msgs = append(msgs, &test.Request{
			RequestInt: int32(i),
			RequestStr: "test message",
		})
	}
	//send the messages
	for _, msg := range msgs {
		err := stream.Send(msg)
		if err != nil {
			t.Errorf("error sending message %d: %v", msg.RequestInt, err)
		}
	}
	stream.CloseSend()

	//receive the replies
	var authzFailed bool
	for {
		_, err := stream.Recv()
		if err != nil && err != io.EOF {
			authzFailed = true
		}
		break
	}

	go srv.GracefulStop()
	for err := range errChan {
		if err != nil {
			t.Errorf("error from grpc server: %v", err)
		}
	}
	if !authzFailed {
		t.Error("call to service should have failed with an authorization error")
	}
}

func connect(addr, spn, username, ktHex string) (*grpc.ClientConn, error) {
	kcfg, _ := config.NewFromString(krb5conf)
	b, _ := hex.DecodeString(ktHex)
	kt := keytab.New()
	kt.Unmarshal(b)
	cl := client.NewWithKeytab(username, "TEST.GOKRB5", kt, kcfg)

	ci := &KRBClientInterceptor{
		KRBClient:  cl,
		DefaultSPN: spn,
	}

	if ci.DefaultSPN == "" {
		ci.DefaultSPN = "HTTP/host.test.gokrb5"
	}

	opts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithDisableRetry(),
		grpc.WithUnaryInterceptor(ci.Unary()),
		grpc.WithStreamInterceptor(ci.Stream())}
	return grpc.Dial(addr, opts...)
}

func sendUnaryMessage(addr, spn, username, ktHex string) (*test.Response, error) {
	req := &test.Request{
		RequestInt: 123,
		RequestStr: "hello world",
	}
	conn, err := connect(addr, spn, username, ktHex)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := test.NewServiceClient(conn)

	ctx := context.Background()
	return client.Reflector(ctx, req)
}

// newTestServer returns a test grpc server.
// Check that the *grpc.Server is not nil before use.
// The error channel will return errors from the grpc server's Serve() method
// If the port is specified as zero one is auto allocated and can be discovered from the net.Addr returned
func newTestServer(port int) (*grpc.Server, net.Addr, <-chan error) {
	errs := make(chan error, 1)
	s := new(test.Server)

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, nil, errs
	}

	b, _ := hex.DecodeString(serviceKeytab)
	kt := keytab.New()
	kt.Unmarshal(b)
	l := log.New(os.Stdout, "KRB: ", log.LstdFlags)
	authzRoles := make(map[string][]string)
	authzRoles["/Service/Reflector"] = []string{"testuser1@TEST.GOKRB5"}
	authzRoles["/Service/Mirror"] = []string{"testuser1@TEST.GOKRB5"}

	si := &KRBServerInterceptor{
		Settings:           service.NewSettings(kt, service.Logger(l)),
		AuthorizationRoles: authzRoles,
	}

	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(si.Unary()),
		grpc.StreamInterceptor(si.Stream()),
	}
	grpcSrv := grpc.NewServer(opts...)

	test.RegisterServiceServer(grpcSrv, s)
	go func() {
		errs <- grpcSrv.Serve(lis)
		close(errs)
	}()
	return grpcSrv, lis.Addr(), errs
}
