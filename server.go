package grpc_krb

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	MDField = "authorization"
)

type KRBServerInterceptor struct {
	Settings           *service.Settings
	AuthorizationRoles map[string][]string
	AllowAnonymous     bool
}

func NewKRBServerInterceptor(kt *keytab.Keytab, logger *log.Logger) *KRBServerInterceptor {
	return &KRBServerInterceptor{
		Settings: service.NewSettings(kt, service.Logger(logger)),
	}
}

func (i *KRBServerInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		identity, identErr := i.authn(ctx)
		if identErr != nil {
			i.Settings.Logger().Printf("kerberos authentication failed for request to %s: %v", info.FullMethod, identErr)
		} else {
			ctx = context.WithValue(ctx, goidentity.CTXKey, identity)
		}

		if i.AllowAnonymous {
			if _, ok := i.AuthorizationRoles[info.FullMethod]; !ok {
				// Anonymous access is allowed and there is no defined role needed for this method so just serve it
				return handler(ctx, req)
			}
		}

		if identErr != nil {
			return nil, identErr
		}

		if !i.authz(identity, info.FullMethod) {
			i.Settings.Logger().Printf("user %s not authorized for request to %s", identity.UserName(), info.FullMethod)
			return nil, status.Errorf(codes.Unauthenticated, "user unauthorised for call")
		}

		i.Settings.Logger().Printf("user %s@%s authorised to access %s", identity.UserName(), identity.Domain(), info.FullMethod)
		return handler(ctx, req)
	}
}

func (i *KRBServerInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if i.AllowAnonymous {
			if _, ok := i.AuthorizationRoles[info.FullMethod]; !ok {
				// Anonymous access is allowed and there is no defined role needed for this method so just serve it
				return handler(srv, ss)
			}
		}

		identity, err := i.authn(ss.Context())
		if err != nil {
			i.Settings.Logger().Printf("kerberos authentication failed for request to %s: %v", info.FullMethod, err)
			return err
		}

		if !i.authz(identity, info.FullMethod) {
			i.Settings.Logger().Printf("user %s not authorized for request to %s", identity.UserName(), info.FullMethod)
			return status.Errorf(codes.Unauthenticated, "user not authorised for call")
		}

		i.Settings.Logger().Printf("user %s@%s authorised to access %s", identity.UserName(), identity.Domain(), info.FullMethod)
		return handler(srv, ss)
	}
}

func (i *KRBServerInterceptor) authn(ctx context.Context) (goidentity.Identity, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	values := md[MDField]
	if len(values) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}

	//base 64 decode string
	b, err := base64.StdEncoding.DecodeString(values[0])
	if err != nil {
		// log for server side here
		return nil, status.Errorf(codes.Unauthenticated, "malformed authorization token")
	}

	apReq := new(messages.APReq)
	err = apReq.Unmarshal(b)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "malformed AP_REQ authorization token")
	}

	ok, creds, err := service.VerifyAPREQ(apReq, i.Settings)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "error verifying AP_REQ authorization token: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failure")
	}
	var fqpn strings.Builder
	fmt.Fprintf(&fqpn, "%s@%s", creds.UserName(), creds.Domain())
	creds.AddAuthzAttribute(fqpn.String())

	return creds, nil
}

func (i *KRBServerInterceptor) authz(identity goidentity.Identity, method string) bool {
	attribs, ok := i.AuthorizationRoles[method]
	if !ok {
		return true
	}
	for _, attrib := range attribs {
		if identity.Authorized(attrib) {
			return true
		}
	}
	return false
}
