package grpc_krb

import (
	"context"
	"encoding/base64"
	"net"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type KRBClientInterceptor struct {
	KRBClient  *client.Client
	DefaultSPN string
	MethodSPNs map[string]string
}

func (i *KRBClientInterceptor) Unary() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, err := i.attachKrbToken(ctx, cc, method)
		if err != nil {
			return status.Error(codes.Unknown, err.Error())
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func (i *KRBClientInterceptor) Stream() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx, err := i.attachKrbToken(ctx, cc, method)
		if err != nil {
			cs, e := streamer(ctx, desc, cc, method, opts...)
			if e != nil {
				return cs, status.Errorf(codes.Unknown, "streamer error: %v attach krb token error: %v", e, err)
			}
			return cs, status.Error(codes.Unknown, err.Error())
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}

func (i *KRBClientInterceptor) attachKrbToken(ctx context.Context, cc *grpc.ClientConn, method string) (context.Context, error) {
	err := i.KRBClient.AffirmLogin()
	if err != nil {
		return ctx, err
	}
	spn := i.resolveSPN(cc, method)
	tkt, key, err := i.KRBClient.GetServiceTicket(spn)
	if err != nil {
		return ctx, err
	}
	auth, err := types.NewAuthenticator(i.KRBClient.Credentials.Realm(), i.KRBClient.Credentials.CName())
	if err != nil {
		return ctx, err
	}
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return ctx, err
	}
	err = auth.GenerateSeqNumberAndSubKey(key.KeyType, etype.GetKeyByteSize())
	if err != nil {
		return ctx, err
	}

	auth.Cksum = types.Checksum{
		CksumType: 32772,          // using an unassigned id as this is not used here
		Checksum:  []byte(method), // putting the method being called in the authenticator checksum. Server side can check this matches that being called.
	}

	apReq, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return ctx, err
	}
	b, err := apReq.Marshal()
	if err != nil {
		return ctx, err
	}

	b64 := base64.StdEncoding.EncodeToString(b)
	return metadata.AppendToOutgoingContext(ctx, MDField, b64), nil
}

func (i *KRBClientInterceptor) resolveSPN(cc *grpc.ClientConn, method string) string {
	if spn, ok := i.MethodSPNs[method]; ok {
		return spn
	}
	if i.DefaultSPN != "" {
		return i.DefaultSPN
	}
	host, _, err := net.SplitHostPort(cc.Target())
	if err != nil {
		return ""
	}
	var spn strings.Builder
	spn.WriteString("GRPC/")
	spn.WriteString(host)
	return spn.String()
}
