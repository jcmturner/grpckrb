package test

import (
	"context"
	"io"
)

type Server struct {
	UnimplementedServiceServer
}

func (s *Server) Reflector(ctx context.Context, req *Request) (*Response, error) {
	resp := &Response{
		RequestInt:  req.RequestInt,
		RequestStr:  req.RequestStr,
		ResponseInt: 1,
	}
	return resp, nil
}

func (s *Server) Mirror(stream Service_MirrorServer) error {
	for {
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		out := &Response{
			RequestInt:  in.RequestInt,
			RequestStr:  in.RequestStr,
			ResponseInt: 1,
		}
		if err := stream.Send(out); err != nil {
			return err
		}
	}
}
