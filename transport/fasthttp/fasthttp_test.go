package fasthttp_test

import (
	"context"
	"net"
	"testing"

	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	transport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	"github.com/pers0na2dev/single-auth/transport/internal/testsuite"
)

type requestContextKey struct{}

func TestConformance(t *testing.T) {
	testsuite.Run(t, func(t *testing.T, dispatcher *engine.Dispatcher) testsuite.Exchange {
		t.Helper()
		handler := transport.NewHandler(
			dispatcher,
			transport.WithContextProvider(func(ctx *fasthttpserver.RequestCtx) context.Context {
				requestContext, _ := ctx.UserValue(requestContextKey{}).(context.Context)
				return requestContext
			}),
		)
		return func(input testsuite.Request) (testsuite.Response, error) {
			var request fasthttpserver.Request
			request.Header.SetMethod(input.Method)
			request.SetRequestURI(input.Target)
			request.Header.SetHost(input.Host)
			for _, field := range input.Headers.Fields() {
				request.Header.Add(field.Name, field.Value)
			}
			request.SetBody(input.Body)

			var ctx fasthttpserver.RequestCtx
			ctx.Init(
				&request,
				&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123},
				nil,
			)
			ctx.SetUserValue(requestContextKey{}, input.Context)
			handler(&ctx)

			headers := contract.Headers{}
			ctx.Response.Header.VisitAll(func(name, value []byte) {
				headers.Add(string(name), string(value))
			})
			return testsuite.Response{
				Status:  ctx.Response.StatusCode(),
				Headers: headers,
				Body:    append([]byte(nil), ctx.Response.Body()...),
			}, nil
		}
	})
}

func TestMaxBodyBytes(t *testing.T) {
	handler := transport.NewHandler(nil, transport.WithMaxBodyBytes(3))
	var request fasthttpserver.Request
	request.Header.SetMethod("POST")
	request.SetRequestURI("/")
	request.SetBodyString("four")

	var ctx fasthttpserver.RequestCtx
	ctx.Init(&request, nil, nil)
	handler(&ctx)
	if ctx.Response.StatusCode() != 413 {
		t.Fatalf("status = %d, want 413", ctx.Response.StatusCode())
	}
	want := `{"code":"PAYLOAD_TOO_LARGE","message":"Request body is too large"}`
	if string(ctx.Response.Body()) != want {
		t.Fatalf("body = %q, want %q", ctx.Response.Body(), want)
	}
}
