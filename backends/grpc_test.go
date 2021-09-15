package backends

import (
	"context"
	"net"
	"testing"

	"github.com/golang/protobuf/ptypes/empty"
	gs "github.com/iegomez/mosquitto-go-auth/grpc"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
	"google.golang.org/grpc"
)

const (
	grpcUsername  string = "test_user"
	grpcSuperuser string = "superuser"
	grpcPassword  string = "test_password"
	grpcTopic     string = "test/topic"
	grpcAcc       int32  = 1
	grpcClientId  string = "test_client"
)

type AuthServiceAPI struct{}

func NewAuthServiceAPI() *AuthServiceAPI {
	return &AuthServiceAPI{}
}

func (a *AuthServiceAPI) GetUser(ctx context.Context, req *gs.GetUserRequest) (*gs.AuthResponse, error) {
	if req.Username == grpcUsername && req.Password == grpcPassword {
		return &gs.AuthResponse{
			Ok: true,
		}, nil
	}
	return &gs.AuthResponse{
		Ok: false,
	}, nil
}

func (a *AuthServiceAPI) GetSuperuser(ctx context.Context, req *gs.GetSuperuserRequest) (*gs.AuthResponse, error) {
	if req.Username == grpcSuperuser {
		return &gs.AuthResponse{
			Ok: true,
		}, nil
	}
	return &gs.AuthResponse{
		Ok: false,
	}, nil
}

func (a *AuthServiceAPI) CheckAcl(ctx context.Context, req *gs.CheckAclRequest) (*gs.AuthResponse, error) {
	if req.Username == grpcUsername && req.Topic == grpcTopic && req.Clientid == grpcClientId && req.Acc == grpcAcc {
		return &gs.AuthResponse{
			Ok: true,
		}, nil
	}
	return &gs.AuthResponse{
		Ok: false,
	}, nil
}

func (a *AuthServiceAPI) GetName(ctx context.Context, req *empty.Empty) (*gs.NameResponse, error) {
	return &gs.NameResponse{
		Name: "MyGRPCBackend",
	}, nil
}

func (a *AuthServiceAPI) Halt(ctx context.Context, req *empty.Empty) (*empty.Empty, error) {
	return &empty.Empty{}, nil
}

func TestGRPC(t *testing.T) {

	Convey("given a mock grpc server", t, func(c C) {
		grpcServer := grpc.NewServer()
		gs.RegisterAuthServiceServer(grpcServer, NewAuthServiceAPI())

		lis, err := net.Listen("tcp", ":3123")
		So(err, ShouldBeNil)

		go grpcServer.Serve(lis)
		defer grpcServer.Stop()

		authOpts := make(map[string]string)
		authOpts["grpc_host"] = "localhost"
		authOpts["grpc_port"] = "3123"
		authOpts["grpc_dial_timeout_ms"] = "100"

		Convey("given wrong host", func(c C) {
			wrongOpts := make(map[string]string)
			wrongOpts["grpc_host"] = "localhost"
			wrongOpts["grpc_port"] = "1111"

			Convey("when grpc_fail_on_dial_error is set to true, it should return an error", func(c C) {
				wrongOpts["grpc_fail_on_dial_error"] = "true"

				_, err := NewGRPC(wrongOpts, log.DebugLevel)
				c.So(err, ShouldNotBeNil)
			})

			Convey("when grpc_fail_on_dial_error is not set to true, it should not return an error", func(c C) {
				wrongOpts["grpc_fail_on_dial_error"] = "false"

				g, err := NewGRPC(wrongOpts, log.DebugLevel)
				c.So(err, ShouldBeNil)

				Convey("but it should return an error on any user or acl check", func(c C) {
					auth, err := g.GetUser(grpcUsername, grpcPassword, grpcClientId)
					So(err, ShouldNotBeNil)
					c.So(auth, ShouldBeFalse)
				})

				Convey("it should work after the service comes back up", func(c C) {
					lis, err := net.Listen("tcp", ":1111")
					So(err, ShouldBeNil)

					go grpcServer.Serve(lis)
					defer grpcServer.Stop()

					auth, err := g.GetUser(grpcUsername, grpcPassword, grpcClientId)
					So(err, ShouldBeNil)
					c.So(auth, ShouldBeTrue)
				})
			})
		})

		Convey("given a correct host grpc backend should be able to initialize", func(c C) {
			g, err := NewGRPC(authOpts, log.DebugLevel)
			c.So(err, ShouldBeNil)
			So(g.timeout, ShouldEqual, 100)

			Convey("given incorrect credentials user should not be authenticated", func(c C) {

				auth, err := g.GetUser(grpcUsername, "wrong", grpcClientId)
				So(err, ShouldBeNil)
				c.So(auth, ShouldBeFalse)
				Convey("given correct credential user should be authenticated", func(c C) {

					auth, err := g.GetUser(grpcUsername, grpcPassword, grpcClientId)
					So(err, ShouldBeNil)
					c.So(auth, ShouldBeTrue)

					Convey("given a non superuser user the service should respond false", func(c C) {
						auth, err = g.GetSuperuser(grpcUsername)
						So(err, ShouldBeNil)
						So(auth, ShouldBeFalse)

						Convey("switching to a superuser should return true", func(c C) {
							auth, err = g.GetSuperuser(grpcSuperuser)
							So(err, ShouldBeNil)
							So(auth, ShouldBeTrue)

							Convey("but if we disable superuser checks it should return false", func(c C) {
								authOpts["grpc_disable_superuser"] = "true"
								g, err = NewGRPC(authOpts, log.DebugLevel)
								c.So(err, ShouldBeNil)

								auth, err = g.GetSuperuser(grpcSuperuser)
								So(err, ShouldBeNil)
								So(auth, ShouldBeFalse)
							})

							Convey("authorizing a wrong topic should fail", func(c C) {
								auth, err = g.CheckAcl(grpcUsername, "wrong/topic", grpcClientId, grpcAcc)
								So(err, ShouldBeNil)
								So(auth, ShouldBeFalse)

								Convey("switching to a correct one should succedd", func(c C) {
									auth, err = g.CheckAcl(grpcUsername, grpcTopic, grpcClientId, grpcAcc)
									So(err, ShouldBeNil)
									So(auth, ShouldBeTrue)

								})
							})

						})
					})

				})
			})

		})
	})

}
