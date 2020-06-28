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

		Convey("given a correct host grpc backend should be able to initialize", func(c C) {
			g, err := NewGRPC(authOpts, log.DebugLevel)
			c.So(err, ShouldBeNil)

			Convey("given incorrect credentials user should not be authenticated", func(c C) {

				auth := g.GetUser(grpcUsername, "wrong", grpcClientId)
				c.So(auth, ShouldBeFalse)
				Convey("given correct credential user should be authenticated", func(c C) {

					auth := g.GetUser(grpcUsername, grpcPassword, grpcClientId)
					c.So(auth, ShouldBeTrue)

					Convey("given a non superuser user the service should respond false", func(c C) {
						auth = g.GetSuperuser(grpcUsername)
						So(auth, ShouldBeFalse)

						Convey("switching to a superuser should return true", func(c C) {
							auth = g.GetSuperuser(grpcSuperuser)
							So(auth, ShouldBeTrue)

							Convey("but if we disable superuser checks it should return false", func(c C) {
								authOpts["grpc_disable_superuser"] = "true"
								g, err = NewGRPC(authOpts, log.DebugLevel)
								c.So(err, ShouldBeNil)

								auth = g.GetSuperuser(grpcSuperuser)
								So(auth, ShouldBeFalse)
							})

							Convey("authorizing a wrong topic should fail", func(c C) {
								auth = g.CheckAcl(grpcUsername, "wrong/topic", grpcClientId, grpcAcc)
								So(auth, ShouldBeFalse)

								Convey("switching to a correct one should succedd", func(c C) {
									auth = g.CheckAcl(grpcUsername, grpcTopic, grpcClientId, grpcAcc)
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
