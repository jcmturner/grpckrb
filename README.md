# grpckrb

grpckrb provides the client and server interceptors required to implement Kerberos based authentication for GRPC.

These interceptors make use of the [gokrb5](https://github.com/jcmturner/gokrb5) library.
Please refer to the documentation there for more information.

## Server side configuration

1. Load the service's keytab
2. Create gokrb5 service settings
3. Create a ``grpckrb.KRBServerInterceptor`` with the service settings
4. Create a new GRPC server with the UnaryInterceptor and StreamInterceptor server options set.

```go
import (
    "github.com/jcmturner/gokrb5/v8/keytab"
    "github.com/jcmturner/gokrb5/v8/service"
)

kt, _ := keytab.Load("path/to/keytab/file")

si := &grpckrb.KRBServerInterceptor{
	Settings: service.NewSettings(kt),
}

opts := []grpc.ServerOption{
	grpc.UnaryInterceptor(si.Unary()),
	grpc.StreamInterceptor(si.Stream()),
}

grpcSrv := grpc.NewServer(opts...)
```

### Authorization
Without any authorization settings any valid authenticated user will have access to all GRPC methods.

A map of GRPC methods to authorising attributes can be added to the ``grpckrb.KRBServerInterceptor`` object:

```go
authzRoles := make(map[string][]string)
authzRoles["/Service/Reflector"] = []string{"testuser1@TEST.GOKRB5"}
authzRoles["/Service/Mirror"] = []string{"testuser1@TEST.GOKRB5"}

si := &grpckrb.KRBServerInterceptor{
	Settings:           service.NewSettings(kt),
	AuthorizationRoles: authzRoles,
}
```
The authorising attributes can be user principal names or,
if Active Directory is being used as the KDC, SIDs of AD groups.

#### Anonymuos access
By default any GRPC methods that do not have any authorization settings in the map will be accessible to any valid authenticated user.
If desired they can be made accessible to anonymous users by setting the ``AllowAnonymous`` field of the
``grpckrb.KRBServerInterceptor`` to true:
```go
si := &grpckrb.KRBServerInterceptor{
	Settings:       service.NewSettings(kt),
	AllowAnonymous: true,
}
```

### Best Practices
#### Logging
It is recommended to implement a logger on the server side. This can be done through the gokrb5 service settings:
```go
l := log.New(os.Stdout, "KRB Auth: ", log.LstdFlags)

si := &grpckrb.KRBServerInterceptor{
	Settings: service.NewSettings(kt, service.Logger(l)),
}
```

## Client side configuration
1. Load the clients keytab
2. Load the client krb5.conf
3. Create a gokrb5 client
4. Create a ``grpckrb.KRBClientInterceptor`` with the gokrb5 client
5. Dial the GRPC connection with the ``WithUnaryInterceptor`` and ``WithStreamInterceptor`` DialOptions set.

```go
import (
    "github.com/jcmturner/gokrb5/v8/client"
    "github.com/jcmturner/gokrb5/v8/config"
    "github.com/jcmturner/gokrb5/v8/keytab"
)

kcfg, _ := config.Load("path/to/krb5.conf")
kt, _ := keytab.Load("path/to/keytab/file")
cl := client.NewWithKeytab(username, "MY.REALM", kt, kcfg)

ci := &KRBClientInterceptor{
    KRBClient: cl,
}

opts := []grpc.DialOption{
	grpc.WithUnaryInterceptor(ci.Unary()),
	grpc.WithStreamInterceptor(ci.Stream())}

conn, _ := grpc.Dial(addr, opts...)
```

### Service Principal Name
In Kerberos authentication the client must request a ticket from the KDC for the service it wants to access.
The Service Principal Name (SPN) is what specifies this service.
The server side must have a keytab which contains the key for this SPN.
The SPN the client requests tickets for is derived in a number of ways:

* If nothing is configured the SPN used will default to ``GRPC/<hostname>``
  where ``hostname`` is the host portion of the address passed to the ``grpc.Dial`` function.
    
* This SPN can be overridden by setting the value of the ``DefaultSPN`` field on the ``grpckrb.KRBClientInterceptor`` object:
    ```go
    ci := &KRBClientInterceptor{
        KRBClient: cl,
        DefaultSPN: "HOST/host.example.com",
    }
    ```
* SPNs can be defined per GRPC method call using the map in the ``MethodSPNs`` field of the ``grpckrb.KRBClientInterceptor`` object:
    ```go
    spns := make(map[string]string)
    spns["/Service/Reflector"] = "HOST/host-a.example.com"
    spns["/Service/Mirror"] = "HOST/host-b.example.com"
    ci := &KRBClientInterceptor{
        KRBClient: cl,
        MethodSPNs: spns,
    }
    ```
  Any method not in this map will fall back to using the DefaultSPN.