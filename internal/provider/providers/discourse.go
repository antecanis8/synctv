package main

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "os"

    plugin "github.com/hashicorp/go-plugin"
    "github.com/synctv-org/synctv/internal/provider"
    "github.com/synctv-org/synctv/internal/provider/plugins"
    "golang.org/x/oauth2"
)

type DiscourseProvider struct {
    config oauth2.Config
}

func newDiscourseProvider(baseURL string) provider.Interface {
    return &DiscourseProvider{
        config: oauth2.Config{
            Scopes: []string{"read"},
            Endpoint: oauth2.Endpoint{
                AuthURL:  fmt.Sprintf("%s/oauth2/auth", baseURL),  // 授权码获取接口
                TokenURL: fmt.Sprintf("%s/oauth2/token", baseURL), // Token端点
            },
        },
    }
}

func (p *DiscourseProvider) Init(c provider.Oauth2Option) {
    p.config.ClientID = c.ClientID
    p.config.ClientSecret = c.ClientSecret
    p.config.RedirectURL = c.RedirectURL
}

func (p *DiscourseProvider) Provider() provider.OAuth2Provider {
    return "bbzlb" // 插件名
}

func (p *DiscourseProvider) NewAuthURL(ctx context.Context, state string) (string, error) {
    return p.config.AuthCodeURL(state, oauth2.AccessTypeOnline), nil
}

func (p *DiscourseProvider) GetUserInfo(ctx context.Context, code string) (*provider.UserInfo, error) {
    tk, err := p.config.Exchange(ctx, code)
    if err != nil {
        return nil, err
    }
    client := p.config.Client(ctx, tk)
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://52.163.219.125:3000/oauth2/userinfo", nil) // 用户信息端点
    if err != nil {
        return nil, err
    }
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    ui := DiscourseUserInfo{}
    err = json.NewDecoder(resp.Body).Decode(&ui)
    if err != nil {
        return nil, err
    }

    // 返回用户信息
	un := ui.Name
	if un == "" {
		un = ui.Sub
	}
    return &provider.UserInfo{
        Username:       ui.Name,
        ProviderUserID: un,
    }, nil
}

type DiscourseUserInfo struct {
    Sub           string   `json:"sub"`            // 用户唯一标识
    Name          string   `json:"name"`           // 用户名
    Email         string   `json:"email"`          // 用户邮箱
}

func main() {
    args := os.Args
    pluginMap := map[string]plugin.Plugin{
        "Provider": &plugins.ProviderPlugin{Impl: newDiscourseProvider(args[1])},
    }
    plugin.Serve(&plugin.ServeConfig{
        HandshakeConfig: plugins.HandshakeConfig,
        Plugins:         pluginMap,
        GRPCServer:      plugin.DefaultGRPCServer,
    })
}