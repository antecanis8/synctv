package providers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/synctv-org/synctv/internal/provider"
	"golang.org/x/oauth2"
)

type DiscourseProvider struct {
	config oauth2.Config
}

func newDiscourseProvider() provider.Interface {
	return &DiscourseProvider{
		config: oauth2.Config{
			Scopes: []string{""},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://live.bbzlb.cn:30443/oauth2/auth",  // 授权码获取接口
				TokenURL: "https://live.bbzlb.cn:30443/oauth2/token", // Token端点
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

func (p *DiscourseProvider) GetToken(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

func (p *DiscourseProvider) RefreshToken(ctx context.Context, tk string) (*oauth2.Token, error) {
	return p.config.TokenSource(ctx, &oauth2.Token{RefreshToken: tk}).Token()
}
func (p *DiscourseProvider) GetUserInfo(ctx context.Context, code string) (*provider.UserInfo, error) {
	tk, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	client := p.config.Client(ctx, tk)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://live.bbzlb.cn:30443/oauth2/userinfo", nil) // 用户信息端点
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
		Username:       un,
		ProviderUserID: ui.Sub,
	}, nil
}

type DiscourseUserInfo struct {
	Sub   string `json:"sub"`   // 用户唯一标识
	Name  string `json:"name"`  // 用户名
	Email string `json:"email"` // 用户邮箱
}

func init() {
	RegisterProvider(newDiscourseProvider())
}
