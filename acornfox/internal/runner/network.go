package runner

import (
	"context"
	"net/http"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

const PathNetworkRemove = "/v1/networks/remove"

// NetworkRemover is the typed, per-app network cleanup capability. Callers
// cannot supply a network name or force removal of connected endpoints.
type NetworkRemover interface {
	RemoveNetwork(context.Context, string) error
}

func checkNetworkOwner(app string, n network.Inspect) error {
	if n.Name != NetworkName(app) || n.Labels[LabelManaged] != "1" || n.Labels[LabelApp] != app {
		return &RemoteError{Status: http.StatusForbidden, ErrorResponse: ErrorResponse{
			Code: "refused", Message: "应用网络名称或受管标签不匹配，拒绝操作",
		}}
	}
	return nil
}

// RemoveNetwork only removes the app's empty, labeled network. A missing
// network is success; Docker also rejects an endpoint attached after inspect.
func (d *Docker) RemoveNetwork(ctx context.Context, app string) error {
	if !ValidApp(app) {
		return &RemoteError{Status: http.StatusBadRequest, ErrorResponse: ErrorResponse{
			Code: "invalid_request", Message: "应用名不合法",
		}}
	}
	res, err := d.cli.NetworkInspect(ctx, NetworkName(app), client.NetworkInspectOptions{})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	if err := checkNetworkOwner(app, res.Network); err != nil {
		return err
	}
	if len(res.Network.Containers) != 0 || res.Network.ID == "" {
		return &RemoteError{Status: http.StatusConflict, ErrorResponse: ErrorResponse{
			Code: "network_in_use", Message: "应用网络仍有容器连接或缺少资源 ID，未删除",
		}}
	}
	_, err = d.cli.NetworkRemove(ctx, res.Network.ID, client.NetworkRemoveOptions{})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) RemoveNetwork(ctx context.Context, app string) error {
	return c.call(ctx, c.standard, PathNetworkRemove, AppRef{App: app}, clientDefaultBound, nil)
}

func (s *Server) handleNetworkRemove(w http.ResponseWriter, r *http.Request) {
	var ref AppRef
	if err := decode(r, &ref); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体格式不合法")
		return
	}
	if !validAppName(w, ref.App) {
		return
	}
	remover, ok := s.api.(NetworkRemover)
	if !ok {
		writeError(w, http.StatusNotImplemented, "unsupported", "执行器不支持应用网络回收")
		return
	}
	if err := remover.RemoveNetwork(r.Context(), ref.App); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, OK{OK: true})
}

var (
	_ NetworkRemover = (*Client)(nil)
	_ NetworkRemover = (*Docker)(nil)
)
