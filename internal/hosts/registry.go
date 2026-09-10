package hosts

import (
	"github.com/zjyl1994/shellgate/internal/config"
	"sort"
)

type Info struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}
type Registry struct{ values map[string]config.RuntimeHost }

func New(values map[string]config.RuntimeHost) *Registry       { return &Registry{values: values} }
func (r *Registry) Get(name string) (config.RuntimeHost, bool) { v, ok := r.values[name]; return v, ok }
func (r *Registry) List() []Info {
	out := make([]Info, 0, len(r.values))
	for n, v := range r.values {
		out = append(out, Info{Name: n, Description: v.Description})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
