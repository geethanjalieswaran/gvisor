// automatically generated by stateify.

package inet

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *TCPBufferSize) beforeSave() {}
func (x *TCPBufferSize) save(m state.Map) {
	x.beforeSave()
	m.Save("Min", &x.Min)
	m.Save("Default", &x.Default)
	m.Save("Max", &x.Max)
}

func (x *TCPBufferSize) afterLoad() {}
func (x *TCPBufferSize) load(m state.Map) {
	m.Load("Min", &x.Min)
	m.Load("Default", &x.Default)
	m.Load("Max", &x.Max)
}

func (x *Namespace) beforeSave() {}
func (x *Namespace) save(m state.Map) {
	x.beforeSave()
	m.Save("creator", &x.creator)
	m.Save("isRoot", &x.isRoot)
}

func (x *Namespace) load(m state.Map) {
	m.Load("creator", &x.creator)
	m.Load("isRoot", &x.isRoot)
	m.AfterLoad(x.afterLoad)
}

func init() {
	state.Register("pkg/sentry/inet.TCPBufferSize", (*TCPBufferSize)(nil), state.Fns{Save: (*TCPBufferSize).save, Load: (*TCPBufferSize).load})
	state.Register("pkg/sentry/inet.Namespace", (*Namespace)(nil), state.Fns{Save: (*Namespace).save, Load: (*Namespace).load})
}
