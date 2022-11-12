//go:build !bypass
// +build !bypass

package bypass

import "errors"

func CheckBypassBuild() bool { return false }
func StartBypassService() error {
	return errors.New("not build bypass, please build with `-tags bypass`")
}
func RegisterCallback(cb *CallbackDesc) {}
func RemoveCallback(cb *CallbackDesc)   {}
func StopBypassService()                {}
