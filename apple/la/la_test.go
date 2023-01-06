package la

import (
	"fmt"
	"testing"
)

func TestStuff(t *testing.T) {
	c := NewContext()

	v := c.CanEvaluatePolicy(PolicyDeviceOwnerAuthenticationWithBiometrics)

	fmt.Println(v)
}

func TestAuthTouchID(t *testing.T) {
	c := NewContext()

	v := c.EvaluatePolicy(PolicyDeviceOwnerAuthentication, "Authenticate to continue test")

	switch v {
	case nil:
		fmt.Println("Success")
	default:
		fmt.Println("Failed")
	}
}
