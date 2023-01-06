// Package la provides access to Apple's LocalAuthentication framework,
// which provides support for Touch ID and Face ID.
//
// https://developer.apple.com/reference/localauthentication
package la

// https://developer.apple.com/documentation/localauthentication/logging_a_user_into_your_app_with_face_id_or_touch_id

// https://github.com/apache/pulsar/issues/6040#issuecomment-616096758

// #cgo CFLAGS: -x objective-c -fmodules -fblocks
// #cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
// #import <LocalAuthentication/LocalAuthentication.h>
// #include <stdlib.h>
// #include <stdio.h>
//
// LAContext *newContext() {
// 	return [[LAContext alloc] init];
// }
//
// int canEvaluatePolicy(LAContext *ctx, LAPolicy policy) {
// 	return [ctx canEvaluatePolicy:policy error:nil];
// }
//
// int evaluatePolicy(LAContext *ctx, LAPolicy policy, char const* reason) {
//  NSError *authError = nil;
//  NSString *authReason = [NSString stringWithUTF8String:reason];
//  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
// 	__block BOOL success = NO;
//  __block int value = 0;
//
// 	[ctx evaluatePolicy:policy localizedReason:authReason reply:^(BOOL success, NSError *error) {
// 		if (success) {
//		  value = 1;
//		} else {
//		  value = 2;
//		}
//      dispatch_semaphore_signal(sema);
// 	}];
//
//  dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
//  dispatch_release(sema);
//
// 	return value;
// }
//
import "C"
import "fmt"

// Context represents a context for evaluating authentication policies.
type Context struct{}

// NewContext creates a new context for evaluating authentication policies.
func NewContext() *Context {
	return &Context{
		// ctx: *C.newContext(),
	}
}

// CanEvaluatePolicy returns whether the context can evaluate the given
// authentication policy.
func (c *Context) CanEvaluatePolicy(policy Policy) bool {
	lactx := C.newContext()

	return C.canEvaluatePolicy(lactx, policy) != 0
}

// EvaluatePolicy evaluates the given authentication policy.
func (c *Context) EvaluatePolicy(policy Policy, reason string) error {
	lactx := C.newContext()

	res := C.evaluatePolicy(lactx, policy, C.CString(reason))

	if res == 0 {
		return fmt.Errorf("failed to evaluate policy")
	}

	switch res {
	case 1:
		return nil
	default:
		return fmt.Errorf("failed to evaluate policy")
	}
}

// Policy represents an authentication policy, which is used to evaluate
// authentication requests.
//
// A policy is a set of conditions that must be met for an authentication
// request to succeed. For example, you can create a policy that requires
// the user to authenticate using Touch ID or Face ID, or you can create a
// policy that requires the user to enter a passcode.
//
// https://developer.apple.com/documentation/localauthentication/lapolicy
type Policy = C.LAPolicy

const (
	// PolicyDeviceOwnerAuthenticationWithBiometrics specifies that the
	// user must authenticate using Touch ID or Face ID.
	//
	// https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometrics
	PolicyDeviceOwnerAuthenticationWithBiometrics Policy = 1

	// PolicyDeviceOwnerAuthentication specifies that the user must
	// authenticate using Touch ID, Face ID, or a passcode.
	//
	// https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication
	PolicyDeviceOwnerAuthentication Policy = 2

	// PolicyDeviceOwnerAuthenticationWithWatch specifies that the user
	// must authenticate using a paired Apple Watch.
	//
	// https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithwatch
	PolicyDeviceOwnerAuthenticationWithWatch Policy = 3

	// PolicyDeviceOwnerAuthenticationWithBiometricsOrWatch specifies that
	// the user must authenticate using Touch ID or Face ID, or using a
	// paired Apple Watch.
	//
	// https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometricsorwatch
	PolicyDeviceOwnerAuthenticationWithBiometricsOrWatch Policy = 4

	// PolicyDEviceOwnerAuthenticationWithWristDetection specifics that evaluation fails
	// if the user hasn’t set or entered the passcode on their watch or if the watch previously
	// detected its removal from the user’s wrist.
	//
	// https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithwristdetection
	PolicyDeviceOwnerAuthenticationWithWristDetection Policy = 5
)
