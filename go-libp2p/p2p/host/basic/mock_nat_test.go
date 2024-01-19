// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/libp2p/go-libp2p/p2p/host/basic (interfaces: NAT)
//
// Generated by this command:
//
//	mockgen -build_flags=-tags=gomock -package basichost -destination mock_nat_test.go github.com/libp2p/go-libp2p/p2p/host/basic NAT
//
// Package basichost is a generated GoMock package.
package basichost

import (
	context "context"
	netip "net/netip"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockNAT is a mock of NAT interface.
type MockNAT struct {
	ctrl     *gomock.Controller
	recorder *MockNATMockRecorder
}

// MockNATMockRecorder is the mock recorder for MockNAT.
type MockNATMockRecorder struct {
	mock *MockNAT
}

// NewMockNAT creates a new mock instance.
func NewMockNAT(ctrl *gomock.Controller) *MockNAT {
	mock := &MockNAT{ctrl: ctrl}
	mock.recorder = &MockNATMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNAT) EXPECT() *MockNATMockRecorder {
	return m.recorder
}

// AddMapping mocks base method.
func (m *MockNAT) AddMapping(arg0 context.Context, arg1 string, arg2 int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddMapping", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddMapping indicates an expected call of AddMapping.
func (mr *MockNATMockRecorder) AddMapping(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddMapping", reflect.TypeOf((*MockNAT)(nil).AddMapping), arg0, arg1, arg2)
}

// Close mocks base method.
func (m *MockNAT) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockNATMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockNAT)(nil).Close))
}

// GetMapping mocks base method.
func (m *MockNAT) GetMapping(arg0 string, arg1 int) (netip.AddrPort, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMapping", arg0, arg1)
	ret0, _ := ret[0].(netip.AddrPort)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// GetMapping indicates an expected call of GetMapping.
func (mr *MockNATMockRecorder) GetMapping(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMapping", reflect.TypeOf((*MockNAT)(nil).GetMapping), arg0, arg1)
}

// RemoveMapping mocks base method.
func (m *MockNAT) RemoveMapping(arg0 context.Context, arg1 string, arg2 int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveMapping", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveMapping indicates an expected call of RemoveMapping.
func (mr *MockNATMockRecorder) RemoveMapping(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveMapping", reflect.TypeOf((*MockNAT)(nil).RemoveMapping), arg0, arg1, arg2)
}
