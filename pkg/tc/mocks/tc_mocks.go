// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/aws/aws-ebpf-sdk-go/pkg/tc (interfaces: BpfTc)

// Package mock_tc is a generated GoMock package.
package mock_tc

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockBpfTc is a mock of BpfTc interface.
type MockBpfTc struct {
	ctrl     *gomock.Controller
	recorder *MockBpfTcMockRecorder
}

// MockBpfTcMockRecorder is the mock recorder for MockBpfTc.
type MockBpfTcMockRecorder struct {
	mock *MockBpfTc
}

// NewMockBpfTc creates a new mock instance.
func NewMockBpfTc(ctrl *gomock.Controller) *MockBpfTc {
	mock := &MockBpfTc{ctrl: ctrl}
	mock.recorder = &MockBpfTcMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBpfTc) EXPECT() *MockBpfTcMockRecorder {
	return m.recorder
}

// CleanupQdiscs mocks base method.
func (m *MockBpfTc) CleanupQdiscs(arg0, arg1 bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CleanupQdiscs", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// CleanupQdiscs indicates an expected call of CleanupQdiscs.
func (mr *MockBpfTcMockRecorder) CleanupQdiscs(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CleanupQdiscs", reflect.TypeOf((*MockBpfTc)(nil).CleanupQdiscs), arg0, arg1)
}

// TCEgressAttach mocks base method.
func (m *MockBpfTc) TCEgressAttach(arg0 string, arg1 int, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TCEgressAttach", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// TCEgressAttach indicates an expected call of TCEgressAttach.
func (mr *MockBpfTcMockRecorder) TCEgressAttach(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TCEgressAttach", reflect.TypeOf((*MockBpfTc)(nil).TCEgressAttach), arg0, arg1, arg2)
}

// TCEgressDetach mocks base method.
func (m *MockBpfTc) TCEgressDetach(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TCEgressDetach", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// TCEgressDetach indicates an expected call of TCEgressDetach.
func (mr *MockBpfTcMockRecorder) TCEgressDetach(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TCEgressDetach", reflect.TypeOf((*MockBpfTc)(nil).TCEgressDetach), arg0)
}

// TCIngressAttach mocks base method.
func (m *MockBpfTc) TCIngressAttach(arg0 string, arg1 int, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TCIngressAttach", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// TCIngressAttach indicates an expected call of TCIngressAttach.
func (mr *MockBpfTcMockRecorder) TCIngressAttach(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TCIngressAttach", reflect.TypeOf((*MockBpfTc)(nil).TCIngressAttach), arg0, arg1, arg2)
}

// TCIngressDetach mocks base method.
func (m *MockBpfTc) TCIngressDetach(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TCIngressDetach", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// TCIngressDetach indicates an expected call of TCIngressDetach.
func (mr *MockBpfTcMockRecorder) TCIngressDetach(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TCIngressDetach", reflect.TypeOf((*MockBpfTc)(nil).TCIngressDetach), arg0)
}