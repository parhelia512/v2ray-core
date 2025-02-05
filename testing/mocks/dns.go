// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/v2fly/v2ray-core/v5/features/dns (interfaces: Client)
//
// Generated by this command:
//
//	mockgen -package mocks -destination testing/mocks/dns.go -mock_names Client=DNSClient github.com/v2fly/v2ray-core/v5/features/dns Client
//

// Package mocks is a generated GoMock package.
package mocks

import (
	net "net"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// DNSClient is a mock of Client interface.
type DNSClient struct {
	ctrl     *gomock.Controller
	recorder *DNSClientMockRecorder
}

// DNSClientMockRecorder is the mock recorder for DNSClient.
type DNSClientMockRecorder struct {
	mock *DNSClient
}

// NewDNSClient creates a new mock instance.
func NewDNSClient(ctrl *gomock.Controller) *DNSClient {
	mock := &DNSClient{ctrl: ctrl}
	mock.recorder = &DNSClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *DNSClient) EXPECT() *DNSClientMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *DNSClient) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *DNSClientMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*DNSClient)(nil).Close))
}

// LookupIP mocks base method.
func (m *DNSClient) LookupIP(arg0 string) ([]net.IP, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LookupIP", arg0)
	ret0, _ := ret[0].([]net.IP)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LookupIP indicates an expected call of LookupIP.
func (mr *DNSClientMockRecorder) LookupIP(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LookupIP", reflect.TypeOf((*DNSClient)(nil).LookupIP), arg0)
}

// Start mocks base method.
func (m *DNSClient) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *DNSClientMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*DNSClient)(nil).Start))
}

// Type mocks base method.
func (m *DNSClient) Type() any {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Type")
	ret0, _ := ret[0].(any)
	return ret0
}

// Type indicates an expected call of Type.
func (mr *DNSClientMockRecorder) Type() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Type", reflect.TypeOf((*DNSClient)(nil).Type))
}
