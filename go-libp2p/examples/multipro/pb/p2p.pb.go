// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: p2p.proto

package protocols_p2p

import (
	fmt "fmt"

	proto "github.com/gogo/protobuf/proto"

	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// designed to be shared between all app protocols
type MessageData struct {
	// shared between all requests
	ClientVersion        string   `protobuf:"bytes,1,opt,name=clientVersion,proto3" json:"clientVersion,omitempty"`
	Timestamp            int64    `protobuf:"varint,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Id                   string   `protobuf:"bytes,3,opt,name=id,proto3" json:"id,omitempty"`
	Gossip               bool     `protobuf:"varint,4,opt,name=gossip,proto3" json:"gossip,omitempty"`
	NodeId               string   `protobuf:"bytes,5,opt,name=nodeId,proto3" json:"nodeId,omitempty"`
	NodePubKey           []byte   `protobuf:"bytes,6,opt,name=nodePubKey,proto3" json:"nodePubKey,omitempty"`
	Sign                 []byte   `protobuf:"bytes,7,opt,name=sign,proto3" json:"sign,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MessageData) Reset()         { *m = MessageData{} }
func (m *MessageData) String() string { return proto.CompactTextString(m) }
func (*MessageData) ProtoMessage()    {}
func (*MessageData) Descriptor() ([]byte, []int) {
	return fileDescriptor_p2p_c8fd4e6dd1b6d221, []int{0}
}
func (m *MessageData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MessageData.Unmarshal(m, b)
}
func (m *MessageData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MessageData.Marshal(b, m, deterministic)
}
func (dst *MessageData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MessageData.Merge(dst, src)
}
func (m *MessageData) XXX_Size() int {
	return xxx_messageInfo_MessageData.Size(m)
}
func (m *MessageData) XXX_DiscardUnknown() {
	xxx_messageInfo_MessageData.DiscardUnknown(m)
}

var xxx_messageInfo_MessageData proto.InternalMessageInfo

func (m *MessageData) GetClientVersion() string {
	if m != nil {
		return m.ClientVersion
	}
	return ""
}

func (m *MessageData) GetTimestamp() int64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *MessageData) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *MessageData) GetGossip() bool {
	if m != nil {
		return m.Gossip
	}
	return false
}

func (m *MessageData) GetNodeId() string {
	if m != nil {
		return m.NodeId
	}
	return ""
}

func (m *MessageData) GetNodePubKey() []byte {
	if m != nil {
		return m.NodePubKey
	}
	return nil
}

func (m *MessageData) GetSign() []byte {
	if m != nil {
		return m.Sign
	}
	return nil
}

// a protocol define a set of reuqest and responses
type PingRequest struct {
	MessageData *MessageData `protobuf:"bytes,1,opt,name=messageData" json:"messageData,omitempty"`
	// method specific data
	Message              string   `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PingRequest) Reset()         { *m = PingRequest{} }
func (m *PingRequest) String() string { return proto.CompactTextString(m) }
func (*PingRequest) ProtoMessage()    {}
func (*PingRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_p2p_c8fd4e6dd1b6d221, []int{1}
}
func (m *PingRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PingRequest.Unmarshal(m, b)
}
func (m *PingRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PingRequest.Marshal(b, m, deterministic)
}
func (dst *PingRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PingRequest.Merge(dst, src)
}
func (m *PingRequest) XXX_Size() int {
	return xxx_messageInfo_PingRequest.Size(m)
}
func (m *PingRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PingRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PingRequest proto.InternalMessageInfo

func (m *PingRequest) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *PingRequest) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

type PingResponse struct {
	MessageData *MessageData `protobuf:"bytes,1,opt,name=messageData" json:"messageData,omitempty"`
	// response specific data
	Message              string   `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PingResponse) Reset()         { *m = PingResponse{} }
func (m *PingResponse) String() string { return proto.CompactTextString(m) }
func (*PingResponse) ProtoMessage()    {}
func (*PingResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_p2p_c8fd4e6dd1b6d221, []int{2}
}
func (m *PingResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PingResponse.Unmarshal(m, b)
}
func (m *PingResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PingResponse.Marshal(b, m, deterministic)
}
func (dst *PingResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PingResponse.Merge(dst, src)
}
func (m *PingResponse) XXX_Size() int {
	return xxx_messageInfo_PingResponse.Size(m)
}
func (m *PingResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PingResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PingResponse proto.InternalMessageInfo

func (m *PingResponse) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *PingResponse) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

// a protocol define a set of reuqest and responses
type EchoRequest struct {
	MessageData *MessageData `protobuf:"bytes,1,opt,name=messageData" json:"messageData,omitempty"`
	// method specific data
	Message              string   `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EchoRequest) Reset()         { *m = EchoRequest{} }
func (m *EchoRequest) String() string { return proto.CompactTextString(m) }
func (*EchoRequest) ProtoMessage()    {}
func (*EchoRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_p2p_c8fd4e6dd1b6d221, []int{3}
}
func (m *EchoRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EchoRequest.Unmarshal(m, b)
}
func (m *EchoRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EchoRequest.Marshal(b, m, deterministic)
}
func (dst *EchoRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EchoRequest.Merge(dst, src)
}
func (m *EchoRequest) XXX_Size() int {
	return xxx_messageInfo_EchoRequest.Size(m)
}
func (m *EchoRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_EchoRequest.DiscardUnknown(m)
}

var xxx_messageInfo_EchoRequest proto.InternalMessageInfo

func (m *EchoRequest) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *EchoRequest) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

type EchoResponse struct {
	MessageData *MessageData `protobuf:"bytes,1,opt,name=messageData" json:"messageData,omitempty"`
	// response specific data
	Message              string   `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EchoResponse) Reset()         { *m = EchoResponse{} }
func (m *EchoResponse) String() string { return proto.CompactTextString(m) }
func (*EchoResponse) ProtoMessage()    {}
func (*EchoResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_p2p_c8fd4e6dd1b6d221, []int{4}
}
func (m *EchoResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EchoResponse.Unmarshal(m, b)
}
func (m *EchoResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EchoResponse.Marshal(b, m, deterministic)
}
func (dst *EchoResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EchoResponse.Merge(dst, src)
}
func (m *EchoResponse) XXX_Size() int {
	return xxx_messageInfo_EchoResponse.Size(m)
}
func (m *EchoResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_EchoResponse.DiscardUnknown(m)
}

var xxx_messageInfo_EchoResponse proto.InternalMessageInfo

func (m *EchoResponse) GetMessageData() *MessageData {
	if m != nil {
		return m.MessageData
	}
	return nil
}

func (m *EchoResponse) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func init() {
	proto.RegisterType((*MessageData)(nil), "protocols.p2p.MessageData")
	proto.RegisterType((*PingRequest)(nil), "protocols.p2p.PingRequest")
	proto.RegisterType((*PingResponse)(nil), "protocols.p2p.PingResponse")
	proto.RegisterType((*EchoRequest)(nil), "protocols.p2p.EchoRequest")
	proto.RegisterType((*EchoResponse)(nil), "protocols.p2p.EchoResponse")
}

func init() { proto.RegisterFile("p2p.proto", fileDescriptor_p2p_c8fd4e6dd1b6d221) }

var fileDescriptor_p2p_c8fd4e6dd1b6d221 = []byte{
	// 261 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x8f, 0xb1, 0x4e, 0xc3, 0x30,
	0x10, 0x86, 0xe5, 0xb6, 0xa4, 0xe4, 0xdc, 0x32, 0xdc, 0x80, 0x2c, 0x84, 0x50, 0x14, 0x31, 0x64,
	0xca, 0x10, 0x56, 0x46, 0x18, 0x10, 0x42, 0xaa, 0x3c, 0xb0, 0xa7, 0xc9, 0x11, 0x2c, 0x35, 0xb6,
	0xe9, 0xb9, 0x03, 0x0f, 0xc8, 0x7b, 0xa1, 0xba, 0x41, 0x4d, 0x1f, 0xa0, 0x4c, 0xbe, 0xff, 0xf3,
	0xd9, 0xbf, 0x3e, 0x48, 0x7d, 0xe5, 0x4b, 0xbf, 0x75, 0xc1, 0xe1, 0x32, 0x1e, 0x8d, 0xdb, 0x70,
	0xe9, 0x2b, 0x9f, 0xff, 0x08, 0x90, 0x6f, 0xc4, 0x5c, 0x77, 0xf4, 0x54, 0x87, 0x1a, 0xef, 0x61,
	0xd9, 0x6c, 0x0c, 0xd9, 0xf0, 0x4e, 0x5b, 0x36, 0xce, 0x2a, 0x91, 0x89, 0x22, 0xd5, 0xa7, 0x10,
	0x6f, 0x21, 0x0d, 0xa6, 0x27, 0x0e, 0x75, 0xef, 0xd5, 0x24, 0x13, 0xc5, 0x54, 0x1f, 0x01, 0x5e,
	0xc1, 0xc4, 0xb4, 0x6a, 0x1a, 0x1f, 0x4e, 0x4c, 0x8b, 0xd7, 0x90, 0x74, 0x8e, 0xd9, 0x78, 0x35,
	0xcb, 0x44, 0x71, 0xa9, 0x87, 0xb4, 0xe7, 0xd6, 0xb5, 0xf4, 0xd2, 0xaa, 0x8b, 0xb8, 0x3b, 0x24,
	0xbc, 0x03, 0xd8, 0x4f, 0xab, 0xdd, 0xfa, 0x95, 0xbe, 0x55, 0x92, 0x89, 0x62, 0xa1, 0x47, 0x04,
	0x11, 0x66, 0x6c, 0x3a, 0xab, 0xe6, 0xf1, 0x26, 0xce, 0x39, 0x81, 0x5c, 0x19, 0xdb, 0x69, 0xfa,
	0xda, 0x11, 0x07, 0x7c, 0x04, 0xd9, 0x1f, 0xad, 0xa2, 0x84, 0xac, 0x6e, 0xca, 0x13, 0xf7, 0x72,
	0xe4, 0xad, 0xc7, 0xeb, 0xa8, 0x60, 0x3e, 0xc4, 0x28, 0x97, 0xea, 0xbf, 0x98, 0x7f, 0xc0, 0xe2,
	0x50, 0xc3, 0xde, 0x59, 0xa6, 0xb3, 0xf5, 0x10, 0xc8, 0xe7, 0xe6, 0xd3, 0xfd, 0x83, 0xce, 0xa1,
	0xe6, 0xbc, 0x3a, 0xeb, 0x24, 0xfe, 0xf0, 0xf0, 0x1b, 0x00, 0x00, 0xff, 0xff, 0xf4, 0x47, 0x02,
	0x5e, 0x88, 0x02, 0x00, 0x00,
}
