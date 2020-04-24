// Code generated by protoc-gen-go. DO NOT EDIT.
// source: membership_update_message.proto

package protobuf

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type MembershipUpdateEvent_EventType int32

const (
	MembershipUpdateEvent_UNKNOWN        MembershipUpdateEvent_EventType = 0
	MembershipUpdateEvent_CHAT_CREATED   MembershipUpdateEvent_EventType = 1
	MembershipUpdateEvent_NAME_CHANGED   MembershipUpdateEvent_EventType = 2
	MembershipUpdateEvent_MEMBERS_ADDED  MembershipUpdateEvent_EventType = 3
	MembershipUpdateEvent_MEMBER_JOINED  MembershipUpdateEvent_EventType = 4
	MembershipUpdateEvent_MEMBER_REMOVED MembershipUpdateEvent_EventType = 5
	MembershipUpdateEvent_ADMINS_ADDED   MembershipUpdateEvent_EventType = 6
	MembershipUpdateEvent_ADMIN_REMOVED  MembershipUpdateEvent_EventType = 7
)

var MembershipUpdateEvent_EventType_name = map[int32]string{
	0: "UNKNOWN",
	1: "CHAT_CREATED",
	2: "NAME_CHANGED",
	3: "MEMBERS_ADDED",
	4: "MEMBER_JOINED",
	5: "MEMBER_REMOVED",
	6: "ADMINS_ADDED",
	7: "ADMIN_REMOVED",
}

var MembershipUpdateEvent_EventType_value = map[string]int32{
	"UNKNOWN":        0,
	"CHAT_CREATED":   1,
	"NAME_CHANGED":   2,
	"MEMBERS_ADDED":  3,
	"MEMBER_JOINED":  4,
	"MEMBER_REMOVED": 5,
	"ADMINS_ADDED":   6,
	"ADMIN_REMOVED":  7,
}

func (x MembershipUpdateEvent_EventType) String() string {
	return proto.EnumName(MembershipUpdateEvent_EventType_name, int32(x))
}

func (MembershipUpdateEvent_EventType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_8d37dd0dc857a6be, []int{0, 0}
}

type MembershipUpdateEvent struct {
	// Lamport timestamp of the event
	Clock uint64 `protobuf:"varint,1,opt,name=clock,proto3" json:"clock,omitempty"`
	// List of public keys of objects of the action
	Members []string `protobuf:"bytes,2,rep,name=members,proto3" json:"members,omitempty"`
	// Name of the chat for the CHAT_CREATED/NAME_CHANGED event common
	Name string `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	// The type of the event
	Type                 MembershipUpdateEvent_EventType `protobuf:"varint,4,opt,name=type,proto3,enum=protobuf.MembershipUpdateEvent_EventType" json:"type,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                        `json:"-"`
	XXX_unrecognized     []byte                          `json:"-"`
	XXX_sizecache        int32                           `json:"-"`
}

func (m *MembershipUpdateEvent) Reset()         { *m = MembershipUpdateEvent{} }
func (m *MembershipUpdateEvent) String() string { return proto.CompactTextString(m) }
func (*MembershipUpdateEvent) ProtoMessage()    {}
func (*MembershipUpdateEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_8d37dd0dc857a6be, []int{0}
}

func (m *MembershipUpdateEvent) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MembershipUpdateEvent.Unmarshal(m, b)
}
func (m *MembershipUpdateEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MembershipUpdateEvent.Marshal(b, m, deterministic)
}
func (m *MembershipUpdateEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MembershipUpdateEvent.Merge(m, src)
}
func (m *MembershipUpdateEvent) XXX_Size() int {
	return xxx_messageInfo_MembershipUpdateEvent.Size(m)
}
func (m *MembershipUpdateEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_MembershipUpdateEvent.DiscardUnknown(m)
}

var xxx_messageInfo_MembershipUpdateEvent proto.InternalMessageInfo

func (m *MembershipUpdateEvent) GetClock() uint64 {
	if m != nil {
		return m.Clock
	}
	return 0
}

func (m *MembershipUpdateEvent) GetMembers() []string {
	if m != nil {
		return m.Members
	}
	return nil
}

func (m *MembershipUpdateEvent) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *MembershipUpdateEvent) GetType() MembershipUpdateEvent_EventType {
	if m != nil {
		return m.Type
	}
	return MembershipUpdateEvent_UNKNOWN
}

// MembershipUpdateMessage is a message used to propagate information
// about group membership changes.
// For more information, see https://github.com/status-im/specs/blob/master/status-group-chats-spec.md.
type MembershipUpdateMessage struct {
	// The chat id of the private group chat
	ChatId string `protobuf:"bytes,1,opt,name=chat_id,json=chatId,proto3" json:"chat_id,omitempty"`
	// A list of events for this group chat, first x bytes are the signature, then is a
	// protobuf encoded MembershipUpdateEvent
	Events [][]byte `protobuf:"bytes,2,rep,name=events,proto3" json:"events,omitempty"`
	// An optional chat message
	Message              *ChatMessage `protobuf:"bytes,3,opt,name=message,proto3" json:"message,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *MembershipUpdateMessage) Reset()         { *m = MembershipUpdateMessage{} }
func (m *MembershipUpdateMessage) String() string { return proto.CompactTextString(m) }
func (*MembershipUpdateMessage) ProtoMessage()    {}
func (*MembershipUpdateMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_8d37dd0dc857a6be, []int{1}
}

func (m *MembershipUpdateMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MembershipUpdateMessage.Unmarshal(m, b)
}
func (m *MembershipUpdateMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MembershipUpdateMessage.Marshal(b, m, deterministic)
}
func (m *MembershipUpdateMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MembershipUpdateMessage.Merge(m, src)
}
func (m *MembershipUpdateMessage) XXX_Size() int {
	return xxx_messageInfo_MembershipUpdateMessage.Size(m)
}
func (m *MembershipUpdateMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_MembershipUpdateMessage.DiscardUnknown(m)
}

var xxx_messageInfo_MembershipUpdateMessage proto.InternalMessageInfo

func (m *MembershipUpdateMessage) GetChatId() string {
	if m != nil {
		return m.ChatId
	}
	return ""
}

func (m *MembershipUpdateMessage) GetEvents() [][]byte {
	if m != nil {
		return m.Events
	}
	return nil
}

func (m *MembershipUpdateMessage) GetMessage() *ChatMessage {
	if m != nil {
		return m.Message
	}
	return nil
}

func init() {
	proto.RegisterEnum("protobuf.MembershipUpdateEvent_EventType", MembershipUpdateEvent_EventType_name, MembershipUpdateEvent_EventType_value)
	proto.RegisterType((*MembershipUpdateEvent)(nil), "protobuf.MembershipUpdateEvent")
	proto.RegisterType((*MembershipUpdateMessage)(nil), "protobuf.MembershipUpdateMessage")
}

func init() { proto.RegisterFile("membership_update_message.proto", fileDescriptor_8d37dd0dc857a6be) }

var fileDescriptor_8d37dd0dc857a6be = []byte{
	// 340 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x50, 0x41, 0x4f, 0xf2, 0x40,
	0x10, 0xfd, 0x0a, 0xa5, 0xfd, 0x3a, 0x20, 0xa9, 0x13, 0x91, 0xc6, 0x8b, 0x0d, 0xa7, 0x7a, 0xa9,
	0x09, 0x9e, 0x3d, 0xd4, 0xee, 0x46, 0xd0, 0xec, 0x92, 0xac, 0xa0, 0xc7, 0xa6, 0xc0, 0x2a, 0x44,
	0x0b, 0x0d, 0x14, 0x13, 0xe2, 0x4f, 0xf1, 0x8f, 0xf8, 0xf3, 0x4c, 0x97, 0x16, 0xa2, 0xf1, 0xb2,
	0xbb, 0xef, 0xcd, 0xbc, 0x37, 0x3b, 0x0f, 0xce, 0x13, 0x99, 0x8c, 0xe5, 0x6a, 0x3d, 0x9b, 0xa7,
	0xd1, 0x26, 0x9d, 0xc6, 0x99, 0x8c, 0x12, 0xb9, 0x5e, 0xc7, 0x2f, 0xd2, 0x4f, 0x57, 0xcb, 0x6c,
	0x89, 0xff, 0xd5, 0x35, 0xde, 0x3c, 0x9f, 0xe1, 0x64, 0x16, 0x67, 0x3f, 0xab, 0x9d, 0xaf, 0x0a,
	0xb4, 0xd8, 0xde, 0x61, 0xa4, 0x0c, 0xe8, 0xbb, 0x5c, 0x64, 0x78, 0x02, 0xb5, 0xc9, 0xdb, 0x72,
	0xf2, 0xea, 0x68, 0xae, 0xe6, 0xe9, 0x62, 0x07, 0xd0, 0x01, 0xb3, 0x18, 0xe8, 0x54, 0xdc, 0xaa,
	0x67, 0x89, 0x12, 0x22, 0x82, 0xbe, 0x88, 0x13, 0xe9, 0x54, 0x5d, 0xcd, 0xb3, 0x84, 0x7a, 0xe3,
	0x35, 0xe8, 0xd9, 0x36, 0x95, 0x8e, 0xee, 0x6a, 0x5e, 0xb3, 0x7b, 0xe1, 0x97, 0x5f, 0xf1, 0xff,
	0x1c, 0xe9, 0xab, 0x73, 0xb8, 0x4d, 0xa5, 0x50, 0xb2, 0xce, 0xa7, 0x06, 0xd6, 0x9e, 0xc3, 0x3a,
	0x98, 0x23, 0x7e, 0xcf, 0x07, 0x4f, 0xdc, 0xfe, 0x87, 0x36, 0x34, 0xc2, 0x5e, 0x30, 0x8c, 0x42,
	0x41, 0x83, 0x21, 0x25, 0xb6, 0x96, 0x33, 0x3c, 0x60, 0x34, 0x0a, 0x7b, 0x01, 0xbf, 0xa5, 0xc4,
	0xae, 0xe0, 0x31, 0x1c, 0x31, 0xca, 0x6e, 0xa8, 0x78, 0x88, 0x02, 0x42, 0x28, 0xb1, 0xab, 0x07,
	0x2a, 0xba, 0x1b, 0xf4, 0x39, 0x25, 0xb6, 0x8e, 0x08, 0xcd, 0x82, 0x12, 0x94, 0x0d, 0x1e, 0x29,
	0xb1, 0x6b, 0xb9, 0x57, 0x40, 0x58, 0x9f, 0x97, 0x42, 0x23, 0x17, 0x2a, 0x66, 0xdf, 0x64, 0x76,
	0x3e, 0xa0, 0xfd, 0x7b, 0x0d, 0xb6, 0xcb, 0x16, 0xdb, 0x60, 0xaa, 0xac, 0xe7, 0x53, 0x95, 0x9e,
	0x25, 0x8c, 0x1c, 0xf6, 0xa7, 0x78, 0x0a, 0x86, 0xcc, 0x17, 0xda, 0xa5, 0xd7, 0x10, 0x05, 0xc2,
	0xcb, 0x3c, 0x56, 0xa5, 0x55, 0xf9, 0xd5, 0xbb, 0xad, 0x43, 0x56, 0xe1, 0x2c, 0xce, 0x0a, 0x63,
	0x51, 0x76, 0x8d, 0x0d, 0x55, 0xbe, 0xfa, 0x0e, 0x00, 0x00, 0xff, 0xff, 0x7f, 0xb8, 0xe8, 0x9e,
	0xff, 0x01, 0x00, 0x00,
}
