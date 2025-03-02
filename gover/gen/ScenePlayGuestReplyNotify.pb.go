// https://github.com/SlushinPS/beach-simulator
// Copyright (C) 2023 Slushy Team
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.5
// source: ScenePlayGuestReplyNotify.proto

package gen

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// CmdId: 4437
// Obf: GOIBIFGMAME
type ScenePlayGuestReplyNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PlayId   uint32 `protobuf:"varint,8,opt,name=play_id,json=playId,proto3" json:"play_id,omitempty"`
	IsAgree  bool   `protobuf:"varint,9,opt,name=is_agree,json=isAgree,proto3" json:"is_agree,omitempty"`
	GuestUid uint32 `protobuf:"varint,10,opt,name=guest_uid,json=guestUid,proto3" json:"guest_uid,omitempty"`
}

func (x *ScenePlayGuestReplyNotify) Reset() {
	*x = ScenePlayGuestReplyNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ScenePlayGuestReplyNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScenePlayGuestReplyNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScenePlayGuestReplyNotify) ProtoMessage() {}

func (x *ScenePlayGuestReplyNotify) ProtoReflect() protoreflect.Message {
	mi := &file_ScenePlayGuestReplyNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScenePlayGuestReplyNotify.ProtoReflect.Descriptor instead.
func (*ScenePlayGuestReplyNotify) Descriptor() ([]byte, []int) {
	return file_ScenePlayGuestReplyNotify_proto_rawDescGZIP(), []int{0}
}

func (x *ScenePlayGuestReplyNotify) GetPlayId() uint32 {
	if x != nil {
		return x.PlayId
	}
	return 0
}

func (x *ScenePlayGuestReplyNotify) GetIsAgree() bool {
	if x != nil {
		return x.IsAgree
	}
	return false
}

func (x *ScenePlayGuestReplyNotify) GetGuestUid() uint32 {
	if x != nil {
		return x.GuestUid
	}
	return 0
}

var File_ScenePlayGuestReplyNotify_proto protoreflect.FileDescriptor

var file_ScenePlayGuestReplyNotify_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x53, 0x63, 0x65, 0x6e, 0x65, 0x50, 0x6c, 0x61, 0x79, 0x47, 0x75, 0x65, 0x73, 0x74,
	0x52, 0x65, 0x70, 0x6c, 0x79, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x6c, 0x0a, 0x19, 0x53, 0x63, 0x65, 0x6e, 0x65, 0x50, 0x6c, 0x61, 0x79, 0x47, 0x75,
	0x65, 0x73, 0x74, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x17,
	0x0a, 0x07, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x06, 0x70, 0x6c, 0x61, 0x79, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x69, 0x73, 0x5f, 0x61, 0x67,
	0x72, 0x65, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x69, 0x73, 0x41, 0x67, 0x72,
	0x65, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x67, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x75, 0x69, 0x64, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x67, 0x75, 0x65, 0x73, 0x74, 0x55, 0x69, 0x64, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ScenePlayGuestReplyNotify_proto_rawDescOnce sync.Once
	file_ScenePlayGuestReplyNotify_proto_rawDescData = file_ScenePlayGuestReplyNotify_proto_rawDesc
)

func file_ScenePlayGuestReplyNotify_proto_rawDescGZIP() []byte {
	file_ScenePlayGuestReplyNotify_proto_rawDescOnce.Do(func() {
		file_ScenePlayGuestReplyNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_ScenePlayGuestReplyNotify_proto_rawDescData)
	})
	return file_ScenePlayGuestReplyNotify_proto_rawDescData
}

var file_ScenePlayGuestReplyNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ScenePlayGuestReplyNotify_proto_goTypes = []interface{}{
	(*ScenePlayGuestReplyNotify)(nil), // 0: ScenePlayGuestReplyNotify
}
var file_ScenePlayGuestReplyNotify_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ScenePlayGuestReplyNotify_proto_init() }
func file_ScenePlayGuestReplyNotify_proto_init() {
	if File_ScenePlayGuestReplyNotify_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ScenePlayGuestReplyNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScenePlayGuestReplyNotify); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ScenePlayGuestReplyNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ScenePlayGuestReplyNotify_proto_goTypes,
		DependencyIndexes: file_ScenePlayGuestReplyNotify_proto_depIdxs,
		MessageInfos:      file_ScenePlayGuestReplyNotify_proto_msgTypes,
	}.Build()
	File_ScenePlayGuestReplyNotify_proto = out.File
	file_ScenePlayGuestReplyNotify_proto_rawDesc = nil
	file_ScenePlayGuestReplyNotify_proto_goTypes = nil
	file_ScenePlayGuestReplyNotify_proto_depIdxs = nil
}
