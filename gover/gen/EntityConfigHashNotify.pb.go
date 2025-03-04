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
// source: EntityConfigHashNotify.proto

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

// CmdId: 3104
// Obf: FOBAMKHAKCA
type EntityConfigHashNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CKKJPAICDJG []*EntityConfigHashEntry `protobuf:"bytes,8,rep,name=CKKJPAICDJG,proto3" json:"CKKJPAICDJG,omitempty"`
	HNOOHPABCKC []*EntityConfigHashEntry `protobuf:"bytes,3,rep,name=HNOOHPABCKC,proto3" json:"HNOOHPABCKC,omitempty"`
	ANBBPLNOHMH []*EntityConfigHashEntry `protobuf:"bytes,9,rep,name=ANBBPLNOHMH,proto3" json:"ANBBPLNOHMH,omitempty"`
}

func (x *EntityConfigHashNotify) Reset() {
	*x = EntityConfigHashNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_EntityConfigHashNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EntityConfigHashNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EntityConfigHashNotify) ProtoMessage() {}

func (x *EntityConfigHashNotify) ProtoReflect() protoreflect.Message {
	mi := &file_EntityConfigHashNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EntityConfigHashNotify.ProtoReflect.Descriptor instead.
func (*EntityConfigHashNotify) Descriptor() ([]byte, []int) {
	return file_EntityConfigHashNotify_proto_rawDescGZIP(), []int{0}
}

func (x *EntityConfigHashNotify) GetCKKJPAICDJG() []*EntityConfigHashEntry {
	if x != nil {
		return x.CKKJPAICDJG
	}
	return nil
}

func (x *EntityConfigHashNotify) GetHNOOHPABCKC() []*EntityConfigHashEntry {
	if x != nil {
		return x.HNOOHPABCKC
	}
	return nil
}

func (x *EntityConfigHashNotify) GetANBBPLNOHMH() []*EntityConfigHashEntry {
	if x != nil {
		return x.ANBBPLNOHMH
	}
	return nil
}

var File_EntityConfigHashNotify_proto protoreflect.FileDescriptor

var file_EntityConfigHashNotify_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x48, 0x61,
	0x73, 0x68, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b,
	0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x48, 0x61, 0x73, 0x68,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc6, 0x01, 0x0a, 0x16,
	0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x48, 0x61, 0x73, 0x68,
	0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x38, 0x0a, 0x0b, 0x43, 0x4b, 0x4b, 0x4a, 0x50, 0x41,
	0x49, 0x43, 0x44, 0x4a, 0x47, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x45, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x48, 0x61, 0x73, 0x68, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x52, 0x0b, 0x43, 0x4b, 0x4b, 0x4a, 0x50, 0x41, 0x49, 0x43, 0x44, 0x4a, 0x47,
	0x12, 0x38, 0x0a, 0x0b, 0x48, 0x4e, 0x4f, 0x4f, 0x48, 0x50, 0x41, 0x42, 0x43, 0x4b, 0x43, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x48, 0x61, 0x73, 0x68, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x48,
	0x4e, 0x4f, 0x4f, 0x48, 0x50, 0x41, 0x42, 0x43, 0x4b, 0x43, 0x12, 0x38, 0x0a, 0x0b, 0x41, 0x4e,
	0x42, 0x42, 0x50, 0x4c, 0x4e, 0x4f, 0x48, 0x4d, 0x48, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x16, 0x2e, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x48, 0x61,
	0x73, 0x68, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x41, 0x4e, 0x42, 0x42, 0x50, 0x4c, 0x4e,
	0x4f, 0x48, 0x4d, 0x48, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_EntityConfigHashNotify_proto_rawDescOnce sync.Once
	file_EntityConfigHashNotify_proto_rawDescData = file_EntityConfigHashNotify_proto_rawDesc
)

func file_EntityConfigHashNotify_proto_rawDescGZIP() []byte {
	file_EntityConfigHashNotify_proto_rawDescOnce.Do(func() {
		file_EntityConfigHashNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_EntityConfigHashNotify_proto_rawDescData)
	})
	return file_EntityConfigHashNotify_proto_rawDescData
}

var file_EntityConfigHashNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_EntityConfigHashNotify_proto_goTypes = []interface{}{
	(*EntityConfigHashNotify)(nil), // 0: EntityConfigHashNotify
	(*EntityConfigHashEntry)(nil),  // 1: EntityConfigHashEntry
}
var file_EntityConfigHashNotify_proto_depIdxs = []int32{
	1, // 0: EntityConfigHashNotify.CKKJPAICDJG:type_name -> EntityConfigHashEntry
	1, // 1: EntityConfigHashNotify.HNOOHPABCKC:type_name -> EntityConfigHashEntry
	1, // 2: EntityConfigHashNotify.ANBBPLNOHMH:type_name -> EntityConfigHashEntry
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_EntityConfigHashNotify_proto_init() }
func file_EntityConfigHashNotify_proto_init() {
	if File_EntityConfigHashNotify_proto != nil {
		return
	}
	file_EntityConfigHashEntry_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_EntityConfigHashNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EntityConfigHashNotify); i {
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
			RawDescriptor: file_EntityConfigHashNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_EntityConfigHashNotify_proto_goTypes,
		DependencyIndexes: file_EntityConfigHashNotify_proto_depIdxs,
		MessageInfos:      file_EntityConfigHashNotify_proto_msgTypes,
	}.Build()
	File_EntityConfigHashNotify_proto = out.File
	file_EntityConfigHashNotify_proto_rawDesc = nil
	file_EntityConfigHashNotify_proto_goTypes = nil
	file_EntityConfigHashNotify_proto_depIdxs = nil
}
