// Sorapointa - A server software re-implementation for a certain anime game, and avoid sorapointa.
// Copyright (C) 2022  Sorapointa Team
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
// 	protoc        v3.11.3
// source: AbilityActionBlink.proto

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

type AbilityActionBlink struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Rot *Vector `protobuf:"bytes,8,opt,name=rot,proto3" json:"rot,omitempty"`
	Pos *Vector `protobuf:"bytes,3,opt,name=pos,proto3" json:"pos,omitempty"`
}

func (x *AbilityActionBlink) Reset() {
	*x = AbilityActionBlink{}
	if protoimpl.UnsafeEnabled {
		mi := &file_AbilityActionBlink_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AbilityActionBlink) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AbilityActionBlink) ProtoMessage() {}

func (x *AbilityActionBlink) ProtoReflect() protoreflect.Message {
	mi := &file_AbilityActionBlink_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AbilityActionBlink.ProtoReflect.Descriptor instead.
func (*AbilityActionBlink) Descriptor() ([]byte, []int) {
	return file_AbilityActionBlink_proto_rawDescGZIP(), []int{0}
}

func (x *AbilityActionBlink) GetRot() *Vector {
	if x != nil {
		return x.Rot
	}
	return nil
}

func (x *AbilityActionBlink) GetPos() *Vector {
	if x != nil {
		return x.Pos
	}
	return nil
}

var File_AbilityActionBlink_proto protoreflect.FileDescriptor

var file_AbilityActionBlink_proto_rawDesc = []byte{
	0x0a, 0x18, 0x41, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42,
	0x6c, 0x69, 0x6e, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x56, 0x65, 0x63, 0x74,
	0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4a, 0x0a, 0x12, 0x41, 0x62, 0x69, 0x6c,
	0x69, 0x74, 0x79, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x6c, 0x69, 0x6e, 0x6b, 0x12, 0x19,
	0x0a, 0x03, 0x72, 0x6f, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65,
	0x63, 0x74, 0x6f, 0x72, 0x52, 0x03, 0x72, 0x6f, 0x74, 0x12, 0x19, 0x0a, 0x03, 0x70, 0x6f, 0x73,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52,
	0x03, 0x70, 0x6f, 0x73, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_AbilityActionBlink_proto_rawDescOnce sync.Once
	file_AbilityActionBlink_proto_rawDescData = file_AbilityActionBlink_proto_rawDesc
)

func file_AbilityActionBlink_proto_rawDescGZIP() []byte {
	file_AbilityActionBlink_proto_rawDescOnce.Do(func() {
		file_AbilityActionBlink_proto_rawDescData = protoimpl.X.CompressGZIP(file_AbilityActionBlink_proto_rawDescData)
	})
	return file_AbilityActionBlink_proto_rawDescData
}

var file_AbilityActionBlink_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_AbilityActionBlink_proto_goTypes = []interface{}{
	(*AbilityActionBlink)(nil), // 0: AbilityActionBlink
	(*Vector)(nil),             // 1: Vector
}
var file_AbilityActionBlink_proto_depIdxs = []int32{
	1, // 0: AbilityActionBlink.rot:type_name -> Vector
	1, // 1: AbilityActionBlink.pos:type_name -> Vector
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_AbilityActionBlink_proto_init() }
func file_AbilityActionBlink_proto_init() {
	if File_AbilityActionBlink_proto != nil {
		return
	}
	file_Vector_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_AbilityActionBlink_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AbilityActionBlink); i {
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
			RawDescriptor: file_AbilityActionBlink_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_AbilityActionBlink_proto_goTypes,
		DependencyIndexes: file_AbilityActionBlink_proto_depIdxs,
		MessageInfos:      file_AbilityActionBlink_proto_msgTypes,
	}.Build()
	File_AbilityActionBlink_proto = out.File
	file_AbilityActionBlink_proto_rawDesc = nil
	file_AbilityActionBlink_proto_goTypes = nil
	file_AbilityActionBlink_proto_depIdxs = nil
}
