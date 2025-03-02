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
// source: WidgetSorushInfo.proto

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

// Obf: FFGKNAHPKKF
type WidgetSorushInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pos         *Vector `protobuf:"bytes,2,opt,name=pos,proto3" json:"pos,omitempty"`
	PLDLMAFLGDJ bool    `protobuf:"varint,11,opt,name=PLDLMAFLGDJ,proto3" json:"PLDLMAFLGDJ,omitempty"`
	EDBKNMHNOLP bool    `protobuf:"varint,3,opt,name=EDBKNMHNOLP,proto3" json:"EDBKNMHNOLP,omitempty"`
	Rot         *Vector `protobuf:"bytes,8,opt,name=rot,proto3" json:"rot,omitempty"`
	EMLEJFAGFBF bool    `protobuf:"varint,10,opt,name=EMLEJFAGFBF,proto3" json:"EMLEJFAGFBF,omitempty"`
	Slot        uint32  `protobuf:"varint,7,opt,name=slot,proto3" json:"slot,omitempty"`
}

func (x *WidgetSorushInfo) Reset() {
	*x = WidgetSorushInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_WidgetSorushInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WidgetSorushInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WidgetSorushInfo) ProtoMessage() {}

func (x *WidgetSorushInfo) ProtoReflect() protoreflect.Message {
	mi := &file_WidgetSorushInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WidgetSorushInfo.ProtoReflect.Descriptor instead.
func (*WidgetSorushInfo) Descriptor() ([]byte, []int) {
	return file_WidgetSorushInfo_proto_rawDescGZIP(), []int{0}
}

func (x *WidgetSorushInfo) GetPos() *Vector {
	if x != nil {
		return x.Pos
	}
	return nil
}

func (x *WidgetSorushInfo) GetPLDLMAFLGDJ() bool {
	if x != nil {
		return x.PLDLMAFLGDJ
	}
	return false
}

func (x *WidgetSorushInfo) GetEDBKNMHNOLP() bool {
	if x != nil {
		return x.EDBKNMHNOLP
	}
	return false
}

func (x *WidgetSorushInfo) GetRot() *Vector {
	if x != nil {
		return x.Rot
	}
	return nil
}

func (x *WidgetSorushInfo) GetEMLEJFAGFBF() bool {
	if x != nil {
		return x.EMLEJFAGFBF
	}
	return false
}

func (x *WidgetSorushInfo) GetSlot() uint32 {
	if x != nil {
		return x.Slot
	}
	return 0
}

var File_WidgetSorushInfo_proto protoreflect.FileDescriptor

var file_WidgetSorushInfo_proto_rawDesc = []byte{
	0x0a, 0x16, 0x57, 0x69, 0x64, 0x67, 0x65, 0x74, 0x53, 0x6f, 0x72, 0x75, 0x73, 0x68, 0x49, 0x6e,
	0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc2, 0x01, 0x0a, 0x10, 0x57, 0x69, 0x64, 0x67, 0x65,
	0x74, 0x53, 0x6f, 0x72, 0x75, 0x73, 0x68, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x19, 0x0a, 0x03, 0x70,
	0x6f, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65, 0x63, 0x74, 0x6f,
	0x72, 0x52, 0x03, 0x70, 0x6f, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x50, 0x4c, 0x44, 0x4c, 0x4d, 0x41,
	0x46, 0x4c, 0x47, 0x44, 0x4a, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x50, 0x4c, 0x44,
	0x4c, 0x4d, 0x41, 0x46, 0x4c, 0x47, 0x44, 0x4a, 0x12, 0x20, 0x0a, 0x0b, 0x45, 0x44, 0x42, 0x4b,
	0x4e, 0x4d, 0x48, 0x4e, 0x4f, 0x4c, 0x50, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x45,
	0x44, 0x42, 0x4b, 0x4e, 0x4d, 0x48, 0x4e, 0x4f, 0x4c, 0x50, 0x12, 0x19, 0x0a, 0x03, 0x72, 0x6f,
	0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72,
	0x52, 0x03, 0x72, 0x6f, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x45, 0x4d, 0x4c, 0x45, 0x4a, 0x46, 0x41,
	0x47, 0x46, 0x42, 0x46, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x45, 0x4d, 0x4c, 0x45,
	0x4a, 0x46, 0x41, 0x47, 0x46, 0x42, 0x46, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x6c, 0x6f, 0x74, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x73, 0x6c, 0x6f, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_WidgetSorushInfo_proto_rawDescOnce sync.Once
	file_WidgetSorushInfo_proto_rawDescData = file_WidgetSorushInfo_proto_rawDesc
)

func file_WidgetSorushInfo_proto_rawDescGZIP() []byte {
	file_WidgetSorushInfo_proto_rawDescOnce.Do(func() {
		file_WidgetSorushInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_WidgetSorushInfo_proto_rawDescData)
	})
	return file_WidgetSorushInfo_proto_rawDescData
}

var file_WidgetSorushInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_WidgetSorushInfo_proto_goTypes = []interface{}{
	(*WidgetSorushInfo)(nil), // 0: WidgetSorushInfo
	(*Vector)(nil),           // 1: Vector
}
var file_WidgetSorushInfo_proto_depIdxs = []int32{
	1, // 0: WidgetSorushInfo.pos:type_name -> Vector
	1, // 1: WidgetSorushInfo.rot:type_name -> Vector
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_WidgetSorushInfo_proto_init() }
func file_WidgetSorushInfo_proto_init() {
	if File_WidgetSorushInfo_proto != nil {
		return
	}
	file_Vector_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_WidgetSorushInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*WidgetSorushInfo); i {
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
			RawDescriptor: file_WidgetSorushInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_WidgetSorushInfo_proto_goTypes,
		DependencyIndexes: file_WidgetSorushInfo_proto_depIdxs,
		MessageInfos:      file_WidgetSorushInfo_proto_msgTypes,
	}.Build()
	File_WidgetSorushInfo_proto = out.File
	file_WidgetSorushInfo_proto_rawDesc = nil
	file_WidgetSorushInfo_proto_goTypes = nil
	file_WidgetSorushInfo_proto_depIdxs = nil
}
