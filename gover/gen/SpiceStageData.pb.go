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
// source: SpiceStageData.proto

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

// Obf: KGCOAKGGDMA
type SpiceStageData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsOpen       bool   `protobuf:"varint,11,opt,name=is_open,json=isOpen,proto3" json:"is_open,omitempty"`
	SuccessTimes uint32 `protobuf:"varint,14,opt,name=success_times,json=successTimes,proto3" json:"success_times,omitempty"`
	StageId      uint32 `protobuf:"varint,6,opt,name=stage_id,json=stageId,proto3" json:"stage_id,omitempty"`
}

func (x *SpiceStageData) Reset() {
	*x = SpiceStageData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SpiceStageData_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SpiceStageData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SpiceStageData) ProtoMessage() {}

func (x *SpiceStageData) ProtoReflect() protoreflect.Message {
	mi := &file_SpiceStageData_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SpiceStageData.ProtoReflect.Descriptor instead.
func (*SpiceStageData) Descriptor() ([]byte, []int) {
	return file_SpiceStageData_proto_rawDescGZIP(), []int{0}
}

func (x *SpiceStageData) GetIsOpen() bool {
	if x != nil {
		return x.IsOpen
	}
	return false
}

func (x *SpiceStageData) GetSuccessTimes() uint32 {
	if x != nil {
		return x.SuccessTimes
	}
	return 0
}

func (x *SpiceStageData) GetStageId() uint32 {
	if x != nil {
		return x.StageId
	}
	return 0
}

var File_SpiceStageData_proto protoreflect.FileDescriptor

var file_SpiceStageData_proto_rawDesc = []byte{
	0x0a, 0x14, 0x53, 0x70, 0x69, 0x63, 0x65, 0x53, 0x74, 0x61, 0x67, 0x65, 0x44, 0x61, 0x74, 0x61,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x69, 0x0a, 0x0e, 0x53, 0x70, 0x69, 0x63, 0x65, 0x53,
	0x74, 0x61, 0x67, 0x65, 0x44, 0x61, 0x74, 0x61, 0x12, 0x17, 0x0a, 0x07, 0x69, 0x73, 0x5f, 0x6f,
	0x70, 0x65, 0x6e, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x69, 0x73, 0x4f, 0x70, 0x65,
	0x6e, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f,
	0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x73, 0x74, 0x61, 0x67, 0x65, 0x49,
	0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_SpiceStageData_proto_rawDescOnce sync.Once
	file_SpiceStageData_proto_rawDescData = file_SpiceStageData_proto_rawDesc
)

func file_SpiceStageData_proto_rawDescGZIP() []byte {
	file_SpiceStageData_proto_rawDescOnce.Do(func() {
		file_SpiceStageData_proto_rawDescData = protoimpl.X.CompressGZIP(file_SpiceStageData_proto_rawDescData)
	})
	return file_SpiceStageData_proto_rawDescData
}

var file_SpiceStageData_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SpiceStageData_proto_goTypes = []interface{}{
	(*SpiceStageData)(nil), // 0: SpiceStageData
}
var file_SpiceStageData_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_SpiceStageData_proto_init() }
func file_SpiceStageData_proto_init() {
	if File_SpiceStageData_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_SpiceStageData_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SpiceStageData); i {
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
			RawDescriptor: file_SpiceStageData_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SpiceStageData_proto_goTypes,
		DependencyIndexes: file_SpiceStageData_proto_depIdxs,
		MessageInfos:      file_SpiceStageData_proto_msgTypes,
	}.Build()
	File_SpiceStageData_proto = out.File
	file_SpiceStageData_proto_rawDesc = nil
	file_SpiceStageData_proto_goTypes = nil
	file_SpiceStageData_proto_depIdxs = nil
}
